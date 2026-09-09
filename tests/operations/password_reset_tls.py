"""Prepare and verify a private Mailpit TLS/authentication test receiver.

prepare --directory /private --mail-host NAME
verify --directory /private --output /out/tls-results.json

Preparation writes synthetic credentials and a short-lived leaf key. The CA
private key exists only in memory. Verification makes real SMTP/HTTPS requests;
it does not qualify any live email provider or independent security review.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import socket
import ssl
import time
import urllib.error
import urllib.request

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


TIMEOUT = 5
MAX_RESPONSE = 256 * 1024
PRIVATE_FILES = ('tls.crt', 'tls.key', 'ca.crt', 'smtp-auth', 'ui-auth',
                 'smtp-password', 'wrong-password', 'settings.json')
CHECK_IDS = ('smtp_good_login_noop', 'smtp_wrong_login_rejected',
             'smtp_send_after_wrong_login_rejected', 'smtp_missing_login_send_rejected',
             'smtp_untrusted_ca_rejected', 'smtp_plaintext_rejected',
             'https_valid_basic_auth', 'https_missing_basic_auth_rejected',
             'https_wrong_basic_auth_rejected', 'negative_probes_accept_no_messages')


class ProbeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code='INVALID_INPUT'):
    if not value:
        raise ProbeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def error_code(error):
    if isinstance(error, ProbeError):
        return error.code
    if isinstance(error, ssl.SSLCertVerificationError):
        return 'TLS_CERTIFICATE_REJECTED'
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return 'SMTP_AUTHENTICATION_REJECTED'
    if isinstance(error, (TimeoutError, socket.timeout)):
        return 'TIMEOUT'
    if isinstance(error, smtplib.SMTPServerDisconnected):
        return 'SMTP_DISCONNECTED'
    if isinstance(error, ssl.SSLError):
        return 'TLS_PROTOCOL_ERROR'
    if isinstance(error, smtplib.SMTPException):
        return 'SMTP_ERROR'
    if isinstance(error, OSError):
        return 'IO_OR_NETWORK_ERROR'
    return 'UNEXPECTED_ERROR'


def exclusive_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(directory, name, limit):
    path = directory / name
    require(path.is_file() and not path.is_symlink(), 'PRIVATE_INPUT_INVALID')
    require(path.stat().st_size <= limit, 'PRIVATE_INPUT_TOO_LARGE')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'PRIVATE_INPUT_TOO_LARGE')
    return raw


def valid_host(host):
    require(isinstance(host, str) and 0 < len(host) <= 253, 'INVALID_MAIL_HOST')
    require(all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in host.split('.')), 'INVALID_MAIL_HOST')
    return host


def prepare(directory, host):
    require(cryptography.__version__ == '50.0.1', 'CRYPTOGRAPHY_VERSION_MISMATCH')
    host = valid_host(host)
    directory = Path(directory)
    require(not directory.is_symlink(), 'PRIVATE_DIRECTORY_INVALID')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(directory.is_dir(), 'PRIVATE_DIRECTORY_INVALID')
    require(not any((directory / name).exists() or (directory / name).is_symlink() for name in PRIVATE_FILES),
            'PREPARE_WOULD_OVERWRITE')
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ExpertAuth ephemeral SMTP probe CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                        key_encipherment=True, data_encipherment=False, key_agreement=False,
                                        key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    # Never serialize ca_key. Dropping the reference is not a secure-erasure claim.
    del ca_key
    settings = {'smtp_username': 'expertauth-smtp-' + secrets.token_hex(4),
                'smtp_password': secrets.token_urlsafe(32),
                'ui_username': 'expertauth-api-' + secrets.token_hex(4),
                'ui_password': secrets.token_urlsafe(32), 'mail_host': host}
    wrong = secrets.token_urlsafe(32)
    require(wrong not in (settings['smtp_password'], settings['ui_password']), 'SECRET_GENERATION_COLLISION')
    content = {
        'tls.crt': leaf.public_bytes(serialization.Encoding.PEM),
        'tls.key': leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()),
        'ca.crt': ca.public_bytes(serialization.Encoding.PEM),
        'smtp-auth': (settings['smtp_username'] + ':' + settings['smtp_password'] + '\n').encode('ascii'),
        'ui-auth': (settings['ui_username'] + ':' + settings['ui_password'] + '\n').encode('ascii'),
        'smtp-password': (settings['smtp_password'] + '\n').encode('ascii'),
        'wrong-password': (wrong + '\n').encode('ascii'),
        'settings.json': (json.dumps(settings, sort_keys=True) + '\n').encode('utf-8'),
    }
    for name in PRIVATE_FILES:
        exclusive_write(directory / name, content[name])
    return {'status': 'PREPARED', 'files_created': len(content),
            'ca_certificate_sha256': sha(content['ca.crt']), 'leaf_certificate_sha256': sha(content['tls.crt'])}


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def persist(output, report):
    temporary = output.with_suffix(output.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(output)


def smtp_connection(host, context):
    return smtplib.SMTP_SSL(host, 1025, timeout=TIMEOUT, context=context)


def send_denied(client, recipient):
    raw = ('From: tls-negative@expertauth.invalid\r\nTo: ' + recipient
           + '\r\nSubject: ExpertAuth SMTP authentication negative probe\r\n\r\nSynthetic negative test.\r\n').encode('ascii')
    try:
        client.sendmail('tls-negative@expertauth.invalid', [recipient], raw)
        return False, 'MESSAGE_ACCEPTED_UNEXPECTEDLY'
    except smtplib.SMTPResponseException as error:
        return error.smtp_code in (530, 535), 'SMTP_AUTH_REQUIRED' if error.smtp_code in (530, 535) else 'OTHER_SMTP_REJECTION'
    except smtplib.SMTPRecipientsRefused as error:
        codes = [value[0] for value in error.recipients.values()]
        passed = bool(codes) and all(code in (530, 535) for code in codes)
        return passed, 'SMTP_AUTH_REQUIRED' if passed else 'OTHER_SMTP_REJECTION'


def api_request(host, context, username=None, password=None):
    headers = {}
    if username is not None:
        credential = base64.b64encode((username + ':' + password).encode('ascii')).decode('ascii')
        headers['Authorization'] = 'Basic ' + credential
    request = urllib.request.Request('https://' + host + ':8025/api/v1/messages?start=0&limit=50', headers=headers)
    # No proxy environment or redirect can send synthetic Basic credentials to a
    # different service. All requests use the intended certificate-checked host.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            raw = response.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE, 'API_RESPONSE_TOO_LARGE')
            require(response.status == 200, 'UNEXPECTED_API_STATUS')
            parsed = json.loads(raw, object_pairs_hook=unique_json)
            require(type(parsed) is dict and type(parsed.get('messages')) is list, 'INVALID_API_RESPONSE')
            messages = parsed['messages']
            require(type(parsed.get('total')) is int and parsed['total'] == len(messages) <= 50, 'MAILBOX_NOT_BOUNDED')
            require(all(type(item) is dict and type(item.get('ID')) is str for item in messages), 'INVALID_API_RESPONSE')
            identifiers = {item['ID'] for item in messages}
            require(len(identifiers) == len(messages), 'INVALID_API_RESPONSE')
            return 200, identifiers
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return status, None


def verify(directory, output):
    directory, output = Path(directory), Path(output)
    require(not output.exists() and not output.is_symlink()
            and not output.with_suffix(output.suffix + '.tmp').exists(), 'EVIDENCE_ALREADY_EXISTS')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'expertauth-password-reset-tls-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'status': 'RUNNING', 'passed': False, 'cryptography_version': cryptography.__version__,
              'checks': [], 'errors': [], 'timeout_seconds': TIMEOUT, 'live_provider_qualified': False,
              'independent_security_review': False}
    exclusive_write(output, (json.dumps(report) + '\n').encode('utf-8'))

    def record(identifier, passed, code):
        report['checks'].append({'id': identifier, 'passed': bool(passed), 'code': code})
        persist(output, report)

    def attempt(identifier, operation):
        try:
            passed, code = operation()
            record(identifier, passed, code)
        except Exception as error:
            record(identifier, False, error_code(error))

    try:
        require(cryptography.__version__ == '50.0.1', 'CRYPTOGRAPHY_VERSION_MISMATCH')
        settings = json.loads(read_private(directory, 'settings.json', 8192), object_pairs_hook=unique_json)
        require(type(settings) is dict and set(settings) == {'smtp_username', 'smtp_password', 'ui_username', 'ui_password', 'mail_host'})
        require(all(type(value) is str and value and value.isascii() and not re.search(r'\s', value)
                    for value in settings.values()))
        host = valid_host(settings['mail_host'])
        wrong = read_private(directory, 'wrong-password', 1024).decode('ascii').strip()
        require(wrong and wrong not in (settings['smtp_password'], settings['ui_password']), 'INVALID_WRONG_PASSWORD')
        ca_raw = read_private(directory, 'ca.crt', 65536)
        leaf_raw = read_private(directory, 'tls.crt', 65536)
        leaf = x509.load_pem_x509_certificate(leaf_raw)
        leaf_der_hash = sha(leaf.public_bytes(serialization.Encoding.DER))
        report['certificate_sha256'] = {'ca_pem': sha(ca_raw), 'leaf_pem': sha(leaf_raw)}
        trusted = ssl.create_default_context(cafile=str(directory / 'ca.crt'))
        require(trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED, 'TLS_VERIFICATION_DISABLED')
        baseline_status, before = api_request(host, trusted, settings['ui_username'], settings['ui_password'])
        record('https_valid_basic_auth', baseline_status == 200, 'HTTP_200' if baseline_status == 200 else 'HTTP_VALID_AUTH_REJECTED')
        require(baseline_status == 200 and before is not None, 'MAILBOX_BASELINE_UNAVAILABLE')
        report['mailbox_count_before'] = len(before)
        recipient = 'tls-probe-' + secrets.token_hex(12) + '@expertauth.invalid'

        def good_login():
            with smtp_connection(host, trusted) as client:
                require(sha(client.sock.getpeercert(binary_form=True)) == leaf_der_hash, 'UNEXPECTED_SMTP_CERTIFICATE')
                code, _ = client.login(settings['smtp_username'], settings['smtp_password'])
                require(code == 235, 'SMTP_GOOD_AUTH_REJECTED')
                code, _ = client.noop()
                return code == 250, 'SMTP_AUTH_AND_NOOP_OK' if code == 250 else 'SMTP_NOOP_REJECTED'
        attempt('smtp_good_login_noop', good_login)

        try:
            with smtp_connection(host, trusted) as client:
                try:
                    client.login(settings['smtp_username'], wrong)
                    record('smtp_wrong_login_rejected', False, 'WRONG_CREDENTIALS_ACCEPTED')
                    record('smtp_send_after_wrong_login_rejected', False, 'NOT_ATTEMPTED_AUTH_WAS_ACCEPTED')
                except smtplib.SMTPAuthenticationError as error:
                    denied = 500 <= error.smtp_code <= 599
                    record('smtp_wrong_login_rejected', denied, 'SMTP_AUTH_REJECTED' if denied else 'NONPERMANENT_AUTH_REJECTION')
                    attempt('smtp_send_after_wrong_login_rejected', lambda: send_denied(client, recipient))
        except Exception as error:
            for identifier in ('smtp_wrong_login_rejected', 'smtp_send_after_wrong_login_rejected'):
                if not any(item['id'] == identifier for item in report['checks']):
                    record(identifier, False, error_code(error))

        def missing_login():
            with smtp_connection(host, trusted) as client:
                return send_denied(client, recipient)
        attempt('smtp_missing_login_send_rejected', missing_login)

        def untrusted():
            try:
                with smtp_connection(host, ssl.create_default_context()):
                    return False, 'UNTRUSTED_CA_ACCEPTED'
            except ssl.SSLCertVerificationError:
                return True, 'TLS_CERTIFICATE_REJECTED'
        attempt('smtp_untrusted_ca_rejected', untrusted)

        def plaintext():
            try:
                with smtplib.SMTP(host, 1025, timeout=TIMEOUT) as client:
                    client.ehlo()
                    return False, 'PLAINTEXT_SMTP_ACCEPTED'
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, ssl.SSLError,
                    TimeoutError, ConnectionResetError, BrokenPipeError):
                return True, 'PLAINTEXT_SMTP_REJECTED'
        attempt('smtp_plaintext_rejected', plaintext)

        def rejected_api(username=None, password=None):
            status, _ = api_request(host, trusted, username, password)
            return status in (401, 403), 'HTTP_' + str(status)
        attempt('https_missing_basic_auth_rejected', rejected_api)
        attempt('https_wrong_basic_auth_rejected', lambda: rejected_api(settings['ui_username'], wrong))
        unchanged = True
        for _ in range(3):
            status, after = api_request(host, trusted, settings['ui_username'], settings['ui_password'])
            require(status == 200 and after is not None, 'MAILBOX_FINAL_UNAVAILABLE')
            unchanged = unchanged and after == before
            report['mailbox_count_after'] = len(after)
            time.sleep(0.1)
        record('negative_probes_accept_no_messages', unchanged,
               'MAILBOX_UNCHANGED' if unchanged else 'MAILBOX_CHANGED_DURING_NEGATIVES')
    except Exception as error:
        report['errors'].append(error_code(error))
    existing = {item['id'] for item in report['checks']}
    for identifier in CHECK_IDS:
        if identifier not in existing:
            record(identifier, False, 'NOT_EXECUTED_PREREQUISITE_FAILED')
    report['passed'] = (not report['errors'] and len(report['checks']) == len(CHECK_IDS)
                        and all(item['passed'] for item in report['checks']))
    report['status'] = 'PASS' if report['passed'] else 'PARTIAL'
    report['finished'] = datetime.now(timezone.utc).isoformat()
    persist(output, report)
    return {'status': report['status'], 'checks': len(report['checks']),
            'passed_checks': sum(item['passed'] for item in report['checks']), 'evidence_sha256': sha(output.read_bytes())}


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ProbeError('INVALID_ARGUMENTS')


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        commands = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
        create = commands.add_parser('prepare')
        create.add_argument('--directory', type=Path, required=True)
        create.add_argument('--mail-host', required=True)
        check = commands.add_parser('verify')
        check.add_argument('--directory', type=Path, required=True)
        check.add_argument('--output', type=Path, required=True)
        args = parser.parse_args(argv)
        result = prepare(args.directory, args.mail_host) if args.command == 'prepare' else verify(args.directory, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] in ('PREPARED', 'PASS') else 1
    except Exception as error:
        print(json.dumps({'status': 'FAILED', 'code': error_code(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
