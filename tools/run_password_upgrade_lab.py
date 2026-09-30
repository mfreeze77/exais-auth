"""Source-built PasswordUpgrade lab: hash import matrix (MIG-002) and on-login rehash (PWD-005).

Builds plugin-interface, Core (AspectJ, as upstream) and the PostgreSQL plugin from pinned
source checkouts, verifies every third-party JAR against the reviewed Gradle verification
metadata, applies the same transforms as tools/build_password_session.py, then runs real
PostgreSQL/Core containers on an internal network. Upstream prebuilt SuperTokens JARs, EE
code and telemetry binaries are never used. Import fixtures come from independent
libraries (Python bcrypt, argon2-cffi, hashlib scrypt + cryptography AES-CTR), so run
this with an interpreter that has them. Every owned container/network is removed in
finally; private scratch stays under the supplied scratch directory.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_core_reset import ROOT, CORE_REV, need, sha  # noqa: E402
import build_password_session as builder  # noqa: E402
from patch_password_upgrade import PATH as SIGN_IN  # noqa: E402

PI_REV = '2550750188069110753decd06265a59fadefb427'
PG_REV = builder.PG_REV
RUNTIME = 'mirror.gcr.io/library/gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2'
POSTGRES = 'mirror.gcr.io/library/postgres:17.11'
UPSTREAM_BINARIES = {'core-12.2.0.jar', 'plugin-interface-10.0.0.jar', 'postgresql-plugin-9.8.0.jar', 'ee.jar'}
KEY = 'expertauth-password-upgrade-lab-key-01'
VERSION_YAML = b'core_version: 12.2.0\nplugin_interface_version: 10.0.0\nplugin_version: 9.8.0\nplugin_name: postgresql\n'  # as tools/build_oss_runtime.py
EXPERTAUTH = ['AtomicPasswordReset', 'AtomicPasswordResetAPI', 'TransactionalSessionWriter', 'AtomicPasswordSession',
              'AtomicPasswordSessionAPI', 'SessionPolicy', 'PasswordUpgrade']
JAVA_OPTS = ['--add-opens=java.base/java.lang=ALL-UNNAMED', '--add-opens=java.base/java.util=ALL-UNNAMED',
             '--add-opens=java.base/java.util.concurrent=ALL-UNNAMED']
UNICODE = 'pässwörd-密码-\U0001F511'
WRONG = 'pässwörd-wrong-密'
ASCII = 'plain-ASCII-password-42'
SIGNER = base64.b64encode(hashlib.sha256(b'expertauth-password-upgrade-lab-signer').digest() * 2).decode()  # lab-only
FB_SALT_SEPARATOR = base64.b64encode(b'\x01\x02').decode()
HASH_MARKERS = ('$2a$', '$2b$', '$2y$', '$2x$', '$argon2', '$f_scrypt$', 'passwordHash', 'password_hash')


def historical(value):
    return value.encode('utf-8').decode('iso-8859-1')


class Lab:
    def __init__(self, args):
        self.args = args
        self.run = uuid.uuid4().hex[:10]
        self.out = ROOT / 'evidence/operations/password-upgrade' / args.name
        self.scratch = Path(args.scratch).resolve() / ('password-upgrade-' + args.name)
        need(not self.out.exists() and not self.scratch.exists(), 'Preserve previous evidence and scratch')
        need(not self.scratch.is_relative_to(ROOT) or self.scratch.is_relative_to(ROOT / '.runtime'), 'Scratch must be private')
        self.labels = {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': 'password-upgrade-lab',
                       'org.expertauth.run': self.run}
        self.report = {'kind': 'password-upgrade-lab', 'passed': False, 'runtime_qualified': False, 'foundation_passed': False,
                       'policy': 'EXPERTAUTH-PASSWORD-UPGRADE-2', 'started': datetime.now(timezone.utc).isoformat(),
                       'run': self.run, 'inputs': {}, 'build': {}, 'cases': [], 'findings': [], 'requests': 0, 'errors': [],
                       'scope': 'Scratch source-built lab on a fresh cloud checkout; not the retained Windows lab or an installed image'}
        self.containers, self.networks, self.users, self.bodies = [], [], {}, []

    # ---------- helpers ----------
    def persist(self):
        (self.out / 'report.json').write_text(json.dumps(self.report, indent=2, ensure_ascii=True) + '\n')

    def sh(self, argv, timeout=120, check=True, **kw):
        result = subprocess.run(argv, capture_output=True, timeout=timeout, **kw)
        if check and result.returncode != 0:
            (self.scratch / f'failed-{int(time.time_ns())}.log').write_bytes(result.stdout + b'\n' + result.stderr)
            raise ValueError('Command failed: ' + ' '.join(str(a) for a in argv[:3]))
        return result

    def case(self, name, passed, **detail):
        self.report['cases'].append({'name': name, 'passed': bool(passed), **detail})
        self.persist()

    # ---------- inputs ----------
    def verify_inputs(self):
        sources = Path(self.args.sources).resolve()
        pins = {'supertokens-core': CORE_REV, 'supertokens-plugin-interface': PI_REV, 'supertokens-postgresql-plugin': PG_REV}
        for name, rev in pins.items():
            head = self.sh(['git', '-C', str(sources / name), 'rev-parse', 'HEAD']).stdout.decode().strip()
            dirty = self.sh(['git', '-C', str(sources / name), 'status', '--porcelain']).stdout.strip()
            need(head == rev and not dirty, 'Source checkout differs from pin: ' + name)
            self.report['inputs'][name] = rev
        manifest = {r['source_path']: r['sha256'] for r in json.loads((ROOT / 'reuse/files/supertokens__supertokens-core.json').read_text())['files']}
        self.patched = {}
        for path in [builder.WEB, builder.SESSION, builder.REFRESH, builder.VERIFY, builder.FIREBASE, builder.JSON_INPUT, SIGN_IN]:
            raw = (sources / 'supertokens-core' / path).read_bytes()
            need(hashlib.sha256(raw).hexdigest() == manifest[path], 'Audited Core source differs: ' + path)
            self.patched[path] = builder.patched_source(path, raw.decode())
        self.sources = sources
        ns = '{https://schema.gradle.org/dependency-verification}'
        known = {}
        tree = ET.parse(ROOT / 'engine-extensions/oss-build/locks/gradle/verification-metadata.xml')
        for artifact in tree.getroot().iter(ns + 'artifact'):
            digest = artifact.find(ns + 'sha256')
            if digest is not None: known.setdefault(artifact.get('name'), set()).add(digest.get('value'))
        deps = Path(self.args.dependencies).resolve()
        self.deps = {}
        for group in ['core', 'plugin']:
            rows = []
            for jar in sorted((deps / group).glob('*.jar')):
                if jar.name in UPSTREAM_BINARIES: continue
                need(sha(jar) in known.get(jar.name, ()), 'Dependency not in reviewed verification metadata: ' + jar.name)
                rows.append(jar)
            self.deps[group] = rows
        need(len(self.deps['core']) >= 80 and len(self.deps['plugin']) >= 4, 'Dependency set incomplete')
        self.report['inputs']['verified_dependency_jars'] = {g: len(v) for g, v in self.deps.items()}
        self.report['inputs']['dependency_digest'] = hashlib.sha256(''.join(sorted(sha(j) for g in self.deps.values() for j in g)).encode()).hexdigest()
        aspectj = Path(self.args.aspectj).resolve()
        need(hashlib.sha1(aspectj.read_bytes()).hexdigest() == '96d8512b8e9d92bddfd6333c3588107749de4ac1', 'aspectjtools 1.9.24 differs')
        self.aspectj = aspectj
        tracked = ['tools/run_password_upgrade_lab.py', 'tools/build_password_session.py', 'tools/patch_password_upgrade.py',
                   'tools/patch_firebase_scrypt.py', 'tools/patch_session_policy.py',
                   *[f'engine-extensions/core-reset/src/io/expertauth/core/{n}.java' for n in EXPERTAUTH], builder.PROVIDER]
        self.report['inputs']['files'] = {p: sha(ROOT / p) for p in tracked}

    # ---------- build ----------
    def build(self):
        s = self.scratch; env = {**os.environ, 'JAVA_TOOL_OPTIONS': ''}
        cp = ':'.join(str(j) for j in self.deps['core'] + self.deps['plugin'])
        def javac(out, files, classpath):
            out.mkdir(parents=True)
            self.sh(['javac', '-proc:none', '--release', '21', '-encoding', 'UTF-8', '-nowarn', '-cp', classpath, '-d', str(out), *map(str, files)], timeout=600, env=env)
        def jar(directory, target):
            with zipfile.ZipFile(target, 'x', zipfile.ZIP_DEFLATED) as z:
                for p in sorted(directory.rglob('*')):
                    if p.is_file():
                        info = zipfile.ZipInfo(p.relative_to(directory).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
                        info.external_attr = 0o100644 << 16; info.compress_type = zipfile.ZIP_DEFLATED
                        z.writestr(info, p.read_bytes())
            return target
        src = lambda name: sorted((self.sources / name / 'src/main/java').rglob('*.java'))
        javac(s / 'pi', src('supertokens-plugin-interface'), cp)
        pi = jar(s / 'pi', s / 'plugin-interface-10.0.0.jar')
        (s / 'core').mkdir()
        core_files = [p for p in src('supertokens-core') if '/ee/' not in p.as_posix()]
        (s / 'core-sources.txt').write_text('\n'.join(map(str, core_files)))
        self.sh(['java', '-Xmx2g', '-cp', str(self.aspectj), 'org.aspectj.tools.ajc.Main', '-21', '-encoding', 'UTF-8', '-warn:none',
                 '-cp', cp + ':' + str(pi), '-d', str(s / 'core'), '@' + str(s / 'core-sources.txt')], timeout=900, env=env)
        resources = self.sources / 'supertokens-core/src/main/resources'
        if resources.is_dir():
            for p in resources.rglob('*'):
                # Telemetry resource binaries are excluded, as in the reviewed OSS build.
                if p.is_file() and not p.name.endswith('.jar'):
                    t = s / 'core' / p.relative_to(resources); t.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(p, t)
        core = jar(s / 'core', s / 'core-12.2.0.jar')
        javac(s / 'pg', src('supertokens-postgresql-plugin'), cp + ':' + str(pi))
        shutil.copytree(self.sources / 'supertokens-postgresql-plugin/src/main/resources', s / 'pg', dirs_exist_ok=True)
        pg = jar(s / 'pg', s / 'postgresql-plugin-9.8.0.jar')
        (s / 'patched').mkdir()
        for filename, text in self.patched.values(): (s / 'patched' / filename).write_text(text)
        extra = [ROOT / f'engine-extensions/core-reset/src/io/expertauth/core/{n}.java' for n in EXPERTAUTH] + [ROOT / builder.PROVIDER]
        javac(s / 'cand', sorted((s / 'patched').glob('*.java')) + extra, ':'.join([cp, str(core), str(pi), str(pg)]))
        compiled = {p.relative_to(s / 'cand').as_posix(): p.read_bytes() for p in (s / 'cand').rglob('*.class')}
        provider = 'io/supertokens/storage/postgresql/ExpertAuthSessionWriter.class'
        def candidate(base, target, component):
            replacements = {k: v for k, v in compiled.items() if (k == provider) == (component == 'postgresql')}
            if component == 'postgresql':
                replacements['META-INF/services/io.expertauth.core.TransactionalSessionWriter'] = b'io.supertokens.storage.postgresql.ExpertAuthSessionWriter\n'
            changed, added = [], []
            with zipfile.ZipFile(base) as old, zipfile.ZipFile(target, 'x', zipfile.ZIP_DEFLATED) as new:
                for entry in old.infolist():
                    value = replacements.pop(entry.filename, None)
                    if value is not None: changed.append(entry.filename)
                    new.writestr(entry, old.read(entry) if value is None else value)
                for key, value in sorted(replacements.items()):
                    need(key.startswith(('io/expertauth/core/', 'io/supertokens/session/Session$', 'io/supertokens/storage/postgresql/ExpertAuthSessionWriter',
                                         'META-INF/services/io.expertauth.', 'io/supertokens/webserver/api/session/Guarded')), 'Unexpected added class: ' + key)
                    info = zipfile.ZipInfo(key, date_time=(1980, 1, 1, 0, 0, 0)); info.external_attr = 0o100644 << 16; info.compress_type = zipfile.ZIP_DEFLATED
                    new.writestr(info, value); added.append(key)
            return {'sha256': sha(target), 'changed': changed, 'added': added}
        (s / 'cand-jars').mkdir()
        cc = candidate(core, s / 'cand-jars/core-12.2.0.jar', 'core')
        cp_ = candidate(pg, s / 'cand-jars/postgresql-plugin-9.8.0.jar', 'postgresql')
        need('io/supertokens/emailpassword/EmailPassword.class' in cc['changed'] and 'io/expertauth/core/PasswordUpgrade.class' in cc['added'], 'Candidate misses PasswordUpgrade')
        self.report['build'] = {'javac': self.sh(['javac', '--version'], env=env).stdout.decode().strip(),
                                'base': {'core': sha(core), 'plugin_interface': sha(pi), 'postgresql': sha(pg)},
                                'candidate': {'core': cc, 'postgresql': cp_}, 'patched_upstream': sorted(self.patched)}
        for variant, core_jar, pg_jar in [('candidate', s / 'cand-jars/core-12.2.0.jar', s / 'cand-jars/postgresql-plugin-9.8.0.jar')]:
            home = s / ('install-' + variant); (home / 'lib').mkdir(parents=True); (home / 'plugin').mkdir()
            for j in self.deps['core'] + [core_jar, pi]: shutil.copyfile(j, home / 'lib' / j.name)
            for j in self.deps['plugin'] + [pg_jar]: shutil.copyfile(j, home / 'plugin' / j.name)
            (home / 'version.yaml').write_bytes(VERSION_YAML)
            os.chmod(home, 0o755)
        self.persist()

    # ---------- runtime ----------
    def docker(self, *argv, check=True, timeout=120):
        return self.sh(['docker', *argv], check=check, timeout=timeout)

    def labels_args(self):
        return [a for k, v in self.labels.items() for a in ('--label', f'{k}={v}')]

    def volumes(self):
        return set(self.docker('volume', 'ls', '-q').stdout.decode().split())

    def start_network(self):
        name = 'expertauth-pwupgrade-' + self.run
        self.docker('network', 'create', '--internal', *self.labels_args(), name); self.networks.append(name); self.network = name
        pg = 'expertauth-pwupgrade-pg-' + self.run
        self.docker('run', '-d', '--pull=never', '--name', pg, *self.labels_args(), '--network', name, '--network-alias', 'pg',
                    '--tmpfs', '/var/lib/postgresql/data:rw,size=256m', '-e', 'POSTGRES_PASSWORD=lab-only', '-e', 'POSTGRES_DB=supertokens', POSTGRES)
        self.containers.append(pg); self.pg = pg
        for _ in range(60):
            if self.docker('exec', pg, 'pg_isready', '-U', 'postgres', '-d', 'supertokens', check=False).returncode == 0: break
            time.sleep(1)
        else: raise ValueError('PostgreSQL not ready')
        time.sleep(2)

    def start_core(self, variant, env):
        name = f'expertauth-pwupgrade-{variant}-{self.run}'
        home = self.scratch / 'install-candidate'
        config = self.scratch / f'config-{variant}.yaml'
        config.write_text('core_config_version: 0\npostgresql_config_version: 0\nhost: 0.0.0.0\nport: 3567\n'
                          f'api_keys: "{KEY}"\ndisable_telemetry: true\n'
                          f'firebase_password_hashing_signer_key: "{SIGNER}"\n'
                          'postgresql_connection_uri: "postgresql://postgres:lab-only@pg:5432/supertokens"\n')
        mounts = ['-v', f'{home}/lib:/opt/expertauth/lib:ro', '-v', f'{home}/plugin:/opt/expertauth/plugin:ro',
                  '-v', f'{home}/version.yaml:/opt/expertauth/version.yaml:ro', '-v', f'{config}:/run/expertauth/config.yaml:ro']
        envs = [a for k, v in env.items() for a in ('-e', f'{k}={v}')]
        self.docker('run', '-d', '--pull=never', '--name', name, *self.labels_args(), '--network', self.network, '--user', '0',
                    '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=1m', '--tmpfs', '/opt/expertauth/logs:rw,size=16m', '--tmpfs', '/opt/expertauth/.started:rw,size=1m', '--tmpfs', '/tmp:rw,size=64m',
                    *mounts, *envs, '--entrypoint', 'java', RUNTIME, '-Xmx512m', *JAVA_OPTS, '-cp', '/opt/expertauth/lib/*',
                    'io.supertokens.Main', '/opt/expertauth/', 'configFile=/run/expertauth/config.yaml', 'forceNoInMemDB=true')
        self.containers.append(name)
        ip = self.docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', name).stdout.decode().strip()
        base = f'http://{ip}:3567'
        for _ in range(90):
            try:
                with urllib.request.urlopen(base + '/hello', timeout=2) as r:
                    if r.status == 200: return name, base
            except OSError: pass
            if self.docker('inspect', '-f', '{{.State.Running}}', name).stdout.strip() != b'true': break
            time.sleep(1)
        logs = self.docker('logs', name, check=False).stdout[-4000:]
        (self.scratch / f'{variant}-start.log').write_bytes(logs)
        raise ValueError('Core did not start: ' + variant)

    def stop_core(self, name):
        (self.scratch / f'{name}.log').write_bytes(self.docker('logs', name, check=False).stdout[-20000:])
        self.docker('rm', '-f', '-v', name); self.containers.remove(name)

    def call(self, base, path, payload, rid='emailpassword', charset=True):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        headers = {'api-key': KEY, 'cdi-version': '5.4', 'rid': rid,
                   'Content-Type': 'application/json; charset=utf-8' if charset else 'application/json'}
        request = urllib.request.Request(base + path, data=body, headers=headers, method='POST')
        self.report['requests'] += 1
        try:
            with urllib.request.urlopen(request, timeout=60) as r:
                raw = r.read(); self.bodies.append(raw.decode('utf-8', 'replace')); return r.status, json.loads(raw or b'{}')
        except urllib.error.HTTPError as error:
            raw = error.read(); self.bodies.append(raw.decode('utf-8', 'replace'))
            try: return error.code, json.loads(raw)
            except ValueError: return error.code, {'status': raw[:120].decode('utf-8', 'replace')}

    def signin(self, base, email, password, charset=True):
        code, body = self.call(base, '/recipe/signin', {'email': email, 'password': password}, charset=charset)
        return code == 200 and body.get('status') == 'OK'

    def session(self, base, user, email, password):
        code, body = self.call(base, '/expertauth/password/session', {'userId': user, 'email': email, 'password': password,
            'enableAntiCsrf': False, 'userDataInJWT': {}, 'userDataInDatabase': {}, 'useDynamicSigningKey': True}, rid='session')
        return code == 200 and body.get('status') == 'OK' and 'accessToken' in body

    def stored(self, user):
        out = self.docker('exec', self.pg, 'psql', '-U', 'postgres', '-d', 'supertokens', '-At', '-c',
                          f"SELECT password_hash FROM emailpassword_users WHERE app_id='public' AND user_id='{user}'").stdout.decode().strip()
        need(out, 'Stored hash missing'); return out

    def signup(self, base, label, password, charset):
        email = f'{label}-{self.run}@password-upgrade.invalid'
        code, body = self.call(base, '/recipe/signup', {'email': email, 'password': password}, charset=charset)
        need(code == 200 and body.get('status') == 'OK', 'Signup failed: ' + label)
        self.users[label] = (body['user']['id'], email); return body['user']['id'], email

    # ---------- fixtures ----------
    def fixtures(self, password):
        """Independent-library import fixtures for the configured signer; never produced by Core."""
        import bcrypt
        import argon2.low_level as argon2
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from importlib.metadata import version
        pw = password.encode('utf-8'); rows = {}
        rows['bcrypt-2b-10'] = bcrypt.hashpw(pw, bcrypt.gensalt(10)).decode()
        rows['bcrypt-2a-12'] = bcrypt.hashpw(pw, bcrypt.gensalt(12, prefix=b'2a')).decode()
        rows['bcrypt-2y-10'] = '$2y$' + bcrypt.hashpw(pw, bcrypt.gensalt(10)).decode()[4:]
        for name, kind in [('argon2id', argon2.Type.ID), ('argon2i', argon2.Type.I), ('argon2d', argon2.Type.D)]:
            rows[name + '-m19456-t2-p1'] = argon2.hash_secret(pw, os.urandom(16), time_cost=2, memory_cost=19456,
                                                             parallelism=1, hash_len=32, type=kind).decode()
        salt = os.urandom(16)
        key = hashlib.scrypt(pw, salt=salt + base64.b64decode(FB_SALT_SEPARATOR), n=2 ** 14, r=8, p=1, dklen=64)
        encryptor = Cipher(algorithms.AES(key[:32]), modes.CTR(bytes(16))).encryptor()
        signed = encryptor.update(base64.b64decode(SIGNER)) + encryptor.finalize()
        rows['firebase-scrypt-m14-r8'] = (f'$f_scrypt${base64.b64encode(signed).decode()}${base64.b64encode(salt).decode()}'
                                          f'$m=14$r=8$s={FB_SALT_SEPARATOR}')
        self.report['inputs']['fixture_libraries'] = {p: version(p) for p in ('bcrypt', 'argon2-cffi', 'cryptography')}
        return rows

    def import_hash(self, base, label, value, algorithm=None):
        email = f'{label}-{self.run}@password-upgrade.invalid'
        payload = {'email': email, 'passwordHash': value}
        if algorithm: payload['hashingAlgorithm'] = algorithm
        code, body = self.call(base, '/recipe/user/passwordhash/import', payload)
        ok = code == 200 and body.get('status') == 'OK'
        if ok: self.users[label] = (body['user']['id'], email)
        return ok, code, str(body.get('status', ''))[:80]

    def sessions(self, user):
        return int(self.docker('exec', self.pg, 'psql', '-U', 'postgres', '-d', 'supertokens', '-At', '-c',
                               f"SELECT count(*) FROM session_info WHERE app_id='public' AND user_id='{user}'").stdout.decode().strip())

    # ---------- scenarios ----------
    def scenarios(self):
        self.volumes_before = self.volumes()
        self.start_network()
        fixtures = self.fixtures(UNICODE)
        bcrypt_target = re.compile(r'^\$2a\$11\$')  # Core defaults: BCRYPT, bcrypt_log_rounds 11
        u = lambda label: self.users[label]

        # Phase 1: BCRYPT target, single replica.
        core, base = self.start_core('candidate-bcrypt', {})
        uid, email = self.signup(base, 'native-unicode', UNICODE, charset=True)
        native = self.stored(uid)
        self.case('UTF8-SIGNUP-SIGNIN', bcrypt_target.match(native) and self.signin(base, email, UNICODE) and
                  self.signin(base, email, UNICODE, charset=False))
        self.case('LATIN1-READING-REFUSED', not self.signin(base, email, historical(UNICODE)))
        self.case('WRONG-PASSWORD-REFUSED', not self.signin(base, email, WRONG) and self.stored(uid) == native)
        self.case('SAME-TARGET-NOT-REHASHED', self.signin(base, email, UNICODE) and self.stored(uid) == native)
        for name, value in fixtures.items():
            ok, code, status = self.import_hash(base, 'sig-' + name, value)
            self.case('IMPORT-' + name.upper(), ok, http=code, status=status)
            if not ok: continue
            uid, email = u('sig-' + name)
            self.case(f'IMPORTED-{name.upper()}-WRONG-REFUSED', not self.signin(base, email, WRONG) and self.stored(uid) == value)
            accepted = self.signin(base, email, UNICODE); after = self.stored(uid)
            self.case(f'IMPORTED-{name.upper()}-ACCEPTED-REHASHED', accepted and after != value and bool(bcrypt_target.match(after)))
            self.case(f'IMPORTED-{name.upper()}-STABLE-AFTER-REHASH', self.signin(base, email, UNICODE) and self.stored(uid) == after)
        for name in ('bcrypt-2b-10', 'argon2id-m19456-t2-p1', 'firebase-scrypt-m14-r8'):
            ok, _, _ = self.import_hash(base, 'ses-' + name, fixtures[name]); need(ok, 'Import failed: ses-' + name)
            uid, email = u('ses-' + name)
            self.case(f'ATOMIC-SESSION-{name.upper()}-REHASHED-IN-COMMIT', self.session(base, uid, email, UNICODE) and
                      bool(bcrypt_target.match(self.stored(uid))) and self.sessions(uid) == 1)
            self.case(f'ATOMIC-SESSION-{name.upper()}-WRONG-REFUSED', not self.session(base, uid, email, WRONG) and self.sessions(uid) == 1)
        unsupported = {'md5-hex': ('5f4dcc3b5aa765d61d8327deb882cf99', None),
                       'sha512-crypt': ('$6$saltsalt$' + 'a' * 86, None),
                       'django-pbkdf2': ('pbkdf2_sha256$600000$c2FsdA$' + 'A' * 43 + '=', None),
                       'plaintext': (ASCII, None),
                       'passlib-scrypt': ('$scrypt$ln=16,r=8,p=1$c2FsdA$' + 'A' * 43, None),
                       'bcrypt-declared-argon2': (fixtures['bcrypt-2b-10'], 'ARGON2'),
                       'argon2-declared-bcrypt': (fixtures['argon2id-m19456-t2-p1'], 'BCRYPT'),
                       'unknown-algorithm': (fixtures['bcrypt-2b-10'], 'MD5')}
        for name, (value, algorithm) in unsupported.items():
            ok, code, status = self.import_hash(base, 'bad-' + name, value, algorithm)
            self.case('UNSUPPORTED-' + name.upper() + '-REPORTED', not ok and code == 400, http=code, status=status)
        # Upstream import checks only the prefix; the candidate also requires structure and bounded cost.
        bcrypt_hash, argon2_hash, firebase_hash = fixtures['bcrypt-2b-10'], fixtures['argon2id-m19456-t2-p1'], fixtures['firebase-scrypt-m14-r8']
        malformed = {'bcrypt-truncated': '$2a$10$short', 'bcrypt-bad-alphabet': bcrypt_hash[:-1] + '!',
                     'argon2id-garbage': '$argon2id$garbage', 'argon2-unknown-version': argon2_hash.replace('$v=19$', '$v=20$'),
                     'firebase-bad-base64': firebase_hash.replace('$f_scrypt$', '$f_scrypt$*', 1),
                     'bcrypt-cost-17': '$2b$17' + bcrypt_hash[6:], 'argon2-memory-4gib': argon2_hash.replace('m=19456', 'm=4194304'),
                     'argon2-iterations-101': argon2_hash.replace('t=2,', 't=101,'), 'firebase-memcost-18': firebase_hash.replace('$m=14$', '$m=18$')}
        for name, value in malformed.items():
            ok, code, status = self.import_hash(base, 'malformed-' + name, value)
            self.case('MALFORMED-' + name.upper() + '-REPORTED', not ok and code == 400, http=code, status=status)
        self.stop_core(core)

        # Phase 2: ARGON2 target (Core defaults m=87795,t=1,p=2): imported and bcrypt accounts move to argon2id.
        core, base = self.start_core('candidate-argon2', {'PASSWORD_HASHING_ALG': 'ARGON2'})
        argon2_target = re.compile(r'^\$argon2id\$v=19\$m=87795,t=1,p=2\$')
        for name in ('bcrypt-2b-10', 'argon2id-m19456-t2-p1', 'argon2i-m19456-t2-p1', 'firebase-scrypt-m14-r8'):
            ok, _, _ = self.import_hash(base, 'arg-' + name, fixtures[name]); need(ok, 'Import failed: arg-' + name)
            uid, email = u('arg-' + name)
            accepted = self.signin(base, email, UNICODE); after = self.stored(uid)
            self.case(f'ARGON2-TARGET-{name.upper()}-REHASHED', accepted and bool(argon2_target.match(after)) and self.signin(base, email, UNICODE))
        uid, email = u('native-unicode')
        self.case('ARGON2-TARGET-BCRYPT-SIGNUP-MIGRATES', self.signin(base, email, UNICODE) and bool(argon2_target.match(self.stored(uid))))
        uid, email = self.signup(base, 'native-argon2', UNICODE, charset=True)
        first = self.stored(uid)
        self.case('ARGON2-TARGET-NATIVE-NOT-REHASHED', bool(argon2_target.match(first)) and self.signin(base, email, UNICODE) and self.stored(uid) == first)
        self.stop_core(core)

        # Phase 3: two BCRYPT replicas; eight concurrent first logins per route on imported accounts.
        a, base_a = self.start_core('candidate-replica-a', {})
        b, base_b = self.start_core('candidate-replica-b', {})
        for route in ('signin', 'session'):
            label = 'conc-' + route
            ok, _, _ = self.import_hash(base_a, label, fixtures['argon2i-m19456-t2-p1'] if route == 'signin' else fixtures['firebase-scrypt-m14-r8'])
            need(ok, 'Import failed: ' + label)
            uid, email = u(label)
            def attempt(i):
                target = base_a if i % 2 == 0 else base_b
                if route == 'signin':
                    code, body = self.call(target, '/recipe/signin', {'email': email, 'password': UNICODE})
                else:
                    code, body = self.call(target, '/expertauth/password/session', {'userId': uid, 'email': email, 'password': UNICODE,
                        'enableAntiCsrf': False, 'userDataInJWT': {}, 'userDataInDatabase': {}, 'useDynamicSigningKey': True}, rid='session')
                return code, str(body.get('status', ''))[:60], 'accessToken' in body
            with ThreadPoolExecutor(8) as pool: results = list(pool.map(attempt, range(8)))
            succeeded = sum(1 for c, s_, _ in results if c == 200 and s_ == 'OK')
            others = sorted({(c, s_) for c, s_, _ in results if not (c == 200 and s_ == 'OK')})
            final = self.stored(uid)
            detail = {'attempts': 8, 'succeeded': succeeded, 'other_outcomes': [list(o) for o in others]}
            if route == 'signin':
                self.case('CONCURRENT-SIGNIN-ALL-ACCEPTED-ONE-REHASH', succeeded == 8 and bool(bcrypt_target.match(final)) and
                          self.signin(base_b, email, UNICODE) and self.stored(uid) == final, **detail)
            else:
                count = self.sessions(uid); detail['sessions_in_database'] = count
                # One bounded retry after a concurrent rehash re-verifies against the new hash, so all attempts succeed.
                self.case('CONCURRENT-ATOMIC-SESSION-ALL-ACCEPTED-ONE-REHASH', succeeded == 8 and not others and count == 8
                          and bool(bcrypt_target.match(final)), **detail)
                self.case('CONCURRENT-ATOMIC-SESSION-STABLE-AFTER', self.session(base_b, uid, email, UNICODE) and self.stored(uid) == final)
        self.stop_core(a); self.stop_core(b)
        leaked = [i for i, body in enumerate(self.bodies) if any(marker in body for marker in HASH_MARKERS)]
        self.case('HASH-NEVER-EXPOSED-IN-RESPONSES', not leaked, responses=len(self.bodies), leaking=len(leaked))

    def cleanup(self):
        errors = []
        for name in list(self.containers):
            try:
                labels = json.loads(self.docker('inspect', '-f', '{{json .Config.Labels}}', name, check=False).stdout or b'{}')
                need(all(labels.get(k) == v for k, v in self.labels.items()), 'Ownership differs: ' + name)
                self.docker('rm', '-f', '-v', name); self.containers.remove(name)
            except Exception as error: errors.append(str(error))
        for name in list(self.networks):
            try: self.docker('network', 'rm', name); self.networks.remove(name)
            except Exception as error: errors.append(str(error))
        remaining = self.docker('ps', '-aq', '--filter', 'label=org.expertauth.run=' + self.run, check=False).stdout.strip()
        leaked = sorted(self.volumes() - getattr(self, 'volumes_before', self.volumes()))
        self.report['cleanup'] = {'containers_retired': not remaining and not self.containers, 'networks_retired': not self.networks,
                                  'errors': errors, 'volumes_left': leaked, 'images_built': 0}
        if not self.args.keep_scratch and self.scratch.exists():
            need(self.scratch.name.startswith('password-upgrade-') and not any(p.is_symlink() for p in self.scratch.rglob('*')), 'Unsafe scratch cleanup')
            shutil.rmtree(self.scratch); self.report['cleanup']['scratch_removed'] = True
        return not errors and not remaining and not leaked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--sources', required=True, help='Directory with pinned supertokens-core/-plugin-interface/-postgresql-plugin checkouts')
    parser.add_argument('--dependencies', required=True, help='Directory with core/ and plugin/ third-party JARs (verified against locks)')
    parser.add_argument('--aspectj', required=True, help='aspectjtools-1.9.24.jar')
    parser.add_argument('--scratch', required=True, help='Private scratch parent outside the repository (or under .runtime/)')
    parser.add_argument('--keep-scratch', action='store_true')
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.name), 'Invalid lab name')
    lab = Lab(args)
    lab.out.mkdir(parents=True); lab.scratch.mkdir(parents=True)
    try:
        lab.verify_inputs(); lab.build(); lab.scenarios()
    except Exception as error:
        lab.report['errors'].append(str(error) if isinstance(error, ValueError) else f'{type(error).__name__}: {error}')
    finally:
        clean = lab.cleanup()
        cases = lab.report['cases']
        lab.report['summary'] = {'cases': len(cases), 'passes': sum(c['passed'] for c in cases)}
        lab.report['passed'] = clean and not lab.report['errors'] and bool(cases) and all(c['passed'] for c in cases)
        lab.report['finished'] = datetime.now(timezone.utc).isoformat(); lab.persist()
    print(json.dumps({'passed': lab.report['passed'], 'summary': lab.report['summary'], 'findings': lab.report['findings'], 'errors': lab.report['errors'], 'cleanup': lab.report['cleanup']}))
    return 0 if lab.report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
