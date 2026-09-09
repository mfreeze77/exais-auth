"""Authenticated, bounded recovery bundles for three private operational files.

CLI: keygen --key PATH; pack --source DIR --key PATH --archive PATH;
     unpack --archive PATH --key PATH --destination DIR.

The external Fernet key is never included in the archive. Fernet authenticates
the complete envelope before its inventory is interpreted. No decryption TTL
is imposed on backups. This utility does not qualify external key management,
database consistency, provider recovery, or independent security review.

On write failure, existing inputs and any newly created partial archive/key or
private .expertauth-recovery-* staging directory are preserved for inspection.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile

from cryptography.fernet import Fernet, InvalidToken


FILES = ('database.pgdump', 'core-config.yaml', 'runtime.env')
SCHEMA = 'expertauth-recovery-v1'
MAX_PLAINTEXT = 32 * 1024 * 1024
MAX_ARCHIVE = 48 * 1024 * 1024
MAX_HEADER = 16 * 1024


class BundleError(ValueError):
    """A fixed status code, never file contents or an underlying exception."""

    def __init__(self, status):
        self.status = status
        super().__init__(status)


def require(value, status):
    if not value:
        raise BundleError(status)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _regular_bytes(path, limit, status):
    path = Path(path)
    try:
        require(not path.is_symlink(), status)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, status)
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        require(len(raw) <= limit and len(raw) == before.st_size, status)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), status)
        return raw
    except (OSError, ValueError) as error:
        if isinstance(error, BundleError):
            raise
        raise BundleError(status) from None


def _fernet(key_path):
    raw = _regular_bytes(key_path, 44, 'INVALID_KEY')
    try:
        require(len(raw) == 44, 'INVALID_KEY')
        decoded = base64.b64decode(raw, altchars=b'-_', validate=True)
        require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded) == raw, 'INVALID_KEY')
        return Fernet(raw)
    except (ValueError, TypeError):
        raise BundleError('INVALID_KEY') from None


def _exclusive_write(path, raw, status):
    """Never truncate existing files; preserve a partial file if writing fails."""
    try:
        descriptor = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise BundleError(status) from None


def generate_key(key_path):
    raw = Fernet.generate_key()
    _exclusive_write(key_path, raw, 'KEY_CREATE_REFUSED_OR_FAILED')
    return {'status': 'KEY_CREATED', 'key_bytes': len(raw)}


def _source_names(source):
    try:
        require(source.is_dir() and not source.is_symlink(), 'INVALID_SOURCE_DIRECTORY')
        require({path.name for path in source.iterdir()} == set(FILES), 'INVALID_SOURCE_INVENTORY')
    except OSError:
        raise BundleError('INVALID_SOURCE_DIRECTORY') from None


def _summary(status, archive, plaintext, header, inventory):
    return {'status': status, 'archive_bytes': len(archive), 'archive_sha256': digest(archive),
            'plaintext_bytes': len(plaintext), 'inventory_sha256': digest(header),
            'files': {item['name']: {'bytes': item['bytes'], 'sha256': item['sha256']} for item in inventory}}


def pack(source, key_path, archive_path):
    cipher = _fernet(key_path)
    source = Path(source)
    _source_names(source)
    parts, inventory, total = [], [], 0
    for name in FILES:
        raw = _regular_bytes(source / name, MAX_PLAINTEXT - total, 'INVALID_SOURCE_FILE_OR_SIZE')
        total += len(raw)
        parts.append(raw)
        inventory.append({'name': name, 'bytes': len(raw), 'sha256': digest(raw)})
    _source_names(source)
    header = json.dumps({'schema': SCHEMA, 'files': inventory, 'total_bytes': total},
                        separators=(',', ':'), sort_keys=True).encode('utf-8')
    require(len(header) <= MAX_HEADER and 4 + len(header) + total <= MAX_PLAINTEXT, 'PLAINTEXT_SIZE_EXCEEDED')
    plaintext = struct.pack('>I', len(header)) + header + b''.join(parts)
    archive = cipher.encrypt(plaintext)
    require(len(archive) <= MAX_ARCHIVE, 'ARCHIVE_SIZE_EXCEEDED')
    _exclusive_write(archive_path, archive, 'ARCHIVE_CREATE_REFUSED_OR_FAILED')
    return _summary('PACKED', archive, plaintext, header, inventory)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'INVALID_INVENTORY')
        result[key] = value
    return result


def _invalid_constant(_value):
    raise BundleError('INVALID_INVENTORY')


def _decode_envelope(plaintext):
    require(4 < len(plaintext) <= MAX_PLAINTEXT, 'INVALID_ENVELOPE_SIZE')
    header_size = struct.unpack('>I', plaintext[:4])[0]
    require(0 < header_size <= MAX_HEADER and 4 + header_size <= len(plaintext), 'INVALID_INVENTORY')
    header = plaintext[4:4 + header_size]
    try:
        parsed = json.loads(header.decode('utf-8'), object_pairs_hook=_unique_object,
                            parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise BundleError('INVALID_INVENTORY') from None
    require(type(parsed) is dict and set(parsed) == {'schema', 'files', 'total_bytes'}, 'INVALID_INVENTORY')
    require(parsed['schema'] == SCHEMA, 'UNSUPPORTED_SCHEMA')
    require(type(parsed['total_bytes']) is int and 0 <= parsed['total_bytes'] <= MAX_PLAINTEXT, 'INVALID_INVENTORY')
    inventory = parsed['files']
    require(type(inventory) is list and len(inventory) == len(FILES), 'INVALID_INVENTORY')
    offset, restored = 4 + header_size, {}
    for expected, item in zip(FILES, inventory):
        require(type(item) is dict and set(item) == {'name', 'bytes', 'sha256'}, 'INVALID_INVENTORY')
        require(item['name'] == expected, 'INVALID_INVENTORY')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_PLAINTEXT, 'INVALID_INVENTORY')
        require(type(item['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', item['sha256']) is not None,
                'INVALID_INVENTORY')
        end = offset + item['bytes']
        require(end <= len(plaintext), 'INVALID_INVENTORY')
        raw = plaintext[offset:end]
        require(digest(raw) == item['sha256'], 'INVENTORY_HASH_MISMATCH')
        restored[expected] = raw
        offset = end
    require(offset == len(plaintext) and sum(len(raw) for raw in restored.values()) == parsed['total_bytes'],
            'INVALID_INVENTORY')
    return header, inventory, restored


def _destination_ready(destination):
    try:
        require(not destination.is_symlink(), 'DESTINATION_NOT_EMPTY_OR_INVALID')
        if destination.exists():
            require(destination.is_dir() and not any(destination.iterdir()), 'DESTINATION_NOT_EMPTY_OR_INVALID')
        require(destination.parent.is_dir() and not destination.parent.is_symlink(), 'DESTINATION_PARENT_INVALID')
    except OSError:
        raise BundleError('DESTINATION_NOT_EMPTY_OR_INVALID') from None


def unpack(archive_path, key_path, destination):
    cipher = _fernet(key_path)
    archive = _regular_bytes(archive_path, MAX_ARCHIVE, 'INVALID_ARCHIVE_FILE_OR_SIZE')
    try:
        decoded = base64.b64decode(archive, altchars=b'-_', validate=True)
        require(base64.urlsafe_b64encode(decoded) == archive, 'AUTHENTICATION_FAILED')
        plaintext = cipher.decrypt(archive)
    except (InvalidToken, ValueError, TypeError):
        raise BundleError('AUTHENTICATION_FAILED') from None
    header, inventory, restored = _decode_envelope(plaintext)
    destination = Path(destination)
    _destination_ready(destination)
    # All authentication, schema, path, size, membership and hash checks have
    # succeeded. Staging keeps partial writes out of the requested destination.
    try:
        stage = Path(tempfile.mkdtemp(prefix='.expertauth-recovery-', dir=destination.parent))
        for name in FILES:
            _exclusive_write(stage / name, restored[name], 'RESTORE_WRITE_FAILED')
        _destination_ready(destination)
        if destination.exists():
            destination.rmdir()  # Fails if another writer made it nonempty.
        os.rename(stage, destination)  # Nonempty destinations cannot be replaced.
    except (OSError, BundleError):
        raise BundleError('RESTORE_WRITE_FAILED') from None
    return _summary('UNPACKED', archive, plaintext, header, inventory)


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise BundleError('INVALID_ARGUMENTS')


def main(argv=None):
    try:
        parser = _Parser(description=__doc__)
        commands = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)
        key = commands.add_parser('keygen')
        key.add_argument('--key', type=Path, required=True)
        create = commands.add_parser('pack')
        create.add_argument('--source', type=Path, required=True)
        create.add_argument('--key', type=Path, required=True)
        create.add_argument('--archive', type=Path, required=True)
        restore = commands.add_parser('unpack')
        restore.add_argument('--archive', type=Path, required=True)
        restore.add_argument('--key', type=Path, required=True)
        restore.add_argument('--destination', type=Path, required=True)
        args = parser.parse_args(argv)
        if args.command == 'keygen':
            result = generate_key(args.key)
        elif args.command == 'pack':
            result = pack(args.source, args.key, args.archive)
        else:
            result = unpack(args.archive, args.key, args.destination)
        print(json.dumps(result, sort_keys=True))
        return 0
    except BundleError as error:
        print(json.dumps({'status': error.status}))
        return 1
    except Exception:
        print(json.dumps({'status': 'IO_OR_RUNTIME_FAILURE'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
