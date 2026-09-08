"""Acquire reviewed hash-locked Maven sources; reuse verified cached bytes.

Never resolves versions, rewrites locks or substitutes an unavailable source.
No authentication-vendor interaction or distribution approval is performed.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'reuse/runtime-source-archives.lock.json'
ORIGINS = {'repo.maven.apache.org': '/maven2/', 'build.shibboleth.net': '/maven/releases/'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def approved_url(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.netloc in ORIGINS and
            parsed.path.startswith(ORIGINS[parsed.netloc]) and not parsed.query and not parsed.fragment,
            'Source origin outside reviewed repositories')
    return url


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        approved_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def cache_path(row):
    cache = (ROOT / '.cache/runtime-source-jars').resolve()
    path = (ROOT / row['path']).resolve()
    require(cache.is_relative_to(ROOT.resolve()) and path.parent == cache, 'Source cache path outside exact boundary')
    return path


def validate_lock(lock):
    require(lock['schema'] == 'expertauth-runtime-source-lock-v1', 'Unknown source lock schema')
    inventory = ROOT / 'reuse/runtime-dependencies.json'
    require(sha(inventory.read_bytes()) == lock['runtime_inventory_sha256'], 'Runtime inventory drift')
    dependencies = {row['coordinate']: row['jar']['sha256'] for row in json.loads(inventory.read_bytes())['dependencies']}
    entries = lock['entries']
    require(len(entries) == len(dependencies) == 84 and {row['coordinate'] for row in entries} == set(dependencies),
            'Missing, duplicate or substituted runtime coordinate')
    evidence = lock['acquisition_evidence']
    path = (ROOT / evidence['path']).resolve()
    require(path.is_relative_to((ROOT / 'evidence/reuse/runtime-source-notices').resolve()), 'Acquisition evidence path escaped')
    require(sha(path.read_bytes()) == evidence['sha256'], 'Acquisition evidence drift')
    original = json.loads(path.read_bytes())
    require(sorted(original['sources'], key=lambda row: row['coordinate']) == entries, 'Source lock differs from reviewed acquisition')
    for row in entries:
        require(row['runtime_jar_sha256'] == dependencies[row['coordinate']], 'Source/binary mapping drift')
        approved_url(row['url'])
        require(row['status'] in ('available', 'unavailable'), 'Unresolved fetch failure cannot be locked')
        if row['status'] == 'available':
            cache_path(row)
            require(0 < row['bytes'] <= 64 * 1024 * 1024, 'Source archive exceeds size bound')
    return entries


def verify_bytes(raw, row):
    require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'Source archive byte/hash mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(len(archive.infolist()) == row['members'], 'Source archive membership count mismatch')
        require(sum(item.file_size for item in archive.infolist()) <= 512 * 1024 * 1024, 'Source expansion exceeds bound')
        require(archive.testzip() is None, 'Source archive CRC mismatch')


def fetch(row, *, offline=False):
    base = {'coordinate': row['coordinate'], 'runtime_jar_sha256': row['runtime_jar_sha256']}
    if row['status'] == 'unavailable':
        return {**base, 'status': 'source-unavailable-at-recorded-acquisition', 'downloaded': False, 'url': row['url']}
    target = cache_path(row)
    if target.exists():
        verify_bytes(target.read_bytes(), row)
        return {**base, 'status': 'verified', 'sha256': row['sha256'], 'bytes': row['bytes'], 'downloaded': False}
    require(not offline, 'Locked source missing in offline cache: ' + row['coordinate'])
    opener = urllib.request.build_opener(CheckedRedirect())
    with opener.open(approved_url(row['url']), timeout=45) as response:
        approved_url(response.url)
        raw = response.read(row['bytes'] + 1)
    verify_bytes(raw, row)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as output:
        output.write(raw)
    return {**base, 'status': 'verified', 'sha256': row['sha256'], 'bytes': row['bytes'], 'downloaded': True}


def ensure_sources(*, offline=False):
    entries = validate_lock(json.loads(LOCK.read_bytes()))
    def acquire(row):
        try:
            return fetch(row, offline=offline)
        except Exception as error:
            return {'coordinate': row['coordinate'], 'status': 'failed', 'error': str(error), 'downloaded': False}
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(acquire, entries))
    require(not any(row['status'] == 'failed' for row in results),
            'Locked source acquisition failed: ' + json.dumps([row for row in results if row['status'] == 'failed']))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    results = ensure_sources(offline=args.offline)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    report = {'timestamp_utc': stamp, 'source_lock_sha256': sha(LOCK.read_bytes()),
              'tool_sha256': sha(Path(__file__).read_bytes()), 'offline': args.offline, 'results': results,
              'full_distribution_approved': False}
    output = ROOT / 'evidence/reuse/runtime-source-notices' / f'locked-{stamp}.json'
    with output.open('xb') as stream:
        stream.write((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'verified': sum(row['status'] == 'verified' for row in results),
                      'downloaded': sum(row['downloaded'] for row in results),
                      'unavailable': sum(row['status'].startswith('source-unavailable') for row in results)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
