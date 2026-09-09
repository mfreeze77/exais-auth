"""Acquire the existing 49 hash-locked Linux wheels into one bounded local cache.

No dependency resolution, version changes, installation or vendor calls. Run
inside the cached Python base when host networking is unavailable.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import urllib.request
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_WHEEL = 32 * 1024 * 1024
MAX_CACHE = 128 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def approved_url(url):
    parsed = urlsplit(url)
    need(parsed.scheme == 'https' and parsed.netloc == 'files.pythonhosted.org' and
         parsed.path.startswith('/packages/') and not parsed.query and not parsed.fragment,
         'Wheel URL outside pinned public artifact origin')
    name = parsed.path.rsplit('/', 1)[-1]
    need(re.fullmatch(r'[A-Za-z0-9_.-]+\.whl', name), 'Unsafe wheel filename')
    return name


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        approved_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def locked_wheels():
    resolution = json.loads((ROOT / 'examples/python/dependency-resolution.json').read_bytes())
    locked = {}
    for line in (ROOT / 'examples/python/requirements.lock').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})', line)
        need(match is not None, 'Unexpected requirement syntax')
        name, version, digest = match.groups()
        key = normalized(name)
        need(key not in locked, 'Duplicate normalized requirement')
        locked[key] = (version, digest)
    rows = []
    for entry in resolution['install']:
        name, version = entry['metadata']['name'], entry['metadata']['version']
        download = entry['download_info']
        digest = download['archive_info']['hashes']['sha256']
        filename = approved_url(download['url'])
        need(locked.get(normalized(name)) == (version, digest), 'Resolution differs from hash lock')
        rows.append({'name': name, 'version': version, 'sha256': digest,
                     'url': download['url'], 'filename': filename})
    need(len(rows) == len(locked) == len({normalized(row['name']) for row in rows}) == 49 and
         len({row['filename'].casefold() for row in rows}) == 49, 'Wheel inventory differs')
    return rows


def verify_wheel(raw, row):
    need(0 < len(raw) <= MAX_WHEEL and sha(raw) == row['sha256'], 'Wheel size/hash mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        members = wheel.infolist()
        need(len(members) == len({member.filename for member in members}) <= 100000 and
             sum(member.file_size for member in members) <= 512 * 1024 * 1024,
             'Wheel expansion or inventory exceeds bound')
        for member in members:
            path = PurePosixPath(member.filename)
            need(not path.is_absolute() and '..' not in path.parts and '\\' not in member.filename,
                 'Unsafe wheel member path')
        need(wheel.testzip() is None, 'Wheel CRC failure')
        metadata = [member for member in members if member.filename.endswith('.dist-info/METADATA')]
        need(len(metadata) == 1, 'Wheel distribution metadata missing or ambiguous')
        parsed = BytesParser().parsebytes(wheel.read(metadata[0]))
        need(normalized(parsed['Name']) == normalized(row['name']) and parsed['Version'] == row['version'],
             'Wheel metadata differs from locked coordinate')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    need(output.is_relative_to((ROOT / 'evidence/reuse/python-wheel-cache').resolve()) and
         output.name.endswith('.json') and not output.exists(), 'Use a fresh wheel-cache evidence file')
    cache = (ROOT / '.cache/python-wheels').resolve()
    need(cache.parent == (ROOT / '.cache').resolve() and cache.is_relative_to(ROOT.resolve()), 'Wheel cache boundary differs')
    rows = locked_wheels()  # Reject the entire inventory before any network request.
    cache.mkdir(parents=True, exist_ok=True)
    allowed = {row['filename'] for row in rows}
    need(all(p.is_file() and not p.is_symlink() and p.name in allowed for p in cache.iterdir()),
         'Unknown or linked files in dedicated wheel cache; preserve and investigate')
    report = {'schema': 'expertauth-locked-python-wheels-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'offline': args.offline, 'passed': False, 'results': [], 'errors': [],
              'input_sha256': {p: sha((ROOT / p).read_bytes()) for p in
                               ['tools/fetch_python_wheels.py', 'examples/python/requirements.lock',
                                'examples/python/dependency-resolution.json']},
              'maximum_cache_bytes': MAX_CACHE, 'maximum_wheel_bytes': MAX_WHEEL,
              'full_distribution_approved': False}
    try:
        total = sum(p.stat().st_size for p in cache.iterdir())
        need(total <= MAX_CACHE, 'Wheel cache already exceeds bound')
        opener = urllib.request.build_opener(CheckedRedirect())
        for row in rows:
            target = cache / row['filename']
            downloaded = not target.exists()
            if downloaded:
                need(not args.offline, 'Locked wheel absent in offline cache: ' + row['filename'])
                with opener.open(row['url'], timeout=30) as response:
                    approved_url(response.url)
                    raw = response.read(min(MAX_WHEEL, MAX_CACHE - total) + 1)
                verify_wheel(raw, row)
                need(total + len(raw) <= MAX_CACHE, 'Wheel cache would exceed bound')
                with target.open('xb') as stream:
                    stream.write(raw)
                total += len(raw)
            else:
                need(target.stat().st_size <= MAX_WHEEL, 'Cached wheel exceeds bound')
                raw = target.read_bytes()
                verify_wheel(raw, row)
            report['results'].append({**row, 'bytes': len(raw), 'downloaded': downloaded,
                                      'status': 'hash-and-metadata-verified'})
        need(all(sha((ROOT / p).read_bytes()) == digest for p, digest in report['input_sha256'].items()),
             'Wheel acquisition inputs changed')
        report['cache_bytes'] = total
        report['passed'] = True
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    report['finished'] = datetime.now(timezone.utc).isoformat()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'verified': len(report['results']),
                      'downloaded': sum(row['downloaded'] for row in report['results']),
                      'cache_bytes': report.get('cache_bytes'), 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
