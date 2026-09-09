"""Bounded primary-source acquisition for native dependency review.

Fetch metadata or explicitly requested text blobs only. Never fetch archives,
native binaries, moving-branch source or an arbitrary origin. Source collection
does not approve redistribution, native build correspondence or authentication.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/reuse/native-correspondence'
REPOS = {'wg/scrypt', 'java-native-access/jna', 'phxql/argon2-jvm', 'xerial/sqlite-jdbc', 'P-H-C/phc-winner-argon2'}
PINS = {'jna': ('java-native-access/jna', 'cc4ce71d511a9aa17219cc36e2338dd1b0f52770'),
        'sqlite': ('xerial/sqlite-jdbc', '5ac6b0d4bf42244f1d48b39af74e87ce7621cac6')}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
BINARY_NAME = re.compile(r'\.(?:jar|class|so(?:\.\d+)*|dll|dylib|jnilib|a|o|lib|exe|zip|gz|pdf|png|jpg)$', re.I)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(value):
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and str(path) == value and
            all(part not in {'', '.', '..'} for part in path.parts) and
            '\\' not in value and ':' not in value, 'Unsafe acquisition path')
    return path


def approved_url(url):
    value = urlsplit(url)
    require(value.scheme == 'https' and not value.fragment and not value.username and not value.password,
            'Invalid source URL')
    parts = value.path.strip('/').split('/')
    if url == 'https://www.gnu.org/licenses/gpl-3.0.txt':
        return url
    if value.netloc == 'api.github.com':
        require(len(parts) >= 5 and parts[0] == 'repos' and '/'.join(parts[1:3]) in REPOS and
                parts[3] == 'git' and parts[4] in {'ref', 'tags', 'commits', 'trees'} and
                value.query in {'', 'recursive=1'}, 'Unapproved metadata endpoint')
    else:
        require(value.netloc == 'raw.githubusercontent.com' and len(parts) >= 4 and
                '/'.join(parts[:2]) in REPOS and re.fullmatch('[0-9a-f]{40}', parts[2]) and
                not value.query, 'Source must use a reviewed repository and immutable commit')
        safe_path('/'.join(parts[3:]))
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        approved_url(url)
        return super().redirect_request(request, fp, code, message, headers, url)


def validate_source_request(request):
    rows = request['files']
    require(isinstance(rows, list) and 0 < len(rows) <= 1000, 'Invalid source list')
    seen = set()
    total = 0
    for row in rows:
        path = row['path']
        safe_path(path)
        require(path.casefold() not in {'acquisition.json', 'container.json'}, 'Reserved acquisition artifact path')
        require(path not in seen, 'Duplicate source path')
        seen.add(path)
        url = urlsplit(approved_url(row['url']))
        require(url.netloc == 'raw.githubusercontent.com' and '/'.join(url.path.strip('/').split('/')[3:]) == path,
                'Source URL path must equal the requested source path')
        require(not BINARY_NAME.search(path), 'Binary/archive is not a source capture')
        size, blob = row['expected_bytes'], row['expected_git_blob_sha1']
        require(type(size) is int and 0 < size <= MAX_FILE, 'Exact positive source size required')
        require(isinstance(blob, str) and re.fullmatch('[0-9a-f]{40}', blob), 'Exact Git blob identity required')
        total += size
    require(total <= MAX_TOTAL, 'Acquisition size budget exceeded')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--metadata', action='store_true')
    mode.add_argument('--license-texts', action='store_true')
    mode.add_argument('--request', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(BASE.resolve()) and output != BASE.resolve(), 'Output escaped native review directory')
    output.mkdir(parents=True, exist_ok=True)
    require(not any(output.iterdir()), 'Preserve existing acquisition output')
    report = {'schema': 'expertauth-native-source-acquisition-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'tool_sha256': sha(Path(__file__).read_bytes()), 'records': [], 'errors': [], 'total_bytes': 0,
              'license_approved': False, 'native_build_qualified': False, 'authentication_complete': False}
    opener = urllib.request.build_opener(Redirects())

    def acquire(name, url, *, expected_bytes=None, blob=None):
        path = output / safe_path(name)
        maximum = expected_bytes if expected_bytes is not None else MAX_FILE
        require(0 < maximum <= MAX_FILE and report['total_bytes'] + maximum <= MAX_TOTAL, 'Acquisition size budget exceeded')
        with opener.open(urllib.request.Request(approved_url(url), headers={'User-Agent': 'ExpertAuth-source-review'}), timeout=30) as response:
            approved_url(response.url)
            raw = response.read(maximum + 1)
            require(len(raw) <= maximum and (expected_bytes is None or len(raw) == expected_bytes), 'Source byte length differs')
            final_url, status = response.url, response.status
        if blob is not None:
            require(re.fullmatch('[0-9a-f]{40}', blob), 'Invalid Git blob identity')
            require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob, 'Git source object mismatch')
            require(b'\0' not in raw, 'Requested source contains binary bytes')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        report['total_bytes'] += len(raw)
        report['records'].append({'path': name, 'url': url, 'final_url': final_url, 'http_status': status,
                                  'bytes': len(raw), 'sha256': sha(raw), 'expected_git_blob_sha1': blob})
        return raw

    try:
        if args.metadata:
            ref = json.loads(acquire('argon2/ref.json', 'https://api.github.com/repos/phxql/argon2-jvm/git/ref/tags/v2.11'))['object']
            for depth in range(3):
                if ref['type'] == 'commit':
                    break
                require(ref['type'] == 'tag' and re.fullmatch('[0-9a-f]{40}', ref['sha']), 'Unexpected tag object')
                ref = json.loads(acquire(f'argon2/tag-{depth}.json', 'https://api.github.com/repos/phxql/argon2-jvm/git/tags/' + ref['sha']))['object']
            require(ref['type'] == 'commit', 'Tag resolution depth exceeded')
            pins = {**PINS, 'argon2': ('phxql/argon2-jvm', ref['sha'])}
            report['commits'] = {}
            acquire('scrypt/commit.json', 'https://api.github.com/repos/wg/scrypt/git/commits/0675236370458e819ee21e4427c5f7f3f9485d33')
            for component, (repo, commit) in pins.items():
                require(re.fullmatch('[0-9a-f]{40}', commit), 'Invalid commit pin')
                base = 'https://api.github.com/repos/' + repo + '/git/'
                record = json.loads(acquire(component + '/commit.json', base + 'commits/' + commit))
                require(record['sha'] == commit, 'Commit metadata differs')
                tree = json.loads(acquire(component + '/tree.json', base + 'trees/' + record['tree']['sha'] + '?recursive=1'))
                require(tree.get('truncated') is False and tree['sha'] == record['tree']['sha'], 'Incomplete or mismatched source tree')
                report['commits'][component] = {'repo': repo, 'commit': commit, 'tree': tree['sha'], 'members': len(tree['tree'])}
        elif args.license_texts:
            acquire('GPL-3.0.txt', 'https://www.gnu.org/licenses/gpl-3.0.txt')
        else:
            request_path = args.request.resolve()
            require(request_path.is_relative_to(BASE.resolve()), 'Request outside native review')
            request = json.loads(request_path.read_bytes())
            rows = validate_source_request(request)
            report['request'] = {'path': request_path.relative_to(ROOT).as_posix(), 'sha256': sha(request_path.read_bytes())}
            for row in rows:
                acquire(row['path'], row['url'], expected_bytes=row['expected_bytes'], blob=row['expected_git_blob_sha1'])
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    report['finished'] = datetime.now(timezone.utc).isoformat()
    report['passed'] = not report['errors']
    with (output / 'acquisition.json').open('xb') as stream:
        stream.write((json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps({'output': output.relative_to(ROOT).as_posix(), 'passed': report['passed'], 'records': len(report['records']),
                      'bytes': report['total_bytes'], 'errors': report['errors']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
