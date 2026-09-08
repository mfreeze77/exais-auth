"""One bounded acquisition of primary-source notices and release mapping metadata.

Maximum total response bytes: 2 MB. No source archives or native binaries fetched.
"""
from pathlib import Path
import hashlib
import json
import urllib.error
import urllib.request

OUT = Path('/out/upstream')
OUT.mkdir(exist_ok=True)
LIMIT = 2_000_000
total = 0
records = []
REPOS = {
    'scrypt': ('wg/scrypt', '1.4.0', '0675236370458e819ee21e4427c5f7f3f9485d33'),
    'jna': ('java-native-access/jna', '5.8.0', 'cc4ce71d511a9aa17219cc36e2338dd1b0f52770'),
}


def fetch(name, url, kind, repo, commit):
    global total
    request = urllib.request.Request(url, headers={'User-Agent': 'ExpertAuth-bounded-license-evidence/1',
                                                 'Accept': 'application/vnd.github+json' if kind == 'mapping' else '*/*'})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(min(300_000, LIMIT - total) + 1)
            if len(raw) > min(300_000, LIMIT - total):
                raise RuntimeError('Bounded response limit exceeded; not persisted')
            total += len(raw)
            record = {'path': 'upstream/' + name, 'url': url, 'final_url': response.url,
                      'kind': kind, 'repo': repo, 'commit': commit, 'http_status': response.status,
                      'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            (OUT / name).write_bytes(raw)
            records.append(record)
    except Exception as exc:
        records.append({'url': url, 'kind': kind, 'repo': repo, 'commit': commit,
                        'error': type(exc).__name__ + ': ' + str(exc)})


for name, (repo, tag, commit) in REPOS.items():
    fetch(name + '-tag.json', 'https://api.github.com/repos/' + repo + '/git/ref/tags/' + tag,
          'mapping', repo, commit)
files = {
    'scrypt': ['LICENSE', 'Makefile', 'pom.xml', 'README', 'src/main/c/crypto_scrypt-sse.c',
               'src/main/c/crypto_scrypt-nosse.c', 'src/main/c/sha256.c', 'src/main/c/scrypt_jni.c'],
    'jna': ['LICENSE', 'OTHERS', 'native/Makefile', 'native/libffi/LICENSE', 'pom-jna.xml'],
}
for name, paths in files.items():
    repo, tag, commit = REPOS[name]
    for path in paths:
        fetch(name + '__' + path.replace('/', '__'),
              'https://raw.githubusercontent.com/' + repo + '/' + commit + '/' + path,
              'source', repo, commit)

repo, tag, commit = REPOS['scrypt']
fetch('scrypt-tree.json', 'https://api.github.com/repos/' + repo + '/git/trees/' + commit + '?recursive=1',
      'mapping', repo, commit)
repo, tag, commit = REPOS['jna']
# GitHub's object metadata for >1 MB blobs omits content. Do not fetch dist/jna.jar.
fetch('jna-dist-jar-metadata.json', 'https://api.github.com/repos/' + repo + '/contents/dist/jna.jar?ref=' + commit,
      'mapping', repo, commit)
(OUT.parent / 'supplemental-fetch.json').write_text(json.dumps({'maximum_bytes': LIMIT, 'total_response_bytes': total,
        'container_name': 'expertauth-runtime-distribution-notices-20260908',
        'records': records}, indent=2) + '\n')
print(json.dumps({'responses_saved': sum('sha256' in r for r in records),
                  'errors': [r for r in records if 'error' in r], 'total_response_bytes': total}))
