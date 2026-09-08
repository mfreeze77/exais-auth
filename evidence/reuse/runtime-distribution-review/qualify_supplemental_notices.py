"""Bind retained small upstream notices to the already-cached release binaries.

Reads only local files; exact notice excerpts are byte ranges of retained source.
No build, execution, download or general license approval.
"""
from pathlib import Path
import hashlib
import json
import zipfile

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
UP = OUT / 'upstream'
inventory = json.loads((OUT / 'archive-inventory.json').read_text())
fetch = json.loads((OUT / 'supplemental-fetch.json').read_text())
by_name = {Path(x['path']).name: x for x in fetch['records'] if 'sha256' in x}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


for name, entry in by_name.items():
    assert sha((UP / name).read_bytes()) == entry['sha256'], name

scrypt = next(x for x in inventory['artifacts'] if x['coordinate'] == 'com.lambdaworks:scrypt:1.4.0')
jna = next(x for x in inventory['artifacts'] if x['coordinate'] == 'net.java.dev.jna:jna:5.8.0')
tree = json.loads((UP / 'scrypt-tree.json').read_text())
assert not tree.get('truncated')
tree_files = {x['path']: x for x in tree['tree']}
bindings = []
for component in ('scrypt', 'jna'):
    tag = json.loads((UP / (component + '-tag.json')).read_text())
    expected = by_name[component + '-tag.json']['commit']
    assert tag['object'] == dict(tag['object'], type='commit', sha=expected)

with zipfile.ZipFile(ROOT / scrypt['binary']['path']) as z:
    for member in scrypt['binary']['native_members']:
        raw = z.read(member['member'])
        upstream_path = 'src/main/resources/' + member['member']
        actual = git_blob(raw)
        expected = tree_files[upstream_path]['sha']
        assert actual == expected
        bindings.append({'coordinate': scrypt['coordinate'], 'binary_jar_sha256': scrypt['binary']['sha256'],
                         'jar_member': member['member'], 'member_sha256': sha(raw),
                         'release_commit': by_name['scrypt-tag.json']['commit'], 'upstream_path': upstream_path,
                         'git_blob_sha1': actual, 'matches_release_tree': True})
raw = (ROOT / jna['binary']['path']).read_bytes()
meta = json.loads((UP / 'jna-dist-jar-metadata.json').read_text())
assert git_blob(raw) == meta['sha'] and len(raw) == meta['size']
bindings.append({'coordinate': jna['coordinate'], 'binary_jar_sha256': sha(raw),
                 'release_commit': by_name['jna-tag.json']['commit'], 'upstream_path': 'dist/jna.jar',
                 'git_blob_sha1': git_blob(raw), 'matches_release_tree': True})

eligible = []
for name, coordinate, license_name in (
    ('scrypt__LICENSE', scrypt['coordinate'], 'Apache-2.0'),
    ('jna__native__libffi__LICENSE', jna['coordinate'], 'MIT'),
):
    entry = by_name[name]
    eligible.append({'path': (UP / name).relative_to(ROOT).as_posix(), 'sha256': entry['sha256'],
                     'bytes': entry['bytes'], 'coordinate': coordinate, 'license': license_name,
                     'source_url': entry['url'], 'source_commit': entry['commit'],
                     'eligible_for_supplemental_notice_packaging': True,
                     'eligibility_scope': 'Preserve unmodified notice from matched release source tree; not exhaustive license closure'})

for name in ('scrypt__src__main__c__crypto_scrypt-sse.c', 'scrypt__src__main__c__crypto_scrypt-nosse.c',
             'scrypt__src__main__c__sha256.c'):
    entry = by_name[name]
    raw = (UP / name).read_bytes()
    source_path = name.split('__', 1)[1].replace('__', '/')
    assert git_blob(raw) == tree_files[source_path]['sha']
    assert raw.startswith(b'/*') and b'*/' in raw
    end = raw.index(b'*/') + 2
    notice = raw[:end]
    assert b'Redistribution' in notice and b'disclaimer' in notice
    target = OUT / (name + '.notice.txt')
    target.write_bytes(notice)
    eligible.append({'path': target.relative_to(ROOT).as_posix(), 'sha256': sha(notice), 'bytes': len(notice),
                     'coordinate': scrypt['coordinate'], 'license': 'BSD-2-Clause',
                     'source_file': (UP / name).relative_to(ROOT).as_posix(), 'source_sha256': entry['sha256'],
                     'source_url': entry['url'], 'source_commit': entry['commit'],
                     'exact_source_byte_range': {'start_inclusive': 0, 'end_exclusive': end},
                     'eligible_for_supplemental_notice_packaging': True,
                     'eligibility_scope': 'Exact copyright/permission/disclaimer block from matched release source tree; not exhaustive license closure'})

result = {'scope': 'Supplemental attribution eligibility only; all native licensing/build closure remains unqualified',
          'license_approved': False, 'native_corresponding_source_complete': False,
          'native_rebuild_verified': False, 'bindings': bindings, 'files': eligible,
          'limitations': ['Release-tree byte identity does not prove binaries were built from that tree.',
                         'Headers, transitive native dependencies, static compiler runtimes and all platform builds are not fully audited.',
                         'Argon2 and SQLite native corresponding-source/build gaps remain unchanged.']}
(OUT / 'supplemental-notices.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'release_binary_bindings': len(bindings), 'eligible_supplemental_notices': len(eligible)}))
