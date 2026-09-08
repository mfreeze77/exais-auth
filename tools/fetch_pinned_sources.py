"""Reconstruct the exact audited source cache without resolving moving releases."""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request
from build_oss_core import SOURCES, ROOT

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    counts = {}
    for name, commit in SOURCES.items():
        manifest_path = ROOT/'reuse/files'/f'supertokens__{name}__{commit}.json'
        if not manifest_path.exists():
            manifest_path = ROOT/'reuse/files'/f'supertokens__{name}.json'
        manifest = json.loads(manifest_path.read_text())
        assert manifest['commit'] == commit
        url = f'https://codeload.github.com/supertokens/{name}/tar.gz/{commit}'
        with urllib.request.urlopen(url,timeout=90) as response:
            raw = response.read()
        assert digest(raw)==manifest['archive']['sha256'], 'Source archive hash differs'
        destination = ROOT/'.cache/reuse-audit/source'/f'supertokens__{name}'/commit
        allowed = {r['source_path']:r['sha256'] for r in manifest['files']}
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive:
                relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
                if 'ee' in relative.parts or not member.isfile():
                    continue
                assert not relative.is_absolute() and '..' not in relative.parts
                path = relative.as_posix()
                if path not in allowed:
                    continue
                assert path not in seen, 'Duplicate archive member'
                seen.add(path)
                data = archive.extractfile(member).read()
                assert digest(data)==allowed[path], f'Archive file hash differs: {path}'
                target = destination/Path(path)
                assert target.resolve().is_relative_to(destination.resolve())
                target.parent.mkdir(parents=True,exist_ok=True)
                if target.exists() and digest(target.read_bytes())==allowed[path]:
                    continue
                tmp = target.with_name(target.name+'.expertauth-download-tmp')
                tmp.write_bytes(data)
                tmp.replace(target)
        assert seen==set(allowed), f'Incomplete source archive: {name}'
        counts[name]=len(seen)
    print(json.dumps({'immutable_sources_reconstructed':counts,'enterprise_paths_extracted':0}))

if __name__=='__main__':
    main()
