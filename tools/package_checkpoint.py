"""Package a clean local commit as an explicitly PARTIAL, hash-validated snapshot.

No publication, release approval, engine selection, or entitlement is implied.
Only committed files enter the ZIP. Runtime secrets, caches and build outputs stay
outside it. A Git bundle preserves the actual repository history for resumption.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def run(args, cwd=ROOT):
    return subprocess.run(args,cwd=cwd,capture_output=True,check=True).stdout
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def safe(name):
    path=PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts and '\\' not in name
    assert not any(part in {'.git','.runtime','.cache','node_modules','artifacts'} for part in path.parts)
    assert path.name=='.env.example' or not (path.name=='.env' or path.name.startswith('.env.'))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',default='expertauth-partial-checkpoint')
    args=parser.parse_args()
    assert args.name.replace('-','').replace('_','').isalnum()
    assert not run(['git','status','--porcelain']).strip(), 'Commit current intended work first'
    commit=run(['git','rev-parse','HEAD']).decode().strip()
    target=ROOT/'artifacts'
    target.mkdir(exist_ok=True)
    destination=target/f'{args.name}-{commit[:12]}.zip'
    assert not destination.exists(), 'Preserve existing artifacts; use a new snapshot name'
    files={}
    with tarfile.open(fileobj=io.BytesIO(run(['git','archive','--format=tar',commit]))) as archive:
        for member in archive:
            if member.isdir(): continue
            assert member.isfile(), 'Symlink/special-file archives are not permitted'
            safe(member.name)
            assert member.name not in files
            files[member.name]=archive.extractfile(member).read()
    # Known synthetic local secrets still must not enter a resumable source artifact.
    secrets=[]
    for path in (ROOT/'.runtime').rglob('*.env'):
        for line in path.read_text().splitlines():
            if '=' in line:
                key,value=line.split('=',1)
                if any(word in key for word in ('PASSWORD','SECRET','API_KEY')) and len(value)>=16:
                    secrets.append(value.encode())
    leaks=[name for name,body in files.items() if any(value in body for value in secrets)]
    assert not leaks, f'Local secrets found in committed files: {leaks}'
    with tempfile.TemporaryDirectory(prefix='expertauth-bundle-') as temporary:
        bundle=Path(temporary)/'repository.bundle'
        run(['git','bundle','create',str(bundle),'--all'])
        run(['git','bundle','verify',str(bundle)])
        files['SOURCE_REPOSITORY.bundle']=bundle.read_bytes()
    manifest={'kind':'PARTIAL_SOURCE_CHECKPOINT','commit':commit,'complete':False,'production_approved':False,
              'files':[{'path':name,'bytes':len(body),'sha256':sha(body)} for name,body in sorted(files.items())],
              'acceptance':'All265 requirements,205 APIs and original profiles remain binding. Read PROJECT_STATE.md and BLOCKERS.md.',
              'bundle_restore':'git clone SOURCE_REPOSITORY.bundle expert-auth-resume'}
    manifest_bytes=(json.dumps(manifest,indent=2)+'\n').encode()
    with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,body in sorted({**files,'CHECKPOINT_MANIFEST.json':manifest_bytes}.items()):
            item=zipfile.ZipInfo('expert-auth/'+name,date_time=(1980,1,1,0,0,0))
            item.external_attr=0o100644<<16
            item.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(item,body)
    checks=[]
    with tempfile.TemporaryDirectory(prefix='expertauth-zip-verify-') as temporary:
        extracted=Path(temporary)
        with zipfile.ZipFile(destination) as archive:
            assert archive.testzip() is None
            names=archive.namelist()
            assert len(names)==len(set(names))==len(files)+1
            for name in names:
                safe(name)
                body=archive.read(name)
                expected=manifest_bytes if name=='expert-auth/CHECKPOINT_MANIFEST.json' else files[name.removeprefix('expert-auth/')]
                assert sha(body)==sha(expected)
                path=extracted/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(body)
        repo=extracted/'expert-auth'
        for argv,expected in [([sys.executable,'tools/ledger.py','check'],0),([sys.executable,'tools/capture_contracts.py','--validate'],0),([sys.executable,'tools/validate_release.py'],1)]:
            result=subprocess.run(argv,cwd=repo,capture_output=True,text=True)
            assert result.returncode==expected, f'Extracted snapshot check mismatch: {argv}'
            checks.append({'argv':argv,'expected_exit':expected,'actual_exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        restored=extracted/'restored-repo'
        run(['git','clone',str(repo/'SOURCE_REPOSITORY.bundle'),str(restored)],cwd=extracted)
        assert run(['git','rev-parse','HEAD'],cwd=restored).decode().strip()==commit
    checksum=sha(destination.read_bytes())
    destination.with_suffix('.zip.sha256').write_text(f'{checksum}  {destination.name}\n')
    destination.with_suffix('.manifest.json').write_bytes(manifest_bytes)
    destination.with_suffix('.validation.json').write_text(json.dumps({'kind':'snapshot-integrity-validation','zip':destination.name,'sha256':checksum,'files_verified':len(files)+1,'bundle_clone_head':commit,'checks':checks,'complete':False,'warning':'ZIP/source integrity does not pass authentication acceptance.'},indent=2)+'\n')
    print(json.dumps({'zip':str(destination),'sha256':checksum,'files':len(files)+1,'snapshot_validated':True,'authentication_complete':False}))

if __name__=='__main__':
    main()
