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
import re
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
    assert not any(part in {'.git','.runtime','.cache','.docker','node_modules','artifacts'} for part in path.parts)
    assert path.name=='.env.example' or not (path.name=='.env' or path.name.startswith('.env.'))

def local_secrets(root):
    """Scan credential bytes, resolving only the lab's explicit SMTP mounts.

    A *_FILE value is not generally exempt from scanning. This one known mount
    has a bounded, local source contract; unknown references retain the original
    conservative direct-value scan. No path supplied by an env value is opened.
    """
    secrets=set()
    runtime=root/'.runtime'
    smtp_envs={'good.env','expiry.env','wrong-auth.env','untrusted.env','outage.env','unsupported.env'}
    for path in runtime.rglob('*.env'):
        for line in path.read_text().splitlines():
            if '=' not in line:
                continue
            key,value=line.split('=',1)
            relative=path.relative_to(runtime)
            known_mount=(key=='EXPERTAUTH_SMTP_PASSWORD_FILE' and value=='/run/mailpit/smtp-password'
                         and len(relative.parts)==4 and relative.parts[0]=='password-reset'
                         and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',relative.parts[1]) is not None
                         and relative.parts[2]=='secrets' and path.name in smtp_envs)
            if known_mount:
                for entry in (runtime,runtime/'password-reset',path.parent.parent,path.parent,path):
                    assert not entry.is_symlink() and not getattr(entry.lstat(),'st_file_attributes',0)&0x400, 'SMTP path is a link or reparse point'
                assert path.resolve().is_relative_to((runtime/'password-reset').resolve()), 'SMTP env outside private lab'
                # The wrong-auth case mounts the other file at the same container
                # path. Scan both, so the negative-test credential is protected too.
                for name in ('smtp-password','wrong-password'):
                    source=path.parent/name
                    assert not source.is_symlink() and source.is_file(), 'SMTP credential file missing or unsafe'
                    assert not getattr(source.lstat(),'st_file_attributes',0)&0x400, 'SMTP credential is a reparse point'
                    assert source.resolve().parent==path.parent.resolve(), 'SMTP credential escaped its lab directory'
                    assert 0 < source.stat().st_size <= 4098, 'SMTP credential file size invalid'
                    raw=source.read_bytes()
                    assert 0 < len(raw) <= 4098, 'SMTP credential changed size'
                    credential=raw.decode('utf-8')
                    if credential.endswith('\n'):
                        credential=credential[:-1]
                        if credential.endswith('\r'):
                            credential=credential[:-1]
                    assert credential and len(credential.encode())<=4096 and not any(ord(c)<32 or ord(c)==127 for c in credential), 'SMTP credential content invalid'
                    secrets.add(credential.encode())
                continue
            if any(word in key for word in ('PASSWORD','SECRET','API_KEY')) and len(value)>=16:
                secrets.add(value.encode())
    return secrets

def secret_leaks(files, secrets):
    return [name for name,body in files.items() if any(value in body for value in secrets)]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',default='expertauth-partial-checkpoint')
    args=parser.parse_args()
    assert args.name.replace('-','').replace('_','').isalnum()
    assert not run(['git','status','--porcelain']).strip(), 'Commit current intended work first'
    commit=run(['git','rev-parse','HEAD']).decode().strip()
    target=ROOT/'artifacts'
    target.mkdir(exist_ok=True)
    assert len(list(target.glob('*.zip'))) < 3, 'Three-ZIP cap reached; verify and retire only an authorized old generated checkpoint before packaging'
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
    leaks=secret_leaks(files,local_secrets(ROOT))
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
