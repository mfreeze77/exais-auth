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

def committed_files(root, commit):
    """Read exact committed blobs, independent of nested export-ignore/export-subst.

    Git archive intentionally applies upstream release-export policy. A resumable
    ExpertAuth checkpoint must instead contain every permitted committed file.
    Reject symlinks/submodules; verify each object's framing and Git content hash.
    """
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit):
        raise ValueError('Exact commit identity required')
    entries=[]
    for raw in run(['git','ls-tree','-rz','--full-tree',commit],cwd=root).split(b'\0'):
        if not raw:continue
        metadata,name=raw.split(b'\t',1);mode,kind,oid=metadata.decode('ascii').split()
        name=name.decode('utf-8');safe(name)
        if mode not in {'100644','100755'} or kind!='blob' or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',oid):
            raise ValueError('Only regular committed source files are permitted')
        entries.append((name,oid))
    if not entries or len({name for name,oid in entries})!=len(entries):
        raise ValueError('Missing or duplicate committed files')
    objects=list(dict.fromkeys(oid for name,oid in entries))
    result=subprocess.run(['git','cat-file','--batch'],input=('\n'.join(objects)+'\n').encode('ascii'),
                          cwd=root,capture_output=True,check=True)
    stream=io.BytesIO(result.stdout);bodies={}
    for oid in objects:
        header=stream.readline().decode('ascii').rstrip('\n').split()
        if len(header)!=3 or header[:2]!=[oid,'blob'] or not header[2].isdigit():
            raise ValueError('Git blob response framing differs')
        size=int(header[2]);body=stream.read(size)
        if len(body)!=size or stream.read(1)!=b'\n':raise ValueError('Truncated Git blob')
        content=b'blob '+str(size).encode('ascii')+b'\0'+body
        actual=(hashlib.sha1(content) if len(oid)==40 else hashlib.sha256(content)).hexdigest()
        if actual!=oid:raise ValueError('Committed Git object hash differs')
        bodies[oid]=body
    if stream.read():raise ValueError('Unexpected extra Git blob response')
    return {name:bodies[oid] for name,oid in entries}

def upgrade_fixture_secrets(root):
    """Protect the exact private rollback journal, including interrupted saves."""
    values=set()
    runtime=root/'.runtime'
    parent=runtime/'atomic-core-replacement'
    def regular(entry):
        assert not entry.is_symlink() and not getattr(entry.lstat(),'st_file_attributes',0)&0x400, 'Upgrade fixture path is a link or reparse point'
    if not parent.exists() and not parent.is_symlink():
        return values
    regular(runtime); regular(parent)
    assert parent.is_dir(), 'Upgrade fixture parent is not a directory'
    for run in parent.iterdir():
        regular(run)
        assert run.is_dir() and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',run.name), 'Invalid upgrade fixture run'
        directory=run/'fixture'
        if not directory.exists() and not directory.is_symlink():
            continue  # A controller can fail before creating its journal directory.
        regular(directory)
        assert directory.is_dir(), 'Upgrade fixture directory differs'
        for name in ('fixture.json','fixture.tmp'):
            path=directory/name
            if not path.exists() and not path.is_symlink():
                continue
            regular(path)
            assert path.is_file() and 0 < path.stat().st_size <= 262144, 'Upgrade fixture size or file type invalid'
            assert path.resolve().parent==directory.resolve(), 'Upgrade fixture escaped its directory'
            raw=path.read_bytes()
            assert 0 < len(raw) <= 262144, 'Upgrade fixture changed size'
            state=json.loads(raw)
            assert isinstance(state,dict), 'Upgrade fixture must be an object'
            def credential(value):
                assert isinstance(value,str) and 0 < len(value.encode('utf-8')) <= 65536, 'Upgrade credential invalid'
                values.add(value.encode('utf-8'))
            credential(state['password'])
            for key in ('session','atomic_session'):
                if key not in state:
                    continue  # Seed is durably saved before any session exists.
                session=state[key]
                assert isinstance(session,dict), 'Upgrade session invalid'
                for token in ('accessToken','refreshToken'):
                    assert isinstance(session.get(token),dict), 'Upgrade session token missing'
                    credential(session[token]['token'])
    return values


def local_secrets(root):
    """Scan credential bytes, resolving only the lab's explicit SMTP mounts.

    A *_FILE value is not generally exempt from scanning. This one known mount
    has a bounded, local source contract; unknown references retain the original
    conservative direct-value scan. No path supplied by an env value is opened.
    """
    secrets=set()
    runtime=root/'.runtime'
    smtp_envs={'good.env','expiry.env','wrong-auth.env','untrusted.env','outage.env','unsupported.env','missing-writer.env'}
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
    secrets.update(upgrade_fixture_secrets(root))
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
    files=committed_files(ROOT,commit)
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
