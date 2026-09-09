"""Retire one explicitly pinned generated ZIP; verify and keep two newer ZIPs.

Only one regular file is removed. All sidecars, Git history and supplied
acceptance files are preserved. Requires exactly the three named ZIPs on disk.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[1]

def need(ok,message):
    if not ok: raise ValueError(message)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def regular(path,folder):
    need(path.is_file() and not path.is_symlink() and not getattr(path.lstat(),'st_file_attributes',0)&0x400 and
         path.resolve().parent==folder,'Expected regular file inside artifact directory')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',required=True)
    parser.add_argument('--retire',required=True,help='12-character commit prefix:64-character ZIP SHA-256')
    parser.add_argument('--keep',required=True,action='append',help='Exactly two newer prefix:SHA-256 pins')
    args=parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,64}',args.name) and len(args.keep)==2,'Invalid retention inputs')
    pins=[args.retire,*args.keep]
    need(all(re.fullmatch('[0-9a-f]{12}:[0-9a-f]{64}',p) for p in pins),'Invalid explicit pins')
    pins=[p.split(':') for p in pins]
    need(len({p[0] for p in pins})==3,'Pins must be distinct')
    folder=(ROOT/'artifacts').resolve()
    need(folder.parent==ROOT.resolve() and not (ROOT/'artifacts').is_symlink() and
         not getattr((ROOT/'artifacts').lstat(),'st_file_attributes',0)&0x400,'Artifact directory boundary differs')
    output=ROOT/'evidence/operations/hygiene'/('checkpoint-retention-'+args.name+'.json')
    need(not output.exists(),'Preserve previous retention report')
    report={'started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,'tool_sha256':sha(Path(__file__)),
            'pins':pins,'rows':[],'errors':[],'deletion_performed':False,'maximum_after_next_checkpoint':3}
    def persist(): output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    def ancestor(a,b):
        return subprocess.run(['git','merge-base','--is-ancestor',a,b],cwd=ROOT,capture_output=True,timeout=15).returncode==0
    persist()
    try:
        need({p.name for p in folder.glob('*.zip')}=={f'expertauth-partial-checkpoint-{p}.zip' for p,h in pins},'Unexpected ZIP set')
        for prefix,expected in pins:
            path=folder/f'expertauth-partial-checkpoint-{prefix}.zip'; regular(path,folder)
            need(sha(path)==expected,'ZIP SHA-256 differs')
            sidecars=[path.with_suffix(s) for s in ['.manifest.json','.validation.json','.zip.sha256']]
            for p in sidecars: regular(p,folder)
            manifest_bytes=sidecars[0].read_bytes(); manifest=json.loads(manifest_bytes)
            validation=json.loads(sidecars[1].read_text())
            need(manifest['kind']=='PARTIAL_SOURCE_CHECKPOINT' and manifest['complete'] is False and
                 re.fullmatch('[0-9a-f]{40}',manifest['commit']) and manifest['commit'].startswith(prefix),'Generated source checkpoint identity differs')
            need(validation['sha256']==expected and validation['bundle_clone_head']==manifest['commit'] and validation['complete'] is False and
                 sidecars[2].read_text().split()==[expected,path.name],'Validation/checksum identity differs')
            need(ancestor(manifest['commit'],'HEAD'),'Checkpoint is not an ancestor of this repository')
            with zipfile.ZipFile(path) as archive:
                need(archive.testzip() is None,'ZIP CRC failed')
                names=archive.namelist(); wanted={'expert-auth/'+r['path'] for r in manifest['files']}|{'expert-auth/CHECKPOINT_MANIFEST.json'}
                need(len(names)==len(set(names))==len(wanted) and set(names)==wanted,'ZIP member set differs')
                need(archive.read('expert-auth/CHECKPOINT_MANIFEST.json')==manifest_bytes,'Embedded manifest differs')
                for row in manifest['files']:
                    body=archive.read('expert-auth/'+row['path'])
                    need(len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'],'ZIP member bytes differ')
            report['rows'].append({'path':path.relative_to(ROOT).as_posix(),'sha256':expected,'bytes':path.stat().st_size,
                                  'commit':manifest['commit'],'every_member_and_crc_verified':True,'retired':False,
                                  'sidecar_sha256':{p.name:sha(p) for p in sidecars}})
        need(all(ancestor(report['rows'][0]['commit'],row['commit']) for row in report['rows'][1:]),'Retained ZIPs must contain newer descendant history')
        report['preflight_passed']=True; persist()
        target=ROOT/report['rows'][0]['path']; regular(target,folder)
        need(target.name==f'expertauth-partial-checkpoint-{pins[0][0]}.zip' and sha(target)==pins[0][1],'Final deletion pin differs')
        target.unlink(); report['deletion_performed']=report['rows'][0]['retired']=True; persist()
        for row in report['rows']:
            for name,h in row['sidecar_sha256'].items(): need(sha(folder/name)==h,'Sidecar changed')
            if not row['retired']: need(sha(ROOT/row['path'])==row['sha256'],'Retained recovery ZIP changed')
        need(not target.exists() and len(list(folder.glob('*.zip')))==2,'Final retention set differs')
        report['passed']=True
    except Exception as error: report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally: report['finished']=datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'passed':report['passed'],'deleted_zip':report['deletion_performed'],'retained_zips':len(list(folder.glob('*.zip'))),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
