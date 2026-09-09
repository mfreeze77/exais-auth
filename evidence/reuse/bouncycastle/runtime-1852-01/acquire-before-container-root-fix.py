"""Acquire one bounded current BC runtime/source set with Maven SHA-256 evidence.

Host orchestration uses one cached Python container; no images are built/pulled.
Versions are explicit, not dynamically selected. This is not distribution approval.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[1]
IMAGE='python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'
VERSIONS={'bcprov-jdk18on':'1.85.2','bcutil-jdk18on':'1.85','bcpkix-jdk18on':'1.85'}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def inside():
    cache=Path('/cache');out=Path('/out');rows=[];http=[]
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ValueError('Unexpected Maven redirect')
    opener=urllib.request.build_opener(NoRedirect())
    def get(url,limit):
        need(url.startswith('https://repo.maven.apache.org/maven2/org/bouncycastle/'),'Unexpected origin')
        with opener.open(url,timeout=45) as response:
            need(response.url==url and response.status==200,'Unexpected Maven response')
            raw=response.read(limit+1);need(0<len(raw)<=limit,'Response exceeds bound')
            http.append({'url':url,'bytes':len(raw),'sha256':sha(raw),'status':response.status})
            return raw
    report={'kind':'bouncycastle-bounded-acquisition','passed':False,'complete':False,'started':datetime.now(timezone.utc).isoformat(),'http':http,'artifacts':rows,'errors':[]}
    try:
        need(not list(cache.iterdir()),'Preserve existing dependency cache')
        for artifact,version in VERSIONS.items():
            prefix=artifact+'-'+version;base='https://repo.maven.apache.org/maven2/org/bouncycastle/'+artifact+'/'+version+'/'+prefix
            row={'coordinate':'org.bouncycastle:'+artifact+':'+version,'artifact':artifact,'version':version};rows.append(row)
            for kind,suffix in [('binary','.jar'),('source','-sources.jar'),('pom','.pom')]:
                url=base+suffix;checksum=get(url+'.sha256',128).decode('ascii').strip()
                need(re.fullmatch('[0-9a-fA-F]{64}',checksum),'Malformed published SHA-256')
                raw=get(url,16*1024*1024 if kind!='pom' else 128*1024);need(sha(raw)==checksum.lower(),'Published SHA-256 mismatch')
                record={'url':url,'sha256':sha(raw),'bytes':len(raw),'filename':prefix+suffix,'checksum_url':url+'.sha256'}
                if kind!='pom':
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        names=archive.namelist();need(len(names)==len(set(names)) and archive.testzip() is None,'Invalid archive')
                        need(sum(i.file_size for i in archive.infolist())<=128*1024*1024,'Archive expands beyond bound')
                        need(not any(n.endswith(('.so','.dll','.dylib')) for n in names),'Unexpected native runtime')
                        record['members']=len(names);record['native_members']=0
                        if artifact=='bcprov-jdk18on' and kind=='source':
                            source='org/bouncycastle/crypto/generators/SCrypt.java';body=archive.read(source)
                            record['scrypt_source']={'path':source,'sha256':sha(body),'bytes':len(body)}
                target=(out if kind=='pom' else cache)/(prefix+suffix)
                with target.open('xb') as stream:stream.write(raw)
                row[kind]=record
        report['passed']=True
    except Exception as error:report['errors'].append(str(error))
    report['finished']=datetime.now(timezone.utc).isoformat()
    with (out/'acquisition.json').open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'passed':report['passed'],'artifacts':len(rows),'downloaded_bytes':sum(r['bytes'] for r in http),'errors':report['errors']}))
    return 0 if report['passed'] else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True);args=parser.parse_args()
    need(re.fullmatch('[a-z0-9-]{1,40}',args.name),'Invalid run name')
    out=ROOT/'evidence/reuse/bouncycastle'/args.name;cache=ROOT/'.cache/bouncycastle-runtime'
    need(not out.exists() and not cache.exists(),'Preserve prior acquisition/cache')
    for p in (ROOT,ROOT/'.cache'):
        need(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400,'Cache parent link/reparse point')
    from run_sdk_session_faults import inventory
    before=inventory();out.mkdir(parents=True);cache.mkdir()
    run_id=uuid.uuid4().hex;name='expertauth-bouncycastle-fetch-'+run_id[:10]
    labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'bouncycastle-acquisition','org.expertauth.run':run_id}
    image=json.loads(subprocess.check_output(['docker','image','inspect',IMAGE]))[0]
    need(not image['Config'].get('Volumes'),'Unexpected fetch image volumes')
    report={'kind':'bounded-bouncycastle-fetch-container','passed':False,'image':image['Id'],'started':datetime.now(timezone.utc).isoformat(),
        'images_built':0,'image_downloads':0,'new_volumes':0,'new_networks':0,'published_ports':[],'source_sha256':sha(Path(__file__).read_bytes()),'errors':[],'resources_before':before}
    argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(out/'container.cid'),'--read-only',
        '--memory=256m','--cpus=1','--pids-limit=64','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
        '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--mount',f'type=bind,source={Path(__file__).resolve()},target=/fetch.py,readonly',
        '--mount',f'type=bind,source={out},target=/out','--mount',f'type=bind,source={cache},target=/cache']
    for k,v in labels.items():argv+=['--label',k+'='+v]
    argv += ['--entrypoint','python',image['Id'],'-B','/fetch.py','--inside']
    try:
        with (out/'command.stdout').open('xb') as stdout,(out/'command.stderr').open('xb') as stderr:
            process=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=240)
        report['exit_code']=process.returncode;need(process.returncode==0,'Bounded acquisition failed')
        need(json.loads((out/'acquisition.json').read_text())['passed'],'Incomplete acquisition')
        report['acquisition_sha256']=sha((out/'acquisition.json').read_bytes())
    except Exception as error:report['errors'].append(str(error))
    finally:
        try:
            if (out/'container.cid').exists():
                cid=(out/'container.cid').read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid helper ID')
                state=subprocess.run(['docker','inspect',cid],capture_output=True)
                if state.returncode==0:
                    d=json.loads(state.stdout)[0];need(d['Id']==cid and d['Name']=='/'+name and d['Image']==image['Id'] and all((d['Config'].get('Labels') or {}).get(k)==v for k,v in labels.items()),'Fetch helper ownership differs')
                    subprocess.run(['docker','rm','-f',cid],check=True,capture_output=True)
                need(not subprocess.check_output(['docker','ps','-aq','--filter','name=^/'+name+'$']).strip(),'Fetch helper remains')
                report['container_id']=cid;report['container_retired']=True
            report['resources_after']=inventory();need(before==report['resources_after'],'Resource inventory differs')
        except Exception as error:report['errors'].append(str(error))
        report['passed']=not report['errors'] and report.get('exit_code')==0;report['finished']=datetime.now(timezone.utc).isoformat()
        (out/'container.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'report':out.relative_to(ROOT).as_posix(),'container_retired':report.get('container_retired'),'errors':report['errors']}))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(inside() if sys.argv[1:]==['--inside'] else main())
