"""Compile and unit-test the Node component from a generated ZIP's fresh extraction.

Uses one existing owned Node image for its qualified dependency tree, one bounded
offline --rm container and tmpfs build output. This is representative component
build evidence, not a fresh-host dependency/bootstrap or authentication test.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
import zipfile
from node_runtime_identity import ROOT, require_owned_node
from run_sdk_session_faults import inspect, inventory

def need(ok,message):
    if not ok: raise ValueError(message)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip',required=True)
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    archive_path=(ROOT/args.zip).resolve()
    need(archive_path.parent==(ROOT/'artifacts').resolve() and re.fullmatch('expertauth-partial-checkpoint-[0-9a-f]{12}\\.zip',archive_path.name),'Generated ZIP inside artifact directory required')
    need(archive_path.is_file() and not archive_path.is_symlink() and not getattr(archive_path.lstat(),'st_file_attributes',0)&0x400,'ZIP must be a regular file')
    need(re.fullmatch('sha256:[0-9a-f]{64}',args.image),'Immutable image ID required')
    image=inspect('image',args.image); require_owned_node(image)
    need(image['Id']==args.image and not image['Config'].get('Volumes'),'Image identity/volumes differ')
    output=archive_path.with_suffix('.node-extraction.json')
    need(not output.exists(),'Preserve prior extraction evidence')
    run_id=uuid.uuid4().hex
    private=(ROOT/'.runtime/extracted-node'/run_id).resolve()
    need(private.parent==(ROOT/'.runtime/extracted-node').resolve() and not private.exists(),'Fresh bounded extraction required')
    private.mkdir(parents=True)
    extracted=private/'source'; extracted.mkdir()
    cidfile=private/'container.cid'; name='expertauth-extracted-node-'+run_id[:12]
    labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'extracted-node','org.expertauth.run':run_id}
    report={'kind':'fresh-extracted-node-component-build','started':datetime.now(timezone.utc).isoformat(),'passed':False,
            'complete':False,'authentication_tests':False,'independent_review':False,'image':args.image,
            'zip':archive_path.name,'zip_sha256':sha(archive_path.read_bytes()),'tool_sha256':sha(Path(__file__).read_bytes()),
            'images_built':0,'image_downloads':0,'new_volumes':0,'new_networks':0,'published_ports':[],
            'commands':[],'errors':[],'extracted_members':[]}
    before=inventory(); report['resources_before']=before
    def persist(): output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    def call(argv,required=True,timeout=30):
        record={'argv':argv,'exit_code':None,'timed_out':False}
        try:
            result=subprocess.run(argv,capture_output=True,timeout=timeout,cwd=ROOT)
            record.update(exit_code=result.returncode,stdout=result.stdout.decode('utf-8',errors='replace'),stderr=result.stderr.decode('utf-8',errors='replace'))
        except subprocess.TimeoutExpired:
            record['timed_out']=True; raise
        finally: report['commands'].append(record); persist()
        need(not required or result.returncode==0,'Command failed: '+str(len(report['commands'])))
        return result
    try:
        sidecar=json.loads(archive_path.with_suffix('.validation.json').read_text())
        need(sidecar['sha256']==report['zip_sha256'],'Validated ZIP bytes changed')
        prefix='expert-auth/examples/node-react/'
        wanted={'package.json','package-lock.json','server.js','email-delivery.js','client.jsx','build.mjs','public/index.html','test/email-delivery.test.js'}
        with zipfile.ZipFile(archive_path) as archive:
            need(archive.testzip() is None,'ZIP CRC mismatch')
            manifest=json.loads(archive.read('expert-auth/CHECKPOINT_MANIFEST.json'))
            need(manifest['kind']=='PARTIAL_SOURCE_CHECKPOINT' and manifest['commit']==sidecar['bundle_clone_head'],'Source identity mismatch')
            entries={row['path']:row for row in manifest['files']}
            for member in sorted(wanted):
                key='examples/node-react/'+member; expected=entries[key]; body=archive.read(prefix+member)
                need(len(body)==expected['bytes'] and sha(body)==expected['sha256'],'Extracted member differs from manifest')
                target=extracted/member; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(body)
                report['extracted_members'].append({'path':key,'sha256':sha(body),'bytes':len(body)})
        report['source_commit']=manifest['commit']
        # No application source/dependency is downloaded. Symlinks exist only in
        # this container's tmpfs, never in the host extraction or archive.
        script="""set -eu
mkdir /tmp/app
cp -R /source/. /tmp/app/
ln -s /app/node_modules /tmp/app/node_modules
cd /tmp/app
node --check server.js
node --test --test-reporter=tap test/email-delivery.test.js
node build.mjs
node --input-type=module -e 'import fs from "node:fs"; import crypto from "node:crypto"; const hash=p=>crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex"); const files=["package.json","package-lock.json","server.js","email-delivery.js","client.jsx","build.mjs","public/index.html","public/app.js"]; const rows=files.map(path=>({path,extracted:hash(path),installed:hash("/app/"+path)})); if(rows.some(r=>r.extracted!==r.installed)) throw new Error("EXTRACTED_INSTALLED_BYTES_DIFFER"); console.log("EXTRACTED_NODE_FILES="+JSON.stringify(rows));'
"""
        argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(cidfile),'--network=none',
              '--read-only','--user=0','--memory=512m','--cpus=2','--pids-limit=128','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,size=128m','--log-driver=local',
              '--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
              '--mount',f'type=bind,source={extracted},target=/source,readonly']
        for k,v in labels.items(): argv+=['--label',k+'='+v]
        response=call(argv+['--entrypoint','sh',args.image,'-c',script],timeout=150)
        need(b'# pass 55' in response.stdout and b'# fail 0' in response.stdout and b'# skipped 0' in response.stdout,'Extracted unit test coverage differs')
        lines=[line for line in response.stdout.decode().splitlines() if line.startswith('EXTRACTED_NODE_FILES=')]
        need(len(lines)==1,'Extracted compiler report absent')
        report['files_compared']=json.loads(lines[0].split('=',1)[1]); need(len(report['files_compared'])==8,'App membership differs')
        report['delivery_unit_tests_passed']=55; report['frontend_recompiled']=True
        report['work_passed']=True
    except Exception as error: report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            if cidfile.exists():
                cid=cidfile.read_text().strip(); need(re.fullmatch('[0-9a-f]{64}',cid),'Malformed container ID')
                report['container_id']=cid
                state=call(['docker','inspect','--format','{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}',cid],required=False)
                if state.returncode==0:
                    state=json.loads(state.stdout)
                    need(state['id']==cid and state['name']=='/'+name and state['image']==args.image and
                         all((state['labels'] or {}).get(k)==v for k,v in labels.items()),'Container ownership differs')
                    call(['docker','rm','-f',cid])
            need(not call(['docker','ps','-aq','--filter','name=^/'+name+'$']).stdout.strip(),'Extraction container remains')
            report['container_retired']=True
            paths=list(private.rglob('*'))
            need(all(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400 and p.resolve().is_relative_to(private) for p in [private,*paths]),'Unsafe extraction cleanup')
            for p in paths:
                if p.is_file(): p.unlink()
            for p in sorted((p for p in paths if p.is_dir()),key=lambda p:len(p.parts),reverse=True): p.rmdir()
            private.rmdir(); report['extraction_removed']=True
            report['resources_after']=inventory(); need(before==report['resources_after'],'Resource inventory changed')
            report['resources_unchanged']=True
        except Exception as error: report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
        report['passed']=not report['errors'] and report.get('work_passed') is True
        report['finished']=datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'passed':report['passed'],'report':output.name,'errors':report['errors'],'container_retired':report.get('container_retired')}))
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
