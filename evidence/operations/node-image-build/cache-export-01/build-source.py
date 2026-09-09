"""Build and qualify the Node candidate offline, then replace its one current tag.

Uses an explicitly retained package cache and the existing private identity lab.
No production, new networks/volumes, public ports or automatic dependency fetch.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

from build_oss_runtime import buildx_command
from run_sdk_session_faults import ROOT, inspect, inventory
from run_recovery_drill import projection, SOURCE_CORE, SOURCE_PG

TAG='expertauth-node-react:0.0.5'
BASE='node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436'
PROJECT='expert-auth'
INPUTS=['tools/build_node_runtime.py','tools/build_oss_runtime.py','tools/export_node_packages.mjs',
        'tools/verify_node_runtime.mjs','tools/run_password_reset_lab.py','tools/run_sdk_session_faults.py',
        'tools/run_recovery_drill.py','tests/operations/password_reset_cleanup.py',
        'tests/operations/password_reset_probe.mjs','tests/operations/password_reset_tls.py',
        'tests/browser/password-reset.mjs','tests/browser/package-lock.json',
        'examples/node-react/Dockerfile','examples/node-react/.dockerignore',
        'examples/node-react/package.json','examples/node-react/package-lock.json',
        'examples/node-react/server.js','examples/node-react/email-delivery.js',
        'examples/node-react/client.jsx','examples/node-react/build.mjs',
        'examples/node-react/public/index.html','examples/node-react/public/app.js',
        'examples/node-react/test/email-delivery.test.js']

def need(value,message):
    if not value:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def resources():
    return {key:value for key,value in inventory().items() if key!='images'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',required=True)
    parser.add_argument('--export-cache-only',action='store_true')
    args=parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,64}',args.name),'Invalid run name')
    output=ROOT/'evidence/operations/node-image-build'/args.name
    private=(ROOT/'.runtime/node-image-build'/args.name).resolve()
    cache=(ROOT/'.cache/node-packages').resolve()
    need(not output.exists() and not private.exists(),'Preserve existing build evidence')
    need(private.parent==(ROOT/'.runtime/node-image-build').resolve() and cache.parent==(ROOT/'.cache').resolve()
         and cache.is_relative_to(ROOT.resolve()),'Workspace cache boundary differs')
    selected_inputs=INPUTS if not args.export_cache_only else [
        'tools/build_node_runtime.py','tools/build_oss_runtime.py','tools/export_node_packages.mjs',
        'tools/run_sdk_session_faults.py','tools/run_recovery_drill.py',
        'examples/node-react/Dockerfile','examples/node-react/package-lock.json']
    inputs={p:sha(ROOT/p) for p in selected_inputs}
    output.mkdir(parents=True); private.mkdir(parents=True); cache.mkdir(parents=True,exist_ok=True)
    run_id=uuid.uuid4().hex
    report={'schema':'expertauth-node-offline-image-build-v1','started':datetime.now(timezone.utc).isoformat(),
            'run_id':run_id,'input_sha256':inputs,'passed':False,'foundation_passed':False,
            'full_distribution_approved':False,'image_promoted':False,'build_network':'none',
            'image_downloads':0,'new_networks':0,'new_volumes':0,'published_ports':[],
            'commands':[],'errors':[],'temporary_containers_retired':[]}
    old=candidate=None; promoted=False; promotion_attempted=False

    def persist():
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')

    def call(argv,timeout=45,required=True):
        result=None; error=None
        try:
            result=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=timeout)
            raw=result.stdout+result.stderr
        except subprocess.TimeoutExpired as caught:
            raw=(caught.stdout or b'')+(caught.stderr or b''); error=caught
        path=output/f'command-{len(report["commands"])+1:03d}.log'
        path.write_bytes(raw)
        report['commands'].append({'argv':argv,'exit_code':result.returncode if result else None,
                                   'timed_out':error is not None,'log':path.name,'sha256':sha(path)})
        persist()
        if error:
            raise error
        need(not required or result.returncode==0,'Command failed: '+path.name)
        return result

    def image(identifier):
        return json.loads(call(['docker','image','inspect',identifier]).stdout)[0]

    def helper(role,image_id,mounts,arguments,timeout=120):
        name='expertauth-node-'+role+'-'+run_id[:10]
        cidfile=private/(role+'.cid')
        labels={'org.expertauth.project':PROJECT,'org.expertauth.purpose':'node-image-'+role,'org.expertauth.build-run':run_id}
        argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(cidfile),'--network','none',
              '--read-only','--user','0','--memory=512m','--cpus=2','--pids-limit=128','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,noexec,size=64m']
        for key,value in labels.items(): argv+=['--label',key+'='+value]
        for source,target,writable in mounts:
            argv+=['--mount',f'type=bind,source={source},target={target}'+('' if writable else ',readonly')]
        argv+=['--entrypoint','node',image_id,*arguments]
        try:
            return call(argv,timeout=timeout)
        finally:
            cid=cidfile.read_text().strip() if cidfile.exists() else None
            if cid:
                need(re.fullmatch('[0-9a-f]{64}',cid),'Malformed helper CID')
                found=call(['docker','container','inspect','--format',
                    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}',cid],required=False)
                if found.returncode==0:
                    state=json.loads(found.stdout)
                    need(state['id']==cid and state['name']=='/'+name and state['image']==image_id and
                         all((state['labels'] or {}).get(k)==v for k,v in labels.items()),'Helper ownership changed')
                    call(['docker','container','rm','-f',cid],timeout=25)
            need(not call(['docker','ps','-aq','--filter','name=^/'+name+'$']).stdout.strip(),'Helper still exists')
            report['temporary_containers_retired'].append({'role':role,'name':name,'id':cid})
            cidfile.unlink(missing_ok=True)

    def cache_snapshot():
        files={}
        for path in sorted(cache.rglob('*')):
            need(not path.is_symlink() and path.resolve().is_relative_to(cache),'Unsafe package cache path')
            if path.is_file(): files[path.relative_to(cache).as_posix()]={'bytes':path.stat().st_size,'sha256':sha(path)}
        need(sum(row['bytes'] for row in files.values())<=128*1024*1024,'Package cache exceeds128MiB')
        return files

    def audit(role,image_id):
        destination=output/role; destination.mkdir()
        helper(role,image_id,[(ROOT/'tools/verify_node_runtime.mjs','/verify.mjs',False),
               (cache,'/cache',False),(destination,'/out',True)],
               ['/verify.mjs','--app','/app','--cache-report','/cache/cache-report.json','--cache','/cache','--output','/out/runtime-report.json'])
        return read(destination/'runtime-report.json')

    def owned_unused_image(identifier,built_here):
        state=image(identifier)
        need(state['Id']==identifier and not state.get('RepoTags') and not state.get('RepoDigests'),'Image still referenced')
        labels=state['Config'].get('Labels') or {}
        need(labels.get('org.expertauth.project')==PROJECT,'Image is not project-owned')
        if built_here:
            need(labels.get('org.expertauth.build-run')==run_id and labels.get('org.expertauth.purpose')=='node-foundation'
                 and identifier not in report['images_before'],'Candidate does not belong to this build')
        else:
            need(identifier==old['Id'] and labels==old['Config'].get('Labels'),'Old image ownership changed')
        need(not call(['docker','ps','-aq','--filter','ancestor='+identifier]).stdout.strip(),'Image still has consumers')
        call(['docker','image','rm','--no-prune',identifier])

    try:
        old=image(TAG)
        need(old['Config'].get('Labels',{}).get('org.expertauth.project')==PROJECT,'Current image ownership differs')
        report['previous_image_id']=old['Id']
        report['resources_before']=resources()
        report['source_before']={name:projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)}
        need(all(row['running'] and not row['ports'] for row in report['source_before'].values()),'Private source services must be running')
        report['images_before']=sorted(set(call(['docker','image','ls','-aq','--no-trunc']).stdout.decode().splitlines()))
        need((ROOT/'examples/node-react/Dockerfile').read_text().splitlines()[0]=='FROM '+BASE,'Pinned Dockerfile base differs')
        image(BASE)
        if not (cache/'cache-report.json').exists():
            helper('cache-export',old['Id'],[(ROOT/'tools/export_node_packages.mjs','/export.mjs',False),(cache,'/out',True)],
                   ['/export.mjs','--lock','/app/package-lock.json','--cache','/root/.npm/_cacache/content-v2','--out','/out'])
        report['cache_before']=cache_snapshot()
        report['cache_report_sha256']=sha(cache/'cache-report.json')
        cache_report=read(cache/'cache-report.json')
        need(cache_report.get('ok') is True and cache_report['lock_sha256']==inputs['examples/node-react/package-lock.json'],'Cache export is incomplete or lock differs')
        need(cache_report['applicable_package_count']+cache_report['excluded_package_count']==len(read(ROOT/'examples/node-react/package-lock.json')['packages'])-1,'Locked package accounting differs')
        if args.export_cache_only:
            report['cache_export_only']=True
            need(resources()==report['resources_before'] and inputs=={p:sha(ROOT/p) for p in selected_inputs},'Cache export changed inputs or resources')
            report['passed']=True
        else:
            old_audit=audit('previous-runtime',old['Id'])
            need(old_audit.get('ok') is True,'Previous dependency distribution is not bound to the cache')
            buildx=buildx_command()
            report['buildx_command']=buildx
            if len(buildx)==1: report['buildx_sha256']=sha(Path(buildx[0]))
            builder=call(buildx+['inspect','default']).stdout.decode()
            need(re.search(r'^Driver:\s+docker\s*$',builder,re.M) and re.search(r'^Status:\s+running\s*$',builder,re.M),'Existing Docker-driver builder required')
            iid=private/'image.id'
            call(buildx+['build','--builder','default','--pull=false','--network=none','--resource','memory=512m',
                         '--resource','cpu-quota=200000','--progress=plain','--provenance=false','--iidfile',str(iid),
                         '--metadata-file',str(output/'build-metadata.json'),'--build-context','node_packages='+str(cache),
                         '--label','org.expertauth.project='+PROJECT,'--label','org.expertauth.purpose=node-foundation',
                         '--label','org.expertauth.build-run='+run_id,str(ROOT/'examples/node-react')],timeout=600)
            metadata=read(output/'build-metadata.json')
            need(metadata['containerimage.config.digest']==iid.read_text().strip(),'Build configuration digest differs')
            built=image(metadata['containerimage.digest']); candidate=built['Id']
            report['candidate_image_id']=candidate
            need(candidate not in report['images_before'] and built['Config'].get('Labels',{}).get('org.expertauth.build-run')==run_id,'Candidate identity differs')
            need(built['Config']['User']=='node' and not built['Config'].get('Volumes'),'Candidate runtime user or volumes differ')
            candidate_audit=audit('candidate-runtime',candidate)
            need(candidate_audit.get('ok') is True,'Candidate dependency distribution is incomplete')
            report['candidate_audit_path']=(output/'candidate-runtime/runtime-report.json').relative_to(ROOT).as_posix()
            # Exact manifest fields and source bindings are checked below once the
            # maintained archive verifier emits its complete distribution report.
            unit=helper('unit-tests',candidate,[(ROOT/'examples/node-react/test/email-delivery.test.js','/app/test/email-delivery.test.js',False)],
                        ['--test','--test-reporter=tap','/app/test/email-delivery.test.js'])
            need(b'# pass 55' in unit.stdout and b'# fail 0' in unit.stdout and b'# skipped 0' in unit.stdout,'Installed delivery unit tests incomplete')
            reset_name='installed-'+args.name
            child=subprocess.run([sys.executable,'-B','tools/run_password_reset_lab.py','--name',reset_name,'--installed-image',candidate],cwd=ROOT,capture_output=True)
            (output/'reset-lab.log').write_bytes(child.stdout+child.stderr)
            reset=read(ROOT/'evidence/operations/password-reset'/reset_name/'report.json')
            need(child.returncode==0 and reset['passed'] and reset['installed_image_tested'] and reset['images']['node']==candidate,'Installed reset lab failed')
            report['reset_report']={'path':'evidence/operations/password-reset/'+reset_name+'/report.json',
                                    'sha256':sha(ROOT/'evidence/operations/password-reset'/reset_name/'report.json')}
            need(report['cache_before']==cache_snapshot(),'Package cache changed during build')
            need(inputs=={p:sha(ROOT/p) for p in INPUTS},'Build inputs changed')
            need(resources()==report['resources_before'],'Task resources changed during qualification')
            need(report['source_before']=={name:projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)},'Source services changed')
            need(image(TAG)['Id']==old['Id'],'Current tag changed before promotion')
            promotion_attempted=True
            call(['docker','image','tag',candidate,TAG])
            need(image(TAG)['Id']==candidate,'Tag promotion failed')
            promoted=True; report['image_promoted']=True
            owned_unused_image(old['Id'],False)
            report['retired_previous_image']=old['Id']
            report['passed']=True
    except Exception as error:
        report['errors'].append(type(error).__name__+': '+str(error))
    finally:
        try:
            if not promoted:
                if promotion_attempted and old and candidate and image(TAG)['Id']==candidate:
                    call(['docker','image','tag',old['Id'],TAG])
                found=call(['docker','image','ls','-aq','--no-trunc','--filter','label=org.expertauth.build-run='+run_id]).stdout.decode().splitlines()
                for identifier in sorted(set(found)):
                    owned_unused_image(identifier,True)
                if old: need(image(TAG)['Id']==old['Id'],'Failed build changed current tag')
            (private/'image.id').unlink(missing_ok=True)
            if not any(private.iterdir()): private.rmdir()
            report['private_scratch_removed']=not private.exists()
            need(report['private_scratch_removed'],'Private build scratch still contains unresolved resources')
        except Exception as error:
            report['passed']=False; report['errors'].append('Cleanup: '+type(error).__name__+': '+str(error))
        report['finished']=datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'report':output.relative_to(ROOT).as_posix(),'passed':report['passed'],'image_promoted':report['image_promoted'],'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
