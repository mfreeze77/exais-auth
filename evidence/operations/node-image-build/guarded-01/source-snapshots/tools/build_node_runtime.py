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
from node_runtime_identity import TAG, require_owned_node
from run_password_reset_lab import source_projection

BASE='node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436'
PROJECT='expert-auth'
INPUTS=['tools/build_node_runtime.py','tools/build_oss_runtime.py','tools/export_node_packages.mjs',
        'tools/node_runtime_identity.py','tests/reuse/node_package_boundaries.mjs',
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
    parser.add_argument('--session-build',help='Qualify the installed atomic Node profile against this exact Core/plugin build in a disposable database')
    parser.add_argument('--qualify-refresh-grace',action='store_true',help='Also require installed Node CDI5.6 adaptation and browser qualification before promotion')
    args=parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}',args.name),'Invalid run name; reserve10 characters for installed-image lab prefix')
    session_inputs=[]
    need(not args.qualify_refresh_grace or bool(args.session_build),'Refresh/grace qualification also requires the atomic password/session regression')
    if args.session_build:
        need(not args.export_cache_only and len(args.name)<=44 and re.fullmatch('[A-Za-z0-9_-]{1,54}',args.session_build),'Invalid atomic installed profile')
        path='evidence/operations/password-session-build/'+args.session_build+'/report.json'
        compiled=read(ROOT/path)
        need(compiled['passed'] and len(compiled['candidates'])==2 and all(sha(ROOT/p)==h for p,h in compiled['inputs'].items()) and
             all(sha(ROOT/r['path'])==r['sha256'] for r in compiled['candidates']),'Atomic Core source/binary prerequisites differ')
        session_inputs=['tools/run_atomic_reset_lab.py','tests/operations/AtomicResetProbe.java',
                        'tests/operations/PasswordSessionProbe.java','tests/operations/password_session_wire.mjs',path,*compiled['inputs']]
    if args.qualify_refresh_grace:
        from atomic_core_identity import current_core_image,require_atomic_core
        grace_core=current_core_image();require_atomic_core(inspect('image',grace_core))
        session_inputs+=['tools/atomic_core_identity.py','tools/run_refresh_grace_lab.py','tests/foundation/RefreshGraceProbe.java',
            'tests/foundation/sdk_refresh_grace.mjs','tests/foundation/session_policy_readiness.mjs','tests/browser/session-grace.mjs','contracts/session-policy-oss-cdi56-grace-v1.json']
    output=ROOT/'evidence/operations/node-image-build'/args.name
    private=(ROOT/'.runtime/node-image-build'/args.name).resolve()
    cache=(ROOT/'.cache/node-packages').resolve()
    need(not output.exists() and not private.exists(),'Preserve existing build evidence')
    need(private.parent==(ROOT/'.runtime/node-image-build').resolve() and cache.parent==(ROOT/'.cache').resolve()
         and cache.is_relative_to(ROOT.resolve()),'Workspace cache boundary differs')
    selected_inputs=list(dict.fromkeys(INPUTS+session_inputs)) if not args.export_cache_only else [
        'tools/build_node_runtime.py','tools/build_oss_runtime.py','tools/export_node_packages.mjs',
        'tools/node_runtime_identity.py',
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
    report['password_session_build']=args.session_build
    report['refresh_grace_qualification_required']=args.qualify_refresh_grace
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip()
    report['source_revision']=revision; report['source_bindings']={}
    for name,digest in inputs.items():
        committed=subprocess.run(['git','show',revision+':'+name],cwd=ROOT,capture_output=True)
        if committed.returncode==0 and hashlib.sha256(committed.stdout).hexdigest()==digest:
            report['source_bindings'][name]={'git_commit':revision,'sha256':digest}
        elif name=='examples/node-react/public/app.js':
            report['source_bindings'][name]={'sha256':digest,'kind':'generated bundle; producer source and installed bytes checked, binary excluded from source checkpoint'}
        else:
            target=output/'source-snapshots'/name
            target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes((ROOT/name).read_bytes())
            need(sha(target)==digest,'Source changed before evidence capture')
            report['source_bindings'][name]={'path':target.relative_to(ROOT).as_posix(),'sha256':digest}
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
              '--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,noexec,size=64m',
              '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false']
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
                    removed=call(['docker','container','rm','-f',cid],timeout=25,required=False)
                    if removed.returncode:
                        need(not call(['docker','ps','-aq','--no-trunc','--filter','id='+cid]).stdout.strip(),
                             'Helper removal failed and exact container remains')
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
               (ROOT/'tools/export_node_packages.mjs','/export_node_packages.mjs',False),
               (cache,'/cache',False),(destination,'/out',True)],
               ['/verify.mjs','--app','/app','--cache-report','/cache/cache-report.json','--cache','/cache','--output','/out/runtime-report.json'])
        return read(destination/'runtime-report.json')

    def owned_unused_image(identifier,built_here):
        state=image(identifier)
        need(state['Id']==identifier and not state.get('RepoTags'),'Image still tagged')
        labels=state['Config'].get('Labels') or {}
        if built_here:
            need(not state.get('RepoDigests'),'Candidate acquired an external digest reference')
            need(labels.get('org.expertauth.project')==PROJECT and labels.get('org.expertauth.build-run')==run_id and labels.get('org.expertauth.purpose')=='node-foundation'
                 and identifier not in report['images_before'],'Candidate does not belong to this build')
        else:
            require_owned_node(state)
            need(identifier==old['Id'] and labels==(old['Config'].get('Labels') or {}),'Old image ownership changed')
            need(set(state.get('RepoDigests') or []).issubset(old.get('RepoDigests') or []) and
                 all(value.startswith('expertauth-node-react@sha256:') for value in (state.get('RepoDigests') or [])),
                 'Old image acquired an unrelated digest reference')
        need(not call(['docker','ps','-aq','--filter','ancestor='+identifier]).stdout.strip(),'Image still has consumers')
        call(['docker','image','rm','--no-prune',identifier])

    try:
        old=image(TAG)
        report['previous_image_ownership']=require_owned_node(old)
        report['previous_image_id']=old['Id']
        report['resources_before']=resources()
        report['source_before']={name:source_projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)}
        report['private_configuration_before']={p:sha(ROOT/p) for p in ['.runtime/oss-core/config.yaml','.runtime/oss-core/runtime.env']}
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
            parser_output=output/'parser-boundaries'; parser_output.mkdir()
            helper('parser-boundaries',old['Id'],[
                (ROOT/'tools/verify_node_runtime.mjs','/repo/tools/verify_node_runtime.mjs',False),
                (ROOT/'tools/export_node_packages.mjs','/repo/tools/export_node_packages.mjs',False),
                (ROOT/'tests/reuse/node_package_boundaries.mjs','/repo/tests/reuse/node_package_boundaries.mjs',False),
                (parser_output,'/out',True)],
                ['/repo/tests/reuse/node_package_boundaries.mjs','--output','/out/node-package-boundaries.json'])
            boundary=read(parser_output/'node-package-boundaries.json')
            need(boundary['ok'] and boundary['passed']==8 and boundary['skipped']==0 and boundary['cleanup']['temporary_directory_removed'],
                 'Actual runtime parser boundaries failed')
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
            need(candidate_audit['dependency_files_sha256']==old_audit['dependency_files_sha256'] and
                 candidate_audit['dependency_directories']==old_audit['dependency_directories'],'Installed dependency files or directories changed')
            expected_app={p.removeprefix('examples/node-react/'):inputs[p] for p in INPUTS if p.startswith('examples/node-react/') and
                          p not in ['examples/node-react/Dockerfile','examples/node-react/.dockerignore','examples/node-react/test/email-delivery.test.js']}
            actual_app={row['path']:row['sha256'] for row in candidate_audit['app_files'] if row['type']=='file'}
            need(len(actual_app)==len(candidate_audit['app_files']) and actual_app==expected_app,'Installed application membership or bytes differ')
            need(all(row['mode']==0o644 for row in candidate_audit['app_files']),
                 'Application files must have deterministic0644 modes')
            need(candidate_audit['lock_sha256']==inputs['examples/node-react/package-lock.json'] and
                 candidate_audit['tar_correspondence']['verified'],'Original npm member correspondence is incomplete')
            report['installed_dependency_tree_unchanged']=True
            report['installed_app_source_and_bundle_match']=True
            report['installed_app_file_mode']='0644'
            unit=helper('unit-tests',candidate,[(ROOT/'examples/node-react/test/email-delivery.test.js','/app/test/email-delivery.test.js',False)],
                        ['--test','--test-reporter=tap','/app/test/email-delivery.test.js'])
            need(b'# pass 55' in unit.stdout and b'# fail 0' in unit.stdout and b'# skipped 0' in unit.stdout,'Installed delivery unit tests incomplete')
            reset_name='installed-'+args.name
            child_argv=[sys.executable,'-B','tools/run_password_reset_lab.py','--name',reset_name,'--installed-image',candidate,'--max-main-seconds','600']
            if args.session_build:
                parent_name=reset_name
                reset_name='atomic-'+parent_name
                child_argv=[sys.executable,'-B','tools/run_atomic_reset_lab.py','--name',parent_name,'--with-node',
                             '--session-build',args.session_build,'--installed-node-image',candidate]
                if args.qualify_refresh_grace:child_argv+=['--installed-core-image',grace_core]
            child_stdout,child_stderr=output/'reset-lab.stdout',output/'reset-lab.stderr'
            child_record={'argv':child_argv,'main_phase_deadline_seconds':600,'exit_code':None,
                          'cleanup_policy':'Child owns bounded cleanup after its main deadline; parent does not kill an owner of live resources'}
            report['reset_child']=child_record
            with child_stdout.open('xb') as out, child_stderr.open('xb') as err:
                child=subprocess.Popen(child_argv,cwd=ROOT,stdout=out,stderr=err)
                child_record['process_id']=child.pid; persist()
                child_record['exit_code']=child.wait()
            child_record['stdout']={'path':child_stdout.name,'sha256':sha(child_stdout)}
            child_record['stderr']={'path':child_stderr.name,'sha256':sha(child_stderr)}
            persist()
            reset=read(ROOT/'evidence/operations/password-reset'/reset_name/'report.json')
            need(child_record['exit_code']==0 and reset['passed'] and reset['installed_image_tested'] and reset['images']['node']==candidate,'Installed reset lab failed')
            if args.session_build:
                parent_path='evidence/operations/atomic-reset/'+parent_name+'/report.json'
                parent=read(ROOT/parent_path)
                need(parent['passed'] and parent['installed_node_image']==candidate and parent['password_session_build']==args.session_build and
                     parent['node_child']['sha256']==sha(ROOT/'evidence/operations/password-reset'/reset_name/'report.json'),'Atomic deployment parent did not qualify exact child')
                report['atomic_parent_report']={'path':parent_path,'sha256':sha(ROOT/parent_path)}
            report['reset_report']={'path':'evidence/operations/password-reset/'+reset_name+'/report.json',
                                    'sha256':sha(ROOT/'evidence/operations/password-reset'/reset_name/'report.json')}
            if args.qualify_refresh_grace:
                grace_name='installed-'+args.name
                argv=[sys.executable,'-B','tools/run_refresh_grace_lab.py','--name',grace_name,'--session-build',args.session_build,'--with-node','--installed-node-image',candidate]
                record={'argv':argv,'exit_code':None,'cleanup_owned_by_child':True};report['refresh_grace_child']=record
                paths={stream:output/('refresh-grace-lab.'+stream) for stream in ('stdout','stderr')}
                with paths['stdout'].open('xb') as out,paths['stderr'].open('xb') as err:
                    child=subprocess.Popen(argv,cwd=ROOT,stdout=out,stderr=err);record['process_id']=child.pid;persist();record['exit_code']=child.wait()
                for stream,path in paths.items():record[stream]={'path':path.name,'sha256':sha(path)}
                path=ROOT/'evidence/foundation/refresh-grace'/grace_name/'report.json';grace=read(path)
                need(record['exit_code']==0 and grace['passed'] and grace['installed_node_image']==candidate and grace['images']['core']==grace_core,
                    'Installed refresh/grace adaptation was not qualified')
                report['refresh_grace_report']={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path)}
                policy_name='policy-'+args.name
                argv=[sys.executable,'-B','tools/run_refresh_grace_lab.py','--name',policy_name,'--session-build',args.session_build,
                      '--with-node','--policy-readiness','--guarded-node','--installed-node-image',candidate]
                record={'argv':argv,'exit_code':None,'cleanup_owned_by_child':True};report['session_policy_child']=record
                paths={stream:output/('session-policy-lab.'+stream) for stream in ('stdout','stderr')}
                with paths['stdout'].open('xb') as out,paths['stderr'].open('xb') as err:
                    child=subprocess.Popen(argv,cwd=ROOT,stdout=out,stderr=err);record['process_id']=child.pid;persist();record['exit_code']=child.wait()
                for stream,path in paths.items():record[stream]={'path':path.name,'sha256':sha(path)}
                path=ROOT/'evidence/foundation/refresh-grace'/policy_name/'report.json';policy=read(path)
                need(record['exit_code']==0 and policy['passed'] and policy['installed_node_image']==candidate and policy['images']['core']==grace_core,
                     'Installed session-policy refusal was not qualified')
                report['session_policy_report']={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path)}
            need(report['cache_before']==cache_snapshot(),'Package cache changed during build')
            need(inputs=={p:sha(ROOT/p) for p in selected_inputs},'Build inputs changed')
            need(resources()==report['resources_before'],'Task resources changed during qualification')
            need(report['source_before']=={name:source_projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)},'Source services changed')
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
        for key,observer,expected in [
            ('resources_after',resources,report.get('resources_before')),
            ('source_after',lambda:{name:source_projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)},report.get('source_before')),
            ('private_configuration_after',lambda:{p:sha(ROOT/p) for p in ['.runtime/oss-core/config.yaml','.runtime/oss-core/runtime.env']},report.get('private_configuration_before')),
            ('inputs_after',lambda:{p:sha(ROOT/p) for p in selected_inputs},inputs),
            ('cache_after',cache_snapshot,report.get('cache_before')),
        ]:
            try:
                observed=observer(); report[key]=observed
                report[key+'_unchanged']=None if expected is None else observed==expected
                if expected is not None: need(observed==expected,'Final preservation check failed: '+key)
            except Exception as error:
                report['passed']=False; report['errors'].append('Final '+key+': '+type(error).__name__+': '+str(error))
        report['finished']=datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'report':output.relative_to(ROOT).as_posix(),'passed':report['passed'],'image_promoted':report['image_promoted'],'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
