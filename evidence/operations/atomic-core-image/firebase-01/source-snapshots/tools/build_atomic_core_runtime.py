"""Build, test and locally replace the Core image with its exact atomic adaptation.

Reuses the original audited runtime assembly and cached pinned base. Qualifies
two installed replicas and the installed Node/SMTP/browser profile before the
separate upgrade/rollback controller may replace the private source Core.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
from build_oss_runtime import prepare_context, buildx_command
from atomic_core_identity import TAG, require_atomic_core
from node_runtime_identity import TAG as NODE, require_owned_node
from run_sdk_session_faults import ROOT, inspect, inventory

SOURCES=['tools/build_atomic_core_runtime.py','tools/build_oss_runtime.py','tools/assemble_runtime_licenses.py',
         'tools/atomic_core_identity.py','tools/replace_atomic_core.py','tools/run_atomic_reset_lab.py','tools/run_password_reset_lab.py',
         'tools/run_recovery_drill.py','tools/run_sdk_session_faults.py','tests/operations/core_upgrade_probe.py','tools/wait_oss_storage.py',
         'tests/operations/AtomicResetProbe.java','tests/operations/PasswordSessionProbe.java','tests/operations/password_reset_probe.mjs',
         'tests/operations/password_session_wire.mjs','deploy/oss-core.Dockerfile','reuse/password-session-components.json',
         'reuse/oss-core-runtime.cdx.json','reuse/licenses/supertokens__supertokens-core/b2219c4aa019a501e4dfea76cf06ef802ca93fc0/LICENSE.md']

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name',required=True)
    parser.add_argument('--session-build',required=True)
    parser.add_argument('--qualify-refresh-grace',action='store_true')
    parser.add_argument('--qualify-guarded-sessions',action='store_true')
    parser.add_argument('--legacy-session-build',help='Include the current pre-guard Core as an actual unsupported-route replica before replacement')
    parser.add_argument('--native-argon2-build',help='Install and qualify the exact source-built native library through the nolibs wrapper')
    args=parser.parse_args()
    need(not args.legacy_session_build or args.qualify_guarded_sessions,'Legacy route proof requires guarded-session qualification')
    need(re.fullmatch('[A-Za-z0-9_-]{1,35}',args.name) and re.fullmatch('[A-Za-z0-9_-]{1,54}',args.session_build),'Invalid build names')
    build_path=ROOT/'evidence/operations/password-session-build'/args.session_build/'report.json'
    compiled=json.loads(build_path.read_text())
    need(compiled['passed'] and len(compiled['candidates'])==2 and all(sha(ROOT/p)==h for p,h in compiled['inputs'].items()) and
         all(sha(ROOT/r['path'])==r['sha256'] for r in compiled['candidates']),'Current source/binary adaptation required')
    node=inspect('image',NODE);require_owned_node(node)
    old=inspect('image',TAG)
    need(old['Config'].get('Labels',{}).get('org.expertauth.project')=='expert-auth' and inspect('container','expertauth-oss-core-a')['Image']==old['Id'],'Protected runtime/tag differs')
    output=ROOT/'evidence/operations/atomic-core-image'/args.name
    private=(ROOT/'.runtime/atomic-core-image'/args.name).resolve()
    context=(ROOT/'.cache'/('runtime-image-atomic-'+uuid.uuid4().hex)).resolve()
    need(not output.exists() and not private.exists() and not context.exists() and private.parent==(ROOT/'.runtime/atomic-core-image').resolve() and
         context.parent==(ROOT/'.cache').resolve(),'Fresh bounded build paths required')
    output.mkdir(parents=True);private.mkdir(parents=True);context.mkdir()
    run_id=uuid.uuid4().hex
    sources=list(dict.fromkeys(SOURCES+list(compiled['inputs'])+[build_path.relative_to(ROOT).as_posix()]))
    if args.qualify_refresh_grace:
        sources+=['tools/run_refresh_grace_lab.py','tests/foundation/RefreshGraceProbe.java','contracts/session-policy-oss-cdi56-grace-v1.json']
    if args.qualify_guarded_sessions:
        sources+=['tools/run_refresh_grace_lab.py','tests/foundation/RefreshGraceProbe.java','tests/foundation/GuardedSessionProbe.java','contracts/session-policy-oss-cdi56-grace-v1.json']
    native=None
    firebase=compiled.get('firebase_scrypt_profile')=='bouncycastle-utf8-v1'
    if firebase:
        from install_bouncycastle import SOURCES as BC_SOURCES,inputs as bc_inputs
        bc_inputs()
        sources += [*BC_SOURCES,'tests/foundation/FirebaseScryptProbe.java','tests/foundation/firebase-fixtures.mjs']
    if args.native_argon2_build:
        from install_native_argon2 import SOURCES as NATIVE_SOURCES,native_build
        native_path,native,_=native_build(args.native_argon2_build)
        sources += [*NATIVE_SOURCES,'tools/qualify_native_startup.py','tests/foundation/NativePasswordProbe.java',
                    'tools/run_refresh_grace_lab.py',native_path.relative_to(ROOT).as_posix()]
    report={'kind':'installed-atomic-core-runtime','started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,
            'foundation_passed':False,'full_distribution_approved':False,'installed_qualification_passed':False,
            'source_inputs':{p:sha(ROOT/p) for p in sources},'node_image':node['Id'],'previous_image':old['Id'],
            'session_build':args.session_build,'run_id':run_id,'commands':[],'errors':[],
            'image_downloads':0,'new_volumes':0,'new_networks':0,'published_ports':[],
            'resources_before':inventory(),'helpers_retired':[],'candidate_image_id':None}
    for p in sources:
        dest=output/'source-snapshots'/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((ROOT/p).read_bytes())
    candidate=None
    def persist():(output/'report.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    def call(argv,timeout=45,required=True):
        n=len(report['commands'])+1;entry={'argv':argv,'exit_code':None,'timed_out':False};report['commands'].append(entry)
        try:
            result=subprocess.run(argv,capture_output=True,timeout=timeout,cwd=ROOT);entry['exit_code']=result.returncode
            for stream in ['stdout','stderr']:
                path=output/f'command-{n:03d}.{stream}';path.write_bytes(getattr(result,stream));entry[stream]={'path':path.name,'sha256':sha(path),'bytes':path.stat().st_size}
        except subprocess.TimeoutExpired:entry['timed_out']=True;raise
        finally:persist()
        need(not required or result.returncode==0,'Command failed: '+str(n));return result
    def child(argv,kind,path):
        entry={'argv':argv,'exit_code':None,'child_owns_cleanup':True};report['commands'].append(entry);n=len(report['commands'])
        files={s:output/f'command-{n:03d}.{s}' for s in ['stdout','stderr']}
        with files['stdout'].open('xb') as out,files['stderr'].open('xb') as err:
            process=subprocess.Popen(argv,cwd=ROOT,stdout=out,stderr=err);entry['pid']=process.pid;persist();entry['exit_code']=process.wait()
        for s,p in files.items():entry[s]={'path':p.name,'sha256':sha(p),'bytes':p.stat().st_size}
        persist();result=json.loads((ROOT/path).read_text())
        report[kind]={'path':path,'sha256':sha(ROOT/path)};persist()
        need(entry['exit_code']==0 and result['passed'],'Installed child failed: '+kind)
        return result
    try:
        expected,notices=prepare_context(context)
        report['original_installed_files']=expected.copy()
        for row in compiled['candidates']:
            target=('lib/' if row['component']=='core' else 'plugin/')+Path(row['path']).name
            need(expected[target]==row['original_sha256'],'Original image artifact differs')
            (context/target).write_bytes((ROOT/row['path']).read_bytes());expected[target]=row['sha256']
        adaptation={'kind':'explicit-Core-owned-password-reset-and-session-adaptation','license':'Apache-2.0','full_distribution_approved':False,
                    'binary_build_report_sha256':sha(build_path),'candidate_artifacts':compiled['candidates'],
                    'reuse_report':json.loads((ROOT/'reuse/password-session-components.json').read_text()),
                    'generated_source_sha256':{p.name:sha(p) for p in sorted(build_path.parent.glob('*.java'))},
                    'boundaries':'Original token minting and licensing checks retained; explicit Core hashing profile recorded in compiled build; no adapter session store or control-plane SQL'}
        bom=json.loads((ROOT/'reuse/oss-core-runtime.cdx.json').read_text())
        bom['metadata']['component']['name']='expertauth-atomic-core-candidate'
        bom['metadata']['properties'].append({'name':'expertauth:adaptation','value':'Two modified Apache JARs plus unchanged plugin interface; OS/native/relink/full distribution remain unqualified'})
        own=[('expertauth-core','12.2.0+atomic-v1','core'),('expertauth-postgresql-plugin','9.8.0+atomic-v1','postgresql')]
        for name,version,key in own:
            row=next(r for r in compiled['candidates'] if r['component']==key)
            bom['components'].append({'type':'library','name':name,'version':version,'licenses':[{'license':{'id':'Apache-2.0'}}],
                'hashes':[{'alg':'SHA-256','content':row['sha256']}],'properties':[{'name':'expertauth:original-jar-sha256','value':row['original_sha256']}]})
        originals=json.loads((ROOT/'evidence/build/oss-core/artifacts.json').read_text())
        interface=next(r for r in originals if r['path'].startswith('supertokens-plugin-interface/build/libs/'))
        bom['components'].append({'type':'library','name':'supertokens-plugin-interface','version':'10.0.0','licenses':[{'license':{'id':'Apache-2.0'}}],
                                  'hashes':[{'alg':'SHA-256','content':interface['sha256']}]})
        if native:
            from install_native_argon2 import install
            report['native_argon2']=install(context,expected,notices,bom,args.native_argon2_build)
            adaptation['native_argon2']=report['native_argon2']
            report['source_inputs'].update({r['path']:r['sha256'] for r in native['inputs']})
            report['native_startup_files']={p:h for p,h in expected.items() if p.startswith('native/')}
        if firebase:
            from install_bouncycastle import install as install_bc
            report['bouncycastle']=install_bc(context,expected,notices,bom,compiled)
            adaptation['bouncycastle']=report['bouncycastle']
        extra={'expertauth/atomic/NOTICE.txt':b'ExpertAuth contributors, 2026. Apache-2.0 adaptations of SuperTokens Core and PostgreSQL plugin, copyright VRAI Labs. Modified files retain upstream attribution. See source-map.json and the preserved original license/notices. No full distribution or independent review approval is implied.\n',
               'expertauth/atomic/LICENSE.txt':(ROOT/SOURCES[-1]).read_bytes(),
               'expertauth/atomic/source-map.json':(json.dumps(adaptation,indent=2)+'\n').encode(),
               'expertauth/atomic/runtime.cdx.json':(json.dumps(bom,indent=2)+'\n').encode()}
        need(b'Apache License' in extra['expertauth/atomic/LICENSE.txt'] and len(bom['components'])==(86 if firebase else 87),'Adaptation notice/SBOM membership differs')
        for name,body in extra.items():
            path=context/'licenses'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
            digest=hashlib.sha256(body).hexdigest();expected['licenses/'+name]=digest
            notices['files'].append({'path':name,'bytes':len(body),'sha256':digest})
        notices['adaptation']={'manifest':'expertauth/atomic/source-map.json','binary_hashes':{r['component']:r['sha256'] for r in compiled['candidates']}}
        notices['input_sha256'].update(report['source_inputs'])
        (context/'licenses/manifest.json').write_bytes((json.dumps(notices,indent=2)+'\n').encode())
        expected['licenses/manifest.json']=sha(context/'licenses/manifest.json')
        (output/'notice-manifest.json').write_bytes((context/'licenses/manifest.json').read_bytes())
        (output/'adaptation-runtime.cdx.json').write_bytes(extra['expertauth/atomic/runtime.cdx.json'])
        (output/'Dockerfile').write_bytes((context/'Dockerfile').read_bytes())
        for path in report.get('native_startup_files',{}):
            if path.endswith('.so'):continue  # Keep one candidate cache; installed hash remains in the manifest.
            target=output/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((context/path).read_bytes())
        report['installed_files']=expected;report['context_bytes']=sum(p.stat().st_size for p in context.rglob('*') if p.is_file())
        need(report['context_bytes']<200*1024*1024,'Build context exceeds 200 MiB')
        base=(context/'Dockerfile').read_text().splitlines()[0].removeprefix('FROM ');inspect('image',base)
        buildx=buildx_command();builder=call(buildx+['inspect','default']).stdout.decode()
        need(re.search(r'^Driver:\s+docker\s*$',builder,re.M) and re.search(r'^Status:\s+running\s*$',builder,re.M),'Existing Docker-driver builder required')
        call(buildx+['build','--builder','default','--pull=false','--network=none','--resource','memory=512m','--resource','cpu-quota=200000',
                     '--provenance=false','--progress=plain','--iidfile',str(private/'image.id'),'--metadata-file',str(output/'build-metadata.json'),
                     '--label','org.expertauth.project=expert-auth','--label','org.expertauth.purpose=atomic-core-runtime',
                     '--label','org.expertauth.adaptation=password-session-v1','--label','org.expertauth.build-run='+run_id,str(context)],timeout=600)
        metadata=json.loads((output/'build-metadata.json').read_text());need(metadata['containerimage.config.digest']==(private/'image.id').read_text().strip(),'Image configuration digest differs')
        built=inspect('image',metadata['containerimage.digest']);candidate=built['Id'];need(require_atomic_core(built)==run_id and candidate not in report['resources_before']['images'],'Candidate ownership differs')
        report['candidate_image_id']=candidate
        helper='expertauth-atomic-image-inspect-'+run_id[:12];cidfile=private/'inspect.cid'
        try:
            result=call(['docker','run','--rm','--pull=never','--name',helper,'--cidfile',str(cidfile),'--network=none',
                '--read-only','--memory=256m','--cpus=1','--pids-limit=64','--cap-drop=ALL','--security-opt=no-new-privileges',
                '--label','org.expertauth.project=expert-auth','--label','org.expertauth.purpose=atomic-image-inspect','--label','org.expertauth.run='+run_id,
                '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
                '--tmpfs','/home/gradle/.gradle:rw,nosuid,noexec,size=1m','--entrypoint','sh',candidate,'-c',
                'cd /opt/expertauth && find lib plugin licenses version.yaml'+(' native' if native else '')+' -type f -exec sha256sum {} +'])
            actual={line.split('  ',1)[1]:line.split('  ',1)[0] for line in result.stdout.decode().splitlines()};need(actual==expected,'Installed JAR/notice inventory differs')
        finally:
            if cidfile.exists():
                cid=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid inspection CID')
                found=call(['docker','inspect','--format','{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}',cid],required=False)
                if found.returncode==0:
                    row=json.loads(found.stdout);need(row['id']==cid and row['name']=='/'+helper and row['image']==candidate and row['labels'].get('org.expertauth.run')==run_id,'Inspection ownership differs');call(['docker','rm','-f',cid])
                need(not call(['docker','ps','-aq','--filter','name=^/'+helper+'$']).stdout.strip(),'Inspection container remains')
                report['helpers_retired'].append(cid);cidfile.unlink()
        if native:
            startup_name='image-'+args.name
            child([sys.executable,'-B','tools/qualify_native_startup.py','--name',startup_name,'--image',candidate,'--native-build',args.native_argon2_build],
                  'native_startup_test','evidence/operations/native-argon2-startup/'+startup_name+'/report.json')
            native_name='image-native-'+args.name
            native_reference_args=[]
            if compiled.get('previous_build',{}).get('mode')=='new-candidate':
                native_reference_args=['--native-reference-session-build',Path(compiled['previous_build']['path']).parent.name]
            native_result=child([sys.executable,'-B','tools/run_refresh_grace_lab.py','--name',native_name,'--session-build',args.session_build,
                '--installed-core-image',candidate,'--native-argon2-build',args.native_argon2_build,'--native-argon2-installed','--native-reference-core-image',old['Id'],*native_reference_args],
                'native_password_test','evidence/foundation/refresh-grace/'+native_name+'/report.json')
            need(native_result['images']['core']==candidate and native_result['native_dependency_overlay'] is False,'Native installed qualification differs')
        if firebase:
            firebase_name='image-firebase-'+args.name
            result=child([sys.executable,'-B','tools/run_atomic_reset_lab.py','--name',firebase_name,'--session-build',args.session_build,
                '--installed-core-image',candidate,'--firebase-scrypt'],'firebase_test','evidence/operations/atomic-reset/'+firebase_name+'/report.json')
            need(result['installed_core_image']==candidate and result['firebase_reference_profile']=='bouncycastle-utf8-v1','Installed Firebase proof differs')
        if args.qualify_guarded_sessions:
            guarded_name='image-guarded-'+args.name
            argv=[sys.executable,'-B','tools/run_refresh_grace_lab.py','--name',guarded_name,'--session-build',args.session_build,
                  '--installed-core-image',candidate,'--guarded-core']
            if args.legacy_session_build:argv+=['--legacy-core-image',old['Id'],'--legacy-session-build',args.legacy_session_build]
            guarded=child(argv,'guarded_session_test','evidence/foundation/refresh-grace/'+guarded_name+'/report.json')
            need(guarded['images']['core']==candidate,'Guarded operation proof tested a different image')
        core_name='image-core-'+args.name
        core=child([sys.executable,'-B','tools/run_atomic_reset_lab.py','--name',core_name,'--session-build',args.session_build,'--installed-core-image',candidate],
                   'core_test','evidence/operations/atomic-reset/'+core_name+'/report.json')
        need(core['installed_core_image']==candidate and all(len(core['installed_core_hashes'][r])==2 for r in ['core-a','core-b']),'Installed two-replica proof missing')
        node_name='image-node-'+args.name
        node_result=child([sys.executable,'-B','tools/run_atomic_reset_lab.py','--name',node_name,'--session-build',args.session_build,'--installed-core-image',candidate,
                          '--with-node','--installed-node-image',node['Id']], 'node_test','evidence/operations/atomic-reset/'+node_name+'/report.json')
        need(node_result['installed_core_image']==candidate and node_result['installed_node_image']==node['Id'],'Installed Core/Node proof differs')
        if args.qualify_refresh_grace:
            grace_name='image-core-'+args.name
            grace=child([sys.executable,'-B','tools/run_refresh_grace_lab.py','--name',grace_name,'--session-build',args.session_build,'--installed-core-image',candidate],
                        'refresh_grace_test','evidence/foundation/refresh-grace/'+grace_name+'/report.json')
            need(grace['images']['core']==candidate and len(grace['installed_binary_hashes'])==2,'Installed Core grace proof differs')
        need(report['source_inputs']=={p:sha(ROOT/p) for p in report['source_inputs']} and all(sha(ROOT/p)==h for p,h in notices['input_sha256'].items()),'Source changed during qualification')
        expected_resources=dict(report['resources_before']);expected_resources['images']=sorted(set(expected_resources['images'])|{candidate})
        need(inventory()==expected_resources,'Temporary resources remain before replacement')
        report['installed_qualification_passed']=True;persist()
        qualification=output/'qualification.json';qualification.write_bytes((json.dumps(report,indent=2)+'\n').encode())
        replacement=child([sys.executable,'-B','tools/replace_atomic_core.py','--name',args.name,'--image-report',qualification.relative_to(ROOT).as_posix()],
                          'replacement','evidence/operations/atomic-core-replacement/'+args.name+'/report.json')
        need(replacement['committed'] and replacement['old_image_retired']==old['Id'],'Replacement did not retire old runtime')
        report['passed']=True
    except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            current=inspect('image',TAG)['Id']
            if candidate and current!=candidate:
                found=inspect('image',candidate);need(require_atomic_core(found)==run_id and not found.get('RepoTags'),'Failed candidate references changed')
                need(not subprocess.check_output(['docker','ps','-aq','--filter','ancestor='+candidate]).strip(),'Failed candidate still in use')
                call(['docker','image','rm','--no-prune',candidate]);report['failed_candidate_retired']=True
            paths=list(context.rglob('*'));need(all(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400 and p.resolve().is_relative_to(context) for p in [context,*paths]),'Unsafe context cleanup')
            for p in paths:
                if p.is_file():p.unlink()
            for p in sorted((p for p in paths if p.is_dir()),key=lambda p:len(p.parts),reverse=True):p.rmdir()
            context.rmdir();report['context_removed']=True
            (private/'image.id').unlink(missing_ok=True)
            if not any(private.iterdir()):private.rmdir()
            report['private_scratch_removed']=not private.exists();need(report['private_scratch_removed'],'Private build scratch remains')
        except Exception as error:report['passed']=False;report['errors'].append('Cleanup: '+(str(error) if isinstance(error,ValueError) else type(error).__name__))
        report['resources_after']=inventory();report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'candidate_image':candidate,'errors':report['errors'],'report':str((output/'report.json').relative_to(ROOT))}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
