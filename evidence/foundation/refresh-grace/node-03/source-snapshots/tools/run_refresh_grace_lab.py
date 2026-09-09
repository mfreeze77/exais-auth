"""Real CDI5.6 grace policy on two installed replicas and one disposable database.

No original database contact, image build/download, new network/volume or ports.
The probe's AFTER UPDATE trigger is fault instrumentation in its tmpfs DB only.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import queue
import secrets
import subprocess
import threading
import time
import uuid
from atomic_core_identity import current_core_image,require_atomic_core
from run_recovery_drill import projection,SOURCE_CORE,SOURCE_PG,POSTGRES
from run_sdk_session_faults import inspect,inventory,NETWORK

ROOT=Path(__file__).resolve().parents[1]
PROBE='tests/foundation/RefreshGraceProbe.java'
BASE='tests/operations/AtomicResetProbe.java'
POLICY='contracts/session-policy-oss-cdi56-grace-v1.json'

def need(value,message):
    if not value: raise ValueError(message)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True)
    parser.add_argument('--with-node',action='store_true',help='Exercise the explicit Node adaptation and real browser instead of repeating the Core-only cases')
    args=parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}',args.name),'Invalid run name')
    output=ROOT/'evidence/foundation/refresh-grace'/args.name
    private=(ROOT/'.runtime/refresh-grace'/args.name).resolve()
    need(not output.exists() and not private.exists() and private.parent==(ROOT/'.runtime/refresh-grace').resolve(),'Preserve prior evidence/private data')
    core=current_core_image();require_atomic_core(inspect('image',core))
    need(inspect('image',POSTGRES)['Id']==POSTGRES and inspect('network',NETWORK)['Internal'],'Cached private lab prerequisites differ')
    policy=json.loads((ROOT/POLICY).read_text())
    need(policy['refresh_token_rotation_grace_period_seconds']==5 and policy['wire_version']=='5.6','Probe and declared policy differ')
    source_before={name:projection(inspect('container',name)) for name in (SOURCE_CORE,SOURCE_PG)}
    before=inventory();output.mkdir(parents=True);(private/'secrets').mkdir(parents=True)
    suffix=uuid.uuid4().hex[:12]
    roles=('postgres','core-a','core-b','ready','node','browser') if args.with_node else ('postgres','core-a','core-b','ready','worker')
    names={role:'expertauth-reset-'+role+'-'+suffix for role in roles}
    labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'refresh-grace-lab','org.expertauth.run':suffix}
    password,key=secrets.token_hex(32),secrets.token_hex(32)
    pg_env=private/'secrets/postgres.env';worker_env=private/'secrets/worker.env';config=private/'secrets/core.yaml'
    pg_env.write_text('POSTGRES_USER=expertauth_reset\nPOSTGRES_DB=expertauth_reset\nPOSTGRES_PASSWORD='+password+'\n')
    worker_env.write_text('RESET_CORE_A=http://'+names['core-a']+':3567\nRESET_CORE_B=http://'+names['core-b']+':3567\nRESET_CORE_API_KEY='+key+'\nRESET_DATABASE_PASSWORD='+password+'\nRESET_JDBC_URL=jdbc:postgresql://'+names['postgres']+':5432/expertauth_reset\n')
    config.write_text('core_config_version: 0\npostgresql_config_version: 0\nhost: 0.0.0.0\nport: 3567\napi_keys: "'+key+'"\npostgresql_host: '+names['postgres']+'\npostgresql_port: 5432\npostgresql_user: expertauth_reset\npostgresql_password: "'+password+'"\npostgresql_database_name: expertauth_reset\ndisable_telemetry: true\naccess_token_validity: 60\naccess_token_validity_jitter: 0\nrefresh_token_rotation_grace_period: 5\nrecent_token_reuse_behaviour: TOKEN_THEFT\nmax_server_pool_size: 12\npostgresql_connection_pool_size: 12\n')
    node_image=browser_image=None
    if args.with_node:
        from node_runtime_identity import require_owned_node,TAG
        from run_sdk_session_faults import BROWSER
        node_image=inspect('image',TAG)['Id'];require_owned_node(inspect('image',node_image))
        browser_image=inspect('image',BROWSER)['Id']
        config.write_text(config.read_text().replace('access_token_validity: 60\n','access_token_validity: 8\n'))
        node_env=private/'secrets/node.env'
        (private/'app-log').mkdir()
        node_alias=names['node']+'.example.test'
        node_env.write_text('EXPERTAUTH_LOCAL_PROBE=true\nEXPERTAUTH_CORE_API_KEY='+key+'\nEXPERTAUTH_PUBLIC_ORIGIN=http://'+node_alias+':3000\n'
            'GRACE_CORE_A='+names['core-a']+'\nGRACE_CORE_B='+names['core-b']+'\nEVIDENCE_DIR=/out\n')
    sources=['tools/run_refresh_grace_lab.py',PROBE,BASE,POLICY,'tools/run_recovery_drill.py','tools/run_sdk_session_faults.py','tools/atomic_core_identity.py',
        'evidence/operations/password-session-build/compile-04/report.json',
        '.cache/engine-build/supertokens-core/src/main/java/io/supertokens/session/Session.java',
        '.cache/engine-build/supertokens-core/src/main/java/io/supertokens/config/CoreConfig.java',
        '.cache/engine-build/supertokens-core/src/main/java/io/supertokens/webserver/api/session/RefreshSessionAPI.java',
        '.cache/engine-build/supertokens-postgresql-plugin/src/main/java/io/supertokens/storage/postgresql/queries/SessionQueries.java']
    if args.with_node:sources+=['tools/node_runtime_identity.py','tests/foundation/sdk_refresh_grace.mjs','tests/browser/session-grace.mjs',
        'tests/browser/package-lock.json','examples/node-react/server.js','examples/node-react/client.jsx','examples/node-react/package-lock.json']
    report={'kind':'isolated-core-refresh-grace-lab','started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,
        'foundation_passed':False,'sdk_qualified':False,'independent_human_review':False,'images_built':0,'image_downloads':0,
        'new_volumes':0,'new_networks':0,'published_ports':[],'source_database_contacted':False,'run_id':suffix,
        'images':{'core':core,'postgres':POSTGRES},'policy':policy,'inputs':{p:sha(ROOT/p) for p in sources},
        'configuration_sha256':sha(config),'commands':[],'errors':[],'created_containers':[],'retired_containers':[],
        'resources_before':before,'source_before':source_before}
    report['mode']='adapted-node-browser' if args.with_node else 'direct-core'
    if args.with_node:report['images'].update(node=node_image,browser=browser_image)
    for name in sources:
        # Original cache source is already license-audited; omit the forbidden cache
        # directory name from source-checkpoint member paths without changing bytes.
        destination=name.replace('.cache/engine-build/','audited-upstream/')
        target=output/'source-snapshots'/destination;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
    ids={}
    def persist(): (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    def call(argv,timeout=35,required=True):
        index=len(report['commands'])+1;row={'argv':argv,'exit_code':None,'timed_out':False};report['commands'].append(row)
        files={stream:private/f'command-{index:03d}.{stream}' for stream in ('stdout','stderr')};result=None
        try:
            with files['stdout'].open('xb') as out,files['stderr'].open('xb') as err:
                result=subprocess.run(argv,cwd=ROOT,stdout=out,stderr=err,stdin=subprocess.DEVNULL,timeout=timeout)
            row['exit_code']=result.returncode
        except subprocess.TimeoutExpired: row['timed_out']=True
        finally:
            for stream,p in files.items():row[stream]={'bytes':p.stat().st_size,'sha256':sha(p)}
            persist()
        need(result is not None,'Command deadline exceeded: '+str(index))
        need(not required or result.returncode==0,'Command failed: '+str(index))
        return result.returncode,files['stdout'].read_bytes()
    def controlled_call(argv):
        index=len(report['commands'])+1;row={'argv':argv,'exit_code':None,'timed_out':False,'live_worker_control':True};report['commands'].append(row)
        files={stream:private/f'command-{index:03d}.{stream}' for stream in ('stdout','stderr')};process=None
        try:
            with files['stdout'].open('xb') as out,files['stderr'].open('xb') as err:
                process=subprocess.Popen(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=err,stdin=subprocess.PIPE)
                lines=queue.Queue()
                def reader():
                    for line in process.stdout:lines.put(line)
                    lines.put(None)
                threading.Thread(target=reader,daemon=True).start();deadline=time.monotonic()+240;controlled=False
                while time.monotonic()<deadline:
                    try:line=lines.get(timeout=1)
                    except queue.Empty:continue
                    if line is None:break
                    out.write(line);out.flush()
                    try:message=json.loads(line)
                    except ValueError:continue
                    if 'check' in message:print(json.dumps(message),flush=True)
                    if 'control' in message:
                        need(message['control']=='browser_coordination' and not controlled,'Unexpected or repeated worker control')
                        controlled=True;need(own('node') is not None,'Node worker missing before browser action')
                        launch('browser',['--read-only','--memory=1g','--pids-limit=256','--ipc=private','--shm-size=256m',
                            '--tmpfs','/tmp:rw,nosuid,size=512m','--env-file',str(node_env),
                            '--mount',f'type=bind,source={ROOT},target=/repo,readonly','--mount',f'type=bind,source={output},target=/out',
                            '--entrypoint','node'],['/repo/tests/browser/session-grace.mjs'],True,150)
                        process.stdin.write(b'{"ok":true}\n');process.stdin.flush()
                else:row['timed_out']=True;raise ValueError('Node worker deadline exceeded')
                row['exit_code']=process.wait(timeout=10);need(row['exit_code']==0,'Actual Node worker failed')
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            for stream,p in files.items():row[stream]={'bytes':p.stat().st_size,'sha256':sha(p)}
            persist()
        return row['exit_code'],files['stdout'].read_bytes()
    def image(role): return POSTGRES if role=='postgres' else node_image if role=='node' else browser_image if role=='browser' else core
    def own(role):
        code,raw=call(['docker','inspect',names[role]],required=False)
        if code:return None
        state=json.loads(raw)[0]
        need(state['Name']=='/'+names[role] and state['Image']==image(role) and all((state['Config'].get('Labels') or {}).get(k)==v for k,v in labels.items()) and
             not state['HostConfig']['PortBindings'] and not any(m['Type']=='volume' for m in state['Mounts']),'Owned container boundary differs')
        if role in ids:need(ids[role]==state['Id'],'Owned container ID changed')
        ids[role]=state['Id'];return state
    def launch(role,extra,arguments=(),wait=False,timeout=40):
        need(not call(['docker','ps','-aq','--filter','name=^/'+names[role]+'$'])[1].strip(),'Container name occupied')
        argv=['docker','run','--rm','--pull=never','--name',names[role],'--cidfile',str(private/(role+'.cid')),'--network',NETWORK,
              '--cpus=2','--security-opt=no-new-privileges','--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false']
        for k,v in labels.items():argv+=['--label',k+'='+v]
        if not wait:argv+=['-d']
        try:
            if role=='node':code,raw=controlled_call(argv+extra+[image(role),*arguments])
            else:code,raw=call(argv+extra+[image(role),*arguments],timeout=timeout,required=False)
        finally:
            cidfile=private/(role+'.cid')
            if cidfile.exists():
                cid=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid Docker-created ID');ids[role]=cid
                report['created_containers'].append({'role':role,'id':cid})
        need(code==0,'Container operation failed: '+role)
        return raw
    def worker(role,ready=False):
        script="javac -proc:none --release 21 -cp '/opt/expertauth/lib/*:/opt/expertauth/plugin/*' -d /tmp/probe /src/*.java && java -Xmx256m -cp '/tmp/probe:/opt/expertauth/lib/*:/opt/expertauth/plugin/*' RefreshGraceProbe"+(' --ready-a' if ready else '')
        return launch(role,['--read-only','--memory=512m','--pids-limit=128','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m',
            '--tmpfs','/home/gradle/.gradle:rw,nosuid,nodev,noexec,size=1m','--env-file',str(worker_env),
            '--mount',f'type=bind,source={ROOT/BASE},target=/src/AtomicResetProbe.java,readonly',
            '--mount',f'type=bind,source={ROOT/PROBE},target=/src/RefreshGraceProbe.java,readonly',
            '--mount',f'type=bind,source={output},target=/out','--entrypoint','sh'],['-eu','-c',script],True,150)
    try:
        launch('postgres',['--memory=512m','--pids-limit=128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,size=256m',
            '--tmpfs','/var/run/postgresql:rw,nosuid,size=16m','--env-file',str(pg_env)])
        need(own('postgres') is not None,'Temporary database missing');deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            if call(['docker','exec',ids['postgres'],'pg_isready','-U','expertauth_reset','-d','expertauth_reset'],required=False)[0]==0:break
            time.sleep(.3)
        else:raise ValueError('Temporary database readiness failed')
        for role in ('core-a','core-b'):
            launch(role,['--memory=1g','--pids-limit=256','--tmpfs','/tmp:rw,nosuid,noexec,size=64m','--tmpfs','/home/gradle/.gradle:rw,nosuid,noexec,size=1m',
                '--mount',f'type=bind,source={config},target=/run/expertauth/config.yaml,readonly'])
            state=own(role);need(state is not None and all(not m['Destination'].startswith('/opt/expertauth/') for m in state['Mounts']),'Installed Core has application overlays')
            report.setdefault('installed_mounts',{})[role]=state['Mounts']
            if role=='core-a':worker('ready',True)
        if args.with_node:
            print('Testing the explicit Node CDI5.6 adaptation and real browser coordination.',flush=True)
            launch('node',['-i','--network-alias',node_alias,'--read-only','--memory=512m','--pids-limit=128','--tmpfs','/tmp:rw,nosuid,size=128m','--env-file',str(node_env),
                '--mount',f'type=bind,source={ROOT},target=/repo,readonly','--mount',f'type=bind,source={output},target=/out',
                '--mount',f'type=bind,source={private/"app-log"},target=/private',
                '--mount',f'type=bind,source={ROOT/"examples/node-react/server.js"},target=/app/server.js,readonly','--entrypoint','node'],
                ['/repo/tests/foundation/sdk_refresh_grace.mjs'],True,240)
            probe=json.loads((output/'sdk-results.json').read_text());browser=json.loads((output/'browser-results.json').read_text())
            need(probe['failed']==0 and not probe['fatal'] and len(probe['rows'])==11 and all(r['outcome']=='passed' for r in probe['rows']) and
                 len(browser['rows'])==3 and all(r['outcome']=='passed' for r in browser['rows']),'Actual SDK/browser cases incomplete')
            need(not probe['unmodified_sdk_qualified'] and not probe['foundation_passed'],'Overbroad SDK qualification')
            report['sdk_sha256']=sha(output/'sdk-results.json');report['browser_sha256']=sha(output/'browser-results.json')
            report['private_app_log_sha256']=sha(private/'app-log/app-output.json')
        else:
            print('Testing twelve declared CDI5.6 policy cases on disposable installed Core replicas.',flush=True)
            worker('worker')
            probe=json.loads((output/'probe-report.json').read_text())
            need(probe['passed'] and len(probe['rows'])==12 and all(r['status']=='passed' for r in probe['rows']),'Policy cases failed or incomplete')
            need(not probe['sdk_qualified'] and not probe['foundation_passed'],'Overbroad qualification claim')
            report['probe_sha256']=sha(output/'probe-report.json')
        report['work_passed']=True
    except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        for role in reversed(list(names)):
            try:
                state=own(role)
                if state:
                    if role.startswith('core') and report['errors']:call(['docker','logs','--tail','80',state['Id']],required=False)
                    if state['State']['Running']:call(['docker','stop','--time=5',state['Id']],timeout=20,required=False)
                    if own(role):call(['docker','rm','-f',state['Id']],timeout=20,required=False)
                need(not call(['docker','ps','-aq','--filter','name=^/'+names[role]+'$'])[1].strip(),'Temporary resource remains')
                if role in ids:
                    need(ids[role] not in call(['docker','ps','-aq','--no-trunc'])[1].decode().splitlines(),'Exact temporary ID remains')
                    report['retired_containers'].append({'role':role,'id':ids[role]})
            except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else 'Retirement failed: '+type(error).__name__)
        try:
            report['resources_after']=inventory();report['source_after']={name:projection(inspect('container',name)) for name in source_before}
            report['resources_unchanged']=before==report['resources_after'];report['source_unchanged']=source_before==report['source_after']
            report['inputs_unchanged']=report['inputs']=={p:sha(ROOT/p) for p in sources}
            need(report['resources_unchanged'] and report['source_unchanged'] and report['inputs_unchanged'],'Source/resource preservation failed')
        except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
        report['passed']=not report['errors'] and report.get('work_passed') is True;report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'report':output.relative_to(ROOT).as_posix(),'created':len(report['created_containers']),'retired':len(report['retired_containers']),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
