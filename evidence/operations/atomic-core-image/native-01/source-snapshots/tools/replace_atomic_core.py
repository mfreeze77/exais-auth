"""Qualify an owned local Core upgrade, actual rollback, and final replacement.

Requires completed installed-image Core/Node tests. Keeps the original container
and image until session continuity, rollback and fixture cleanup pass. Never
replaces PostgreSQL, edits identity tables, or changes private configuration.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
from atomic_core_identity import TAG, require_atomic_core
from run_sdk_session_faults import ROOT, NETWORK, inspect, inventory

CORE='expertauth-oss-core-a'
PG='expertauth-oss-postgres'
PYTHON='sha256:5bffadb83aa3127f8339e6dcd3e8bc6a04dcbcabf3b66b7dcddfab81369e78fd'
SOURCES=['tools/replace_atomic_core.py','tools/atomic_core_identity.py','tools/run_sdk_session_faults.py',
         'tools/wait_oss_storage.py','tests/operations/core_upgrade_probe.py']

def need(ok,message):
    if not ok: raise ValueError(message)

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def state(row):
    return {'id':row['Id'],'image':row['Image'],'started':row['State']['StartedAt'],'running':row['State']['Running'],
            'mounts':sorted(row['Mounts'],key=lambda m:m['Destination']),'ports':row['HostConfig']['PortBindings']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-report',required=True)
    parser.add_argument('--name',required=True)
    args=parser.parse_args();need(re.fullmatch('[A-Za-z0-9_-]{1,54}',args.name),'Invalid replacement name')
    proof_path=(ROOT/args.image_report).resolve()
    need(proof_path.is_relative_to(ROOT/'evidence/operations/atomic-core-image'),'Unexpected image qualification report')
    proof=json.loads(proof_path.read_text())
    need(proof['installed_qualification_passed'] and proof['source_inputs']=={p:sha(ROOT/p) for p in proof['source_inputs']},'Complete current installed-image qualification required')
    image=proof['candidate_image_id'];require_atomic_core(inspect('image',image))
    for kind in ['core_test','node_test']:
        row=proof[kind];need(sha(ROOT/row['path'])==row['sha256'] and json.loads((ROOT/row['path']).read_text())['passed'],'Image behavior proof differs')
    if proof.get('native_argon2'):
        for kind in ('native_startup_test','native_password_test'):
            row=proof[kind];need(sha(ROOT/row['path'])==row['sha256'] and json.loads((ROOT/row['path']).read_text())['passed'],'Native qualification differs')
    output=ROOT/'evidence/operations/atomic-core-replacement'/args.name
    private=(ROOT/'.runtime/atomic-core-replacement'/args.name).resolve()
    need(not output.exists() and not private.exists() and private.parent==(ROOT/'.runtime/atomic-core-replacement').resolve(),'Preserve prior replacement data')
    output.mkdir(parents=True);private.mkdir(parents=True);(private/'fixture').mkdir()
    run_id=uuid.uuid4().hex; old_name='expertauth-core-old-'+run_id[:12]; new_name='expertauth-core-new-'+run_id[:12]
    config=ROOT/'.runtime/oss-core/config.yaml'; env=ROOT/'.runtime/oss-core/runtime.env'
    inputs={p:sha(ROOT/p) for p in SOURCES}
    report={'kind':'local-core-upgrade-rollback','started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,
            'new_image':image,'image_report':{'path':proof_path.relative_to(ROOT).as_posix(),'sha256':sha(proof_path)},
            'inputs':inputs,'private_configuration':{str(p.relative_to(ROOT)):sha(p) for p in [config,env]},
            'commands':[],'errors':[],'helpers':[],'run_id':run_id,'production_changed':False,'database_container_replaced':False}
    for p in SOURCES:
        dest=output/'source-snapshots'/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((ROOT/p).read_bytes())
    old=new=None;active='old';committed=False;fixture_attempted=False
    cidfile=private/'new-core.cid'
    def persist(): (output/'report.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    def call(argv,required=True,timeout=45):
        n=len(report['commands'])+1; record={'argv':argv,'exit_code':None,'timed_out':False};report['commands'].append(record)
        try:
            result=subprocess.run(argv,capture_output=True,timeout=timeout,cwd=ROOT);record['exit_code']=result.returncode
            for stream in ['stdout','stderr']:
                path=private/f'command-{n:03d}.{stream}';path.write_bytes(getattr(result,stream))
                record[stream]={'path':path.relative_to(ROOT).as_posix(),'bytes':path.stat().st_size,'sha256':sha(path)}
        except subprocess.TimeoutExpired:record['timed_out']=True;raise
        finally:persist()
        need(not required or result.returncode==0,'Command failed: '+str(n));return result
    def own(cid,expected_image,expected_name):
        row=inspect('container',cid);labels=row['Config'].get('Labels') or {}
        need(row['Id']==cid and row['Image']==expected_image and row['Name']=='/'+expected_name and
             labels.get('org.expertauth.project')=='expert-auth' and labels.get('org.expertauth.purpose')=='oss-foundation', 'Core ownership differs')
        need(expected_name in [CORE,old_name,new_name] and (expected_image!=image or labels.get('org.expertauth.upgrade-run')==run_id),'Upgrade resource ownership differs')
        return row
    def helper(phase,ready=False,operation=None):
        name='expertauth-upgrade-'+phase+'-'+run_id[:12];cidfile=private/(phase+'.cid')
        labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'atomic-core-upgrade-probe','org.expertauth.run':run_id}
        argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(cidfile),'--network',NETWORK,
              '--read-only','--user=0','--memory=256m','--cpus=1','--pids-limit=64','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,noexec,size=16m',
              '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false','--env-file',str(env)]
        for k,v in labels.items():argv+=['--label',k+'='+v]
        source=ROOT/('tools/wait_oss_storage.py' if ready else 'tests/operations/core_upgrade_probe.py')
        argv+=['--mount',f'type=bind,source={source},target=/probe.py,readonly','--mount',f'type=bind,source={private/"fixture"},target=/private',
               '--mount',f'type=bind,source={output},target=/out','--entrypoint','python',PYTHON,'-B','/probe.py','http://core-a:3567' if ready else (operation or phase)]
        if not ready:argv+=['--report-name',phase]
        try: call(argv,timeout=100)
        finally:
            if cidfile.exists():
                cid=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Malformed helper ID')
                found=call(['docker','inspect','--format','{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}',cid],required=False)
                if found.returncode==0:
                    row=json.loads(found.stdout);need(row['id']==cid and row['name']=='/'+name and row['image']==PYTHON and all((row['labels'] or {}).get(k)==v for k,v in labels.items()),'Helper ownership differs')
                    call(['docker','rm','-f',cid])
                need(not call(['docker','ps','-aq','--filter','name=^/'+name+'$']).stdout.strip(),'Helper remains')
                report['helpers'].append({'phase':phase,'id':cid,'retired':True});cidfile.unlink()
        if not ready:need(json.loads((output/(phase+'.json')).read_text())['passed'],'Actual migration phase failed')
    def stop_rename_disconnect(cid,image_id,destination):
        own(cid,image_id,CORE)
        call(['docker','stop','--time=10',cid]);call(['docker','rename',cid,destination]);call(['docker','network','disconnect',NETWORK,cid])
    def resume(cid,image_id,old_name):
        own(cid,image_id,old_name)
        call(['docker','network','connect','--alias','core-a',NETWORK,cid]);call(['docker','rename',cid,CORE]);call(['docker','start',cid])
    def schema():
        response=call(['docker','exec',PG,'pg_dump','-U','expertauth','-d','expertauth','--schema-only','--no-owner','--no-privileges','--no-comments'])
        # pg_dump's generated psql restriction nonce is not database schema.
        text=response.stdout.decode();clean='\n'.join(line for line in text.splitlines() if not re.fullmatch(r'\\(?:un)?restrict [A-Za-z0-9]+',line))
        return hashlib.sha256(clean.encode()).hexdigest()
    try:
        old=inspect('container',CORE);own(old['Id'],old['Image'],CORE)
        need(old['State']['Running'] and old['Image']!=image and inspect('image',TAG)['Id']==old['Image'],'Expected original running Core/tag')
        need(inspect('network',NETWORK)['Internal'] and set(old['NetworkSettings']['Networks'])=={NETWORK} and not old['HostConfig']['PortBindings'],'Private network boundary differs')
        mounts=old['Mounts'];need(all(m['Destination'] in ['/run/expertauth/config.yaml','/home/gradle/.gradle'] for m in mounts),'Unexpected original data mount')
        need(any(m['Destination']=='/run/expertauth/config.yaml' and m['Type']=='bind' and not m['RW'] and Path(m['Source']).resolve()==config.resolve() for m in mounts),'Original config binding differs')
        report['resources_before']=inventory();report['old_core']=state(old);report['database_before']=state(inspect('container',PG))
        need(report['database_before']['running'],'Database not running')
        report['schema_before_sha256']=schema()
        backup=call(['docker','exec',PG,'pg_dump','-U','expertauth','-d','expertauth','-Fc'])
        need(len(backup.stdout)<64*1024*1024,'Unexpected backup size')
        report['private_backup']=dict(report['commands'][-1]['stdout'],format='pg_dump custom; preserved, not restore-tested by this upgrade')
        call(['docker','logs','--tail','50000',old['Id']],required=False)
        fixture_attempted=True;helper('seed')
        stop_rename_disconnect(old['Id'],old['Image'],old_name);active='none'
        call(['docker','run','-d','--pull=never','--name',CORE,'--cidfile',str(cidfile),'--network',NETWORK,'--network-alias','core-a',
              '--label','org.expertauth.project=expert-auth','--label','org.expertauth.purpose=oss-foundation','--label','org.expertauth.upgrade-run='+run_id,
              '--memory=1g','--cpus=2','--pids-limit=256','--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
              '--tmpfs','/home/gradle/.gradle:rw,nosuid,noexec,size=16m','--mount',f'type=bind,source={config},target=/run/expertauth/config.yaml,readonly',image])
        new=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',new),'Malformed new Core ID');active='new'
        helper('ready-upgrade',ready=True);helper('upgraded')
        stop_rename_disconnect(new,image,new_name);active='none';resume(old['Id'],old['Image'],old_name);active='old'
        helper('ready-rollback',ready=True);helper('rollback')
        stop_rename_disconnect(old['Id'],old['Image'],old_name);active='none';resume(new,image,new_name);active='new'
        helper('ready-final',ready=True);helper('final');helper('cleanup');fixture_attempted=False
        report['schema_after_sha256']=schema();need(report['schema_after_sha256']==report['schema_before_sha256'],'Database schema changed')
        report['database_after']=state(inspect('container',PG));need(report['database_after']==report['database_before'],'Database process/mount state changed')
        actual=call(['docker','exec',new,'sh','-c','cd /opt/expertauth && find lib plugin licenses version.yaml'+(' native' if proof.get('native_argon2') else '')+' -type f -exec sha256sum {} +']).stdout.decode()
        files={line.split('  ',1)[1]:line.split('  ',1)[0] for line in actual.splitlines()}
        need(files==proof['installed_files'],'Running Core differs from installed qualified image')
        need(inputs=={p:sha(ROOT/p) for p in SOURCES} and all(sha(ROOT/p)==h for p,h in report['private_configuration'].items()),'Source or private configuration changed')
        need(inspect('image',TAG)['Id']==old['Image'],'Protected tag changed before promotion')
        call(['docker','image','tag',image,TAG]);need(inspect('image',TAG)['Id']==image,'Tag promotion failed')
        committed=True
        own(old['Id'],old['Image'],old_name);call(['docker','rm',old['Id']])
        old_image=inspect('image',old['Image'])
        need(not old_image.get('RepoTags') and not call(['docker','ps','-aq','--filter','ancestor='+old['Image']]).stdout.strip(),'Old runtime image still referenced')
        need(all(d.startswith('expertauth-oss-core@sha256:') for d in old_image.get('RepoDigests') or []),'Old image has unrelated digest references')
        call(['docker','image','rm','--no-prune',old['Image']]);report['old_image_retired']=old['Image']
        report['new_core']=state(own(new,image,CORE));report['installed_files_verified']=len(files)
        report['resources_after']=inventory()
        expected=dict(report['resources_before']);expected['containers']=sorted((set(expected['containers'])-{old['Id']})|{new});expected['images']=sorted((set(expected['images'])-{old['Image']})|{image})
        need(report['resources_after']==expected,'Unexpected final resource change')
        report['passed']=True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
        if old and not committed:
            try:
                if new is None and cidfile.exists():
                    new=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',new),'Malformed failed-launch Core ID')
                if new:
                    row=inspect('container',new)
                    own(new,image,row['Name'].removeprefix('/'))
                    if row['State']['Running']:call(['docker','stop','--time=5',new])
                    call(['docker','rm',new])
                row=inspect('container',old['Id']);own(old['Id'],old['Image'],row['Name'].removeprefix('/'))
                if NETWORK not in row['NetworkSettings']['Networks']:call(['docker','network','connect','--alias','core-a',NETWORK,old['Id']])
                if row['Name']!='/'+CORE:call(['docker','rename',old['Id'],CORE])
                if not row['State']['Running']:call(['docker','start',old['Id']])
                helper('ready-recovered',ready=True);report['rollback_restored']=True
                if fixture_attempted and (private/'fixture/fixture.json').exists():helper('cleanup-recovered',operation='cleanup');fixture_attempted=False
                if inspect('image',TAG)['Id']==image:call(['docker','image','tag',old['Image'],TAG])
            except Exception as failure:report['errors'].append('Rollback: '+(str(failure) if isinstance(failure,ValueError) else type(failure).__name__))
    finally:
        report['committed']=committed;report['fixture_cleanup_pending']=fixture_attempted
        report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'committed':committed,'errors':report['errors'],'report':str((output/'report.json').relative_to(ROOT))}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
