"""Exercise actual installed native startup success and configuration/integrity refusals."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
from atomic_core_identity import require_atomic_core
from install_native_argon2 import ROOT,native_build
from run_sdk_session_faults import inspect,inventory

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True);parser.add_argument('--image',required=True);parser.add_argument('--native-build',required=True);args=parser.parse_args()
    need(re.fullmatch('[a-z0-9-]{1,48}',args.name) and re.fullmatch('sha256:[0-9a-f]{64}',args.image),'Exact image and fresh name required')
    image=inspect('image',args.image);require_atomic_core(image);_,build,_=native_build(args.native_build)
    output=ROOT/'evidence/operations/native-argon2-startup'/args.name;private=(ROOT/'.runtime/native-argon2-startup'/args.name).resolve()
    need(not output.exists() and not private.exists() and private.parent==(ROOT/'.runtime/native-argon2-startup').resolve(),'Fresh bounded evidence/scratch required')
    output.mkdir(parents=True);private.mkdir(parents=True)
    for case in ('missing','corrupt'):
        directory=private/case;directory.mkdir()
        (directory/'start.sh').write_bytes((ROOT/'deploy/native-argon2-start.sh').read_bytes().replace(b'@ARGON2_SHA256@',build['candidate']['sha256'].encode()))
        (directory/'NativeArgon2Check.java').write_bytes((ROOT/'deploy/NativeArgon2Check.java').read_bytes())
    (private/'corrupt/libargon2.so').write_bytes(b'corrupt owned native test fixture\n')
    (private/'bundled.jar').write_bytes(b'presence-only owned rejection fixture\n')
    run=uuid.uuid4().hex;labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'native-startup-qualification','org.expertauth.run':run}
    report={'kind':'actual-native-startup-qualification','started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,
        'image':args.image,'images_built':0,'image_downloads':0,'new_volumes':0,'published_ports':[],
        'authentication_tests':False,'independent_review':False,'resources_before':inventory(),'rows':[],'commands':[],'errors':[],
        'inputs':{p:sha(ROOT/p) for p in ('tools/qualify_native_startup.py','tools/install_native_argon2.py','deploy/native-argon2-start.sh','deploy/NativeArgon2Check.java')}}
    def persist():(output/'report.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    cases=[('missing',78,'NATIVE_ARGON2_INTEGRITY_FAILED',['--mount',f'type=bind,source={private/"missing"},target=/opt/expertauth/native,readonly']),
           ('corrupt',78,'NATIVE_ARGON2_INTEGRITY_FAILED',['--mount',f'type=bind,source={private/"corrupt"},target=/opt/expertauth/native,readonly']),
           ('bundled',78,'NATIVE_ARGON2_BUNDLED_LIBRARY_PRESENT',['--mount',f'type=bind,source={private/"bundled.jar"},target=/opt/expertauth/lib/argon2-jvm-2.11.jar,readonly'])]
    cases += [(key.lower(),78,'NATIVE_ARGON2_RUNTIME_OPTIONS_REJECTED',['--env',key+'=-Djna.library.path=/unqualified']) for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')]
    cases += [('healthy',0,'NATIVE_ARGON2_SELF_TEST_PASSED',[])]
    try:
        for index,(case,expected,marker,extra) in enumerate(cases):
            name='expertauth-native-start-'+run[:10]+'-'+str(index);cidfile=private/(str(index)+'.cid')
            command=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(cidfile),'--network=none',
                     '--memory=384m','--cpus=2','--pids-limit=128','--cap-drop=ALL','--security-opt=no-new-privileges',
                     '--tmpfs','/home/gradle/.gradle:rw,nosuid,noexec,size=1m','--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false']
            for key,value in labels.items():command+=['--label',key+'='+value]
            command+=extra+[args.image,'sh','/opt/expertauth/native/start.sh','--check-native-only']
            row={'id':'NATIVE-START-'+case.upper(),'status':'failed','expected_exit':expected,'container_retired':False};report['rows'].append(row)
            record={'argv':command,'exit_code':None,'timed_out':False};report['commands'].append(record);persist()
            try:
                result=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=55);record['exit_code']=result.returncode
                for stream in ('stdout','stderr'):
                    path=output/(case+'.'+stream);path.write_bytes(getattr(result,stream));record[stream]={'sha256':sha(path),'bytes':path.stat().st_size}
                actual=(result.stdout+result.stderr).decode('utf-8',errors='replace')
                need(result.returncode==expected and marker in actual and (expected==0 or 'NATIVE_ARGON2_SELF_TEST_PASSED' not in actual),'Installed startup outcome differs: '+case)
                row['status']='passed'
            except subprocess.TimeoutExpired:record['timed_out']=True;raise
            finally:
                if cidfile.exists():
                    cid=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid helper CID');row['container_id']=cid
                    found=subprocess.run(['docker','ps','-aq','--no-trunc','--filter','id='+cid],capture_output=True,check=True,timeout=30).stdout.strip()
                    if found:
                        state=inspect('container',cid);need(state['Id']==cid and state['Name']=='/'+name and state['Image']==args.image and all(state['Config']['Labels'].get(k)==v for k,v in labels.items()),'Cleanup ownership mismatch')
                        subprocess.run(['docker','rm','-f',cid],check=True,capture_output=True,timeout=30)
                    need(not subprocess.check_output(['docker','ps','-aq','--filter','id='+cid],timeout=30).strip(),'Startup helper remains')
                    cidfile.unlink();row['container_retired']=True
                persist()
        report['work_passed']=True
    except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            report['resources_after']=inventory();need(report['resources_after']==report['resources_before'],'Resource changes remain; preserve scratch')
            paths=list(private.rglob('*'));need(all(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400 and p.resolve().is_relative_to(private) for p in [private,*paths]),'Unsafe startup scratch')
            for p in paths:
                if p.is_file():p.unlink()
            for p in sorted((p for p in paths if p.is_dir()),key=lambda p:len(p.parts),reverse=True):p.rmdir()
            private.rmdir();report['scratch_retired']=True
        except Exception as error:report['errors'].append('Cleanup: '+str(error))
        report['passed']=report.get('work_passed') is True and report.get('scratch_retired') is True and len(report['rows'])==7 and all(r['status']=='passed' and r['container_retired'] for r in report['rows']) and not report['errors']
        report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'report':output.relative_to(ROOT).as_posix(),'errors':report['errors']}));return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
