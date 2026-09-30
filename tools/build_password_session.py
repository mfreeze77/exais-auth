"""Offline bounded Core/plugin adaptation build; keep original sources and binaries intact."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
import zipfile
from build_core_reset import ROOT, CORE_REV, WEB, need, sha
from core_compiler_inputs import IMAGE, ARTIFACTS, compiler_inputs
from run_sdk_session_faults import inventory
from password_session_candidates import validate_pair, new_candidate
from patch_session_policy import REFRESH, VERIFY, patch_session, guarded_api
from patch_firebase_scrypt import PATH as FIREBASE, INPUT as JSON_INPUT, patch as patch_firebase, patch_input
from patch_password_upgrade import PATH as SIGN_IN, patch as patch_sign_in, BULK_PATH as BULK_IMPORT, patch_bulk

PG_REV = '0b68fd14ca10baee2d0e3c31466984fccfb36c8a'
SESSION = 'src/main/java/io/supertokens/session/Session.java'
SOURCES = ['tools/build_password_session.py', 'tools/build_core_reset.py', 'tools/core_compiler_inputs.py', 'tools/password_session_candidates.py', 'tools/patch_session_policy.py', 'tools/patch_firebase_scrypt.py', 'tools/patch_password_upgrade.py', ARTIFACTS] + [
    'engine-extensions/core-reset/src/io/expertauth/core/' + name + '.java' for name in
    ['AtomicPasswordReset', 'AtomicPasswordResetAPI', 'TransactionalSessionWriter', 'AtomicPasswordSession', 'AtomicPasswordSessionAPI', 'SessionPolicy', 'PasswordUpgrade']]
PROVIDER = 'engine-extensions/core-reset/postgresql/io/supertokens/storage/postgresql/ExpertAuthSessionWriter.java'
SOURCES.append(PROVIDER)

def patched_source(path, original):
    """Return (published filename, patched text) for one audited Core source path."""
    need('WithinOtelSpan' not in original, 'Source requires additional weaving review')
    if path==JSON_INPUT:
        patched=patch_input(original)
    elif path==FIREBASE:
        patched=patch_firebase(original)
    elif path==SIGN_IN:
        patched=patch_sign_in(original)
    elif path==BULK_IMPORT:
        patched=patch_bulk(original)
    elif path==WEB:
        marker='        addAPI(new ResetPasswordAPI(main));'; need(original.count(marker)==1,'Route anchor differs')
        patched=original.replace(marker, marker+'\n        addAPI(new io.expertauth.core.AtomicPasswordResetAPI(main, true));\n        addAPI(new io.expertauth.core.AtomicPasswordResetAPI(main, false));\n        addAPI(new io.expertauth.core.AtomicPasswordSessionAPI(main));\n        addAPI(new io.expertauth.core.GuardedRefreshSessionAPI(main));\n        addAPI(new io.expertauth.core.GuardedVerifySessionAPI(main));')
    elif path==SESSION:
        body_start=original.index('        validateAccessTokenValidityOverride(tenantIdentifier, main, accessTokenValidity);')
        start=original.rfind('    public static SessionInformationHolder createNewSession(',0,body_start)
        end=original.index('    @TestOnly',body_start)
        header=original[start:body_start]; body=original[body_start:end]
        need(header.count('@Nullable Long accessTokenValidity)')==1,'Session method boundary differs')
        wrapper=header+'        return createNewSessionWithWriter(tenantIdentifier, storage, main, recipeUserId, userDataInJWT, userDataInDatabase, enableAntiCsrf, version, useStaticKey, accessTokenValidity, null);\n    }\n\n'
        new_header=header.replace(' createNewSession(', ' createNewSessionWithWriter(').replace('@Nullable Long accessTokenValidity)', '@Nullable Long accessTokenValidity, io.expertauth.core.AtomicPasswordSession.Insert writer)')
        a=body.index('        StorageUtils.getSessionStorage(storage)'); b=body.index('\n\n        emitSessionCreatedEvent',a)
        existing=body[a:b]
        replacement='        if (writer == null) {\n'+existing+'\n        } else {\n            writer.insert(sessionHandle, recipeUserId, primaryUserId, Utils.hashSHA256(Utils.hashSHA256(refreshToken.token)), userDataInDatabase, refreshToken.expiry, userDataInJWT, refreshToken.createdTime, useStaticKey);\n        }'
        patched=original[:start]+wrapper+new_header+body[:a]+replacement+body[b:]+original[end:]
        patched=patch_session(patched)
    else:
        patched=guarded_api(original,path==REFRESH)
    patched += '\n/* Modified by ExpertAuth contributors (2026): private password-session/reset API registration or transaction-aware session insertion callback. Original token minting and licensing checks retained. */\n'
    filename=Path(path).name
    if path in [REFRESH,VERIFY]:filename='Guarded'+filename
    return filename, patched

def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--name', required=True)
    parser.add_argument('--firebase-scrypt-bc', action='store_true', help='Use existing Bouncy Castle scrypt with UTF-8 Firebase verification')
    parser.add_argument('--password-upgrade', action='store_true', help='Route upstream sign-in/import through PasswordUpgrade (on-login rehash, bounded import structure); requires --firebase-scrypt-bc')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--verify-existing', help='Recompile and compare an existing exact candidate without replacing it')
    mode.add_argument('--candidate-from', help='Build one new immutable pair while preserving this exact previous build')
    args = parser.parse_args(); need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.name), 'Invalid build name')
    need(not args.password_upgrade or args.firebase_scrypt_bc, 'PasswordUpgrade requires the UTF-8 reader profile (--firebase-scrypt-bc)')
    out = ROOT / 'evidence/operations/password-session-build' / args.name
    private = (ROOT / '.runtime/password-session-build' / args.name).resolve()
    cache = (ROOT / '.cache/password-session').resolve()
    need(not out.exists() and not private.exists(), 'Preserve previous evidence and scratch')
    prior=None
    previous_name=args.verify_existing or args.candidate_from
    if previous_name:
        need(re.fullmatch('[A-Za-z0-9_-]{1,54}',previous_name),'Invalid prior build name')
        previous_path=ROOT/'evidence/operations/password-session-build'/previous_name/'report.json'
        previous=json.loads(previous_path.read_text())
        previous_cache=validate_pair(ROOT,previous)
        if args.verify_existing:
            prior=previous;cache=previous_cache
        else:
            cache=new_candidate(ROOT,args.name,previous)
    else:
        need(not cache.exists() and not list((ROOT/'.cache').glob('password-session*')), 'Preserve previous candidate')
    need(private.parent == (ROOT / '.runtime/password-session-build').resolve() and cache.parent == ROOT / '.cache', 'Unsafe build directory')
    out.mkdir(parents=True); private.mkdir(parents=True); cache.mkdir(exist_ok=bool(prior))
    run_id = uuid.uuid4().hex; name = 'expertauth-password-session-compile-' + run_id[:10]
    labels = {'org.expertauth.project':'expert-auth', 'org.expertauth.purpose':'password-session-compile', 'org.expertauth.run':run_id}
    report = {'kind':'password-session-build', 'passed':False, 'runtime_qualified':False, 'foundation_passed':False,
              'started':datetime.now(timezone.utc).isoformat(), 'inputs':{p:sha(ROOT/p) for p in SOURCES},
              'commands':[], 'errors':[], 'images_built':0, 'downloads':0, 'new_volumes':0, 'upstream':[], 'candidates':[]}
    report['firebase_scrypt_profile'] = 'bouncycastle-utf8-v1' if args.firebase_scrypt_bc else 'original-lambdaworks-ascii'
    report['password_upgrade_profile'] = 'expertauth-password-upgrade-2' if args.password_upgrade else 'atomic-session-only'
    if previous_name:
        report['previous_build']={'path':previous_path.relative_to(ROOT).as_posix(),'sha256':sha(previous_path),
                                  'mode':'verify' if prior else 'new-candidate','candidates':previous['candidates']}
    for p in SOURCES:
        target=out/'source-snapshots'/p; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes((ROOT/p).read_bytes())
    def persist(): (out/'report.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    def call(argv, required=True, timeout=35):
        i=len(report['commands'])+1
        result=subprocess.run(argv,capture_output=True,timeout=timeout,cwd=ROOT)
        for stream in ['stdout','stderr']: (out/f'command-{i:03d}.{stream}').write_bytes(getattr(result,stream))
        report['commands'].append({'argv':argv,'exit_code':result.returncode,
            **{s:{'bytes':len(getattr(result,s)),'sha256':hashlib.sha256(getattr(result,s)).hexdigest()} for s in ['stdout','stderr']}})
        persist(); need(not required or result.returncode==0,'Command failed: '+str(i)); return result
    before=None
    try:
        before=report['resources_before']=inventory()
        compiler=compiler_inputs(); report['compiler']=compiler
        image=json.loads(call(['docker','image','inspect',IMAGE]).stdout)[0]
        compiler_id=image['Id']; report['compiler_image_id']=compiler_id
        need(re.fullmatch('sha256:[0-9a-f]{64}',compiler_id) and set(image['Config'].get('Volumes') or {})=={'/home/gradle/.gradle'},'Cached pinned compiler image differs')
        for path in [WEB, SESSION, REFRESH, VERIFY, *([FIREBASE,JSON_INPUT] if args.firebase_scrypt_bc else []), *([SIGN_IN, BULK_IMPORT] if args.password_upgrade else [])]:
            src=ROOT/'.cache/reuse-audit/source/supertokens__supertokens-core'/CORE_REV/path
            manifest=json.loads((ROOT/'reuse/files/supertokens__supertokens-core.json').read_text())
            row=next(r for r in manifest['files'] if r['source_path']==path)
            need(sha(src)==row['sha256'] and b'Apache License, Version 2.0' in src.read_bytes(), 'Audited Core source differs')
            original=src.read_text()
            filename, patched = patched_source(path, original)
            (private/filename).write_bytes(patched.encode()); (out/filename).write_bytes(patched.encode())
            report['upstream'].append({'repository':'supertokens/supertokens-core','commit':CORE_REV,'path':path,'sha256':row['sha256'],
                'modified_sha256':sha(private/filename),'license':'Apache-2.0'})
        artifacts=json.loads((ROOT/'evidence/build/oss-core/artifacts.json').read_text())
        bases={}
        for component, needle in [('core','supertokens-core/build/libs/core-12.2.0.jar'),('postgresql','supertokens-postgresql-plugin/build/libs/')]:
            options=[r for r in artifacts if r['path']==needle or (r['path'].startswith(needle) and r['path'].endswith('.jar') and 'sources' not in r['path'])]
            need(len(options)==1,'Ambiguous original JAR')
            row=options[0]; p=ROOT/'.cache/engine-build'/row['path']; need(sha(p)==row['sha256'],'Original source-built JAR differs'); bases[component]=p
        argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(private/'container.cid'),'--network=none',
              '--read-only','--memory=512m','--cpus=2','--pids-limit=128','--cap-drop=ALL','--security-opt=no-new-privileges',
              '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
              '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m','--tmpfs','/home/gradle/.gradle:rw,nosuid,nodev,noexec,size=1m',
              '--mount',f'type=bind,source={private},target=/out','--mount',compiler['mount']]
        for k,v in labels.items(): argv+=['--label',k+'='+v]
        java_files=[p for p in SOURCES if p.endswith('.java')]
        for p in java_files: argv+=['--mount',f'type=bind,source={ROOT/p},target=/src/{Path(p).name},readonly']
        script="java --version && javac --version && javap -p -classpath "+compiler['core_path']+" io.supertokens.session.Session && javac -proc:none --release 21 -encoding UTF-8 -cp '"+compiler['classpath']+"' -d /out/classes /out/*.java /src/*.java"
        result=call(argv+['--entrypoint','sh',compiler_id,'-eu','-c',script],timeout=100)
        need(b'ajc$' not in result.stdout,'Original Session requires weaving')
        compiled={p.relative_to(private/'classes').as_posix():p.read_bytes() for p in (private/'classes').rglob('*.class')}
        report['compiled_classes']={k:hashlib.sha256(v).hexdigest() for k,v in compiled.items()}; persist()
        provider='io/supertokens/storage/postgresql/ExpertAuthSessionWriter.class'
        need(provider in compiled and 'io/expertauth/core/AtomicPasswordSession.class' in compiled,'Required compiled classes missing')
        for component,base in bases.items():
            replacements={k:v for k,v in compiled.items() if (k==provider)==(component=='postgresql')}
            if component=='postgresql': replacements['META-INF/services/io.expertauth.core.TransactionalSessionWriter']=b'io.supertokens.storage.postgresql.ExpertAuthSessionWriter\n'
            target=(private if prior else cache)/base.name; members=[]
            with zipfile.ZipFile(base) as old, zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as new:
                need(old.testzip() is None and len(old.namelist())==len(set(old.namelist())),'Original JAR invalid')
                for entry in old.infolist():
                    original=old.read(entry); value=replacements.pop(entry.filename,original); new.writestr(entry,value)
                    members.append({'path':entry.filename,'sha256':hashlib.sha256(value).hexdigest(),'original_sha256':hashlib.sha256(original).hexdigest(),'changed':value!=original})
                for key,value in sorted(replacements.items()):
                    need(key.startswith(('io/expertauth/core/','io/supertokens/session/Session$','io/supertokens/storage/postgresql/ExpertAuthSessionWriter','META-INF/services/io.expertauth.')),'Unexpected added class')
                    entry=zipfile.ZipInfo(key,date_time=(1980,1,1,0,0,0)); entry.external_attr=0o100644<<16; entry.compress_type=zipfile.ZIP_DEFLATED
                    new.writestr(entry,value); members.append({'path':key,'sha256':hashlib.sha256(value).hexdigest(),'added':True})
            with zipfile.ZipFile(target) as check: need(check.testzip() is None and len(check.namelist())==len(members),'Candidate JAR invalid')
            if prior:
                expected=next(r for r in prior['candidates'] if r['component']==component)
                need(sha(target)==expected['sha256'] and sha(cache/base.name)==expected['sha256'],'Recompiled binary differs from tested candidate')
                target=cache/base.name
            (out/(component+'-members.json')).write_bytes((json.dumps(members,indent=2)+'\n').encode())
            report['candidates'].append({'component':component,'path':target.relative_to(ROOT).as_posix(),'bytes':target.stat().st_size,'sha256':sha(target),'original_sha256':sha(base),
                'changed':[m['path'] for m in members if m.get('changed')],'added':[m['path'] for m in members if m.get('added')]})
        if prior: report['byte_identical_to_build']=args.verify_existing
        report['build_passed']=True
    except Exception as error: report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            cidfile=private/'container.cid'
            if cidfile.exists():
                cid=cidfile.read_text().strip(); need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid compiler CID')
                state=call(['docker','inspect','--format','{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}',cid],required=False)
                if state.returncode==0:
                    state=json.loads(state.stdout); need(state['id']==cid and state['name']=='/'+name and state['image']==compiler_id and all((state['labels'] or {}).get(k)==v for k,v in labels.items()),'Compiler ownership differs')
                    call(['docker','rm','-f',cid])
            need(not call(['docker','ps','-aq','--filter','name=^/'+name+'$']).stdout.strip(),'Compiler remains')
            report['container_retired']=True
            paths=list(private.rglob('*')); need(all(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400 and p.resolve().is_relative_to(private) for p in paths),'Unsafe scratch cleanup')
            for p in paths:
                if p.is_file(): p.unlink()
            for p in sorted((p for p in paths if p.is_dir()),key=lambda p:len(p.parts),reverse=True): p.rmdir()
            private.rmdir(); report['private_scratch_removed']=True
            if not list(cache.iterdir()): cache.rmdir()
            report['resources_after']=inventory(); report['resources_unchanged']=before==report['resources_after']
            need(report['resources_unchanged'] and report['inputs']=={p:sha(ROOT/p) for p in SOURCES},'Source or resource drift')
            if previous_name:
                need(validate_pair(ROOT,previous)==previous_cache and sha(previous_path)==report['previous_build']['sha256'], 'Previous candidate changed')
                report['previous_pair_preserved']=True
        except Exception as error: report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
        report['passed']=not report['errors'] and report.get('build_passed') is True
        report['finished']=datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'passed':report['passed'],'errors':report['errors'],'container_retired':report.get('container_retired'),'candidates':report['candidates']}))
    return 0 if report['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
