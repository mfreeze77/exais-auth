"""Rebuild Argon2 from exact ZIP members using the cached compiler, then retire scratch.

This proves native source/build extraction, not a fresh-host full deployment or
another run of the Core authentication cases. It creates no image or volume.
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
import zipfile
from run_sdk_session_faults import ROOT, inventory

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--zip',required=True);args=parser.parse_args()
    archive_path=(ROOT/args.zip).resolve()
    need(archive_path.parent==(ROOT/'artifacts').resolve() and re.fullmatch('expertauth-partial-checkpoint-[0-9a-f]{12}\\.zip',archive_path.name),'Generated checkpoint ZIP required')
    need(archive_path.is_file() and not archive_path.is_symlink(),'Regular ZIP required')
    evidence=archive_path.with_suffix('.native-extraction');need(not evidence.exists(),'Preserve extraction evidence');evidence.mkdir()
    private=(ROOT/'.runtime/extracted-native'/uuid.uuid4().hex).resolve()
    need(private.parent==(ROOT/'.runtime/extracted-native').resolve() and not private.exists(),'Fresh bounded scratch required');private.mkdir(parents=True)
    extracted=private/'source';extracted.mkdir()
    report={'kind':'fresh-zip-native-source-build','started':datetime.now(timezone.utc).isoformat(),'passed':False,'complete':False,
            'zip':archive_path.name,'zip_sha256':sha(archive_path),'tool_sha256':sha(Path(__file__)),
            'images_built':0,'image_downloads':0,'new_volumes':0,'authentication_tests':False,'independent_review':False,
            'members':[],'errors':[],'resources_before':inventory()}
    def persist():(evidence/'report.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    try:
        validated=json.loads(archive_path.with_suffix('.validation.json').read_text())
        need(validated['sha256']==report['zip_sha256'],'Validated ZIP differs')
        prefix='evidence/reuse/native-correspondence/argon2/'
        exact={'tools/build_native_argon2.py','tools/run_sdk_session_faults.py',prefix+'native-source-request.json',
               prefix+'native-metadata-01/commit.json',prefix+'native-metadata-01/tree.json'}
        with zipfile.ZipFile(archive_path) as archive:
            need(archive.testzip() is None,'ZIP CRC mismatch')
            manifest=json.loads(archive.read('expert-auth/CHECKPOINT_MANIFEST.json'))
            need(manifest['kind']=='PARTIAL_SOURCE_CHECKPOINT' and manifest['commit']==validated['bundle_clone_head'],'Source commit mismatch')
            entries={r['path']:r for r in manifest['files']};wanted=sorted(p for p in entries if p in exact or p.startswith(prefix+'native-source/'))
            need(exact.issubset(wanted) and len(wanted)==75,'Native source extraction membership differs')
            for name in wanted:
                body=archive.read('expert-auth/'+name);row=entries[name]
                need(len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'],'Source member differs')
                target=(extracted/name).resolve();need(target.is_relative_to(extracted),'Extraction path escaped')
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
                report['members'].append({'path':name,'sha256':row['sha256'],'bytes':len(body)})
            original=json.loads(archive.read('expert-auth/'+prefix+'native-build/linux-03/report.json'))
        report['source_commit']=manifest['commit']
        command=[sys.executable,'-B','tools/build_native_argon2.py','--name','extracted-01']
        report['command']=command;persist()
        with (evidence/'stdout.txt').open('xb') as stdout,(evidence/'stderr.txt').open('xb') as stderr:
            process=subprocess.Popen(command,cwd=extracted,stdout=stdout,stderr=stderr)
            report['child_pid']=process.pid;persist();report['exit_code']=process.wait()
        child_path=extracted/prefix/'native-build/extracted-01/report.json'
        need(child_path.is_file(),'Native builder did not retain its result')
        child=json.loads(child_path.read_text());report['child_report_sha256']=sha(child_path)
        for path in child_path.parent.iterdir():
            need(path.is_file() and not path.is_symlink(),'Unexpected native evidence entry')
            (evidence/path.name if path.name!='report.json' else evidence/'build-report.json').write_bytes(path.read_bytes())
        need(report['exit_code']==0 and child['passed'] and child['container_retired'],'Extracted native build failed')
        need(child['candidate']==original['candidate'],'Fresh extracted native library differs from Core-tested candidate')
        report.update(work_passed=True,native_sha256=child['candidate']['sha256'],native_bytes=child['candidate']['bytes'],
                      upstream_kat_comparisons=child['upstream_kat_comparisons'],upstream_api_pass_lines=child['upstream_api_pass_lines'],
                      container_retired=child['container_retired'])
    except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            after=inventory();need(after==report['resources_before'],'Resources differ; preserve scratch for active child diagnosis')
            report['resources_after']=after
            paths=list(private.rglob('*'))
            need(all(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400 and p.resolve().is_relative_to(private) for p in [private,*paths]),'Unsafe extraction cleanup')
            report['retired_scratch_bytes']=sum(p.stat().st_size for p in paths if p.is_file())
            for p in paths:
                if p.is_file():p.unlink()
            for p in sorted((p for p in paths if p.is_dir()),key=lambda p:len(p.parts),reverse=True):p.rmdir()
            private.rmdir();report['scratch_retired']=True
        except Exception as error:report['errors'].append('Cleanup: '+str(error))
        report['passed']=report.get('work_passed') is True and report.get('scratch_retired') is True and not report['errors']
        report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'report':(evidence/'report.json').relative_to(ROOT).as_posix(),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
