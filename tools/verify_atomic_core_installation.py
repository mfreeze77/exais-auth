"""Check installed Core source, binary, runtime, migration and cleanup correspondence.

Read-only apart from one new report. Integrity checks do not create additional
authentication tests or replace foundation/native/provider/independent review.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile
from atomic_core_identity import TAG, require_atomic_core
from run_sdk_session_faults import ROOT, inspect, inventory

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9_-]{1,35}',args.name):raise ValueError('Invalid build name')
    folder=ROOT/'evidence/operations/atomic-core-image'/args.name
    output=folder/'correspondence.json'
    if output.exists():raise ValueError('Preserve prior correspondence report')
    report={'kind':'installed-core-evidence-correspondence','passed':False,'complete':False,'independent_review':False,
            'started':datetime.now(timezone.utc).isoformat(),'tool_sha256':sha(Path(__file__)),'checks':[],'reports':{}}
    def need(ok,label):
        report['checks'].append({'check':label,'passed':bool(ok)})
        if not ok:raise ValueError(label)
    def bound(path):
        report['reports'][path.relative_to(ROOT).as_posix()]=sha(path);return read(path)
    def source_rows(rows,snapshots):
        for path,h in rows.items():need(sha(ROOT/path)==h==sha(snapshots/path),'Current/captured source '+path)
    def private_commands(rows,private):
        for i,row in enumerate(rows,1):
            for stream in ['stdout','stderr']:
                record=row[stream];path=ROOT/record['path'] if 'path' in record else private/f'command-{i:03d}.{stream}'
                need(path.resolve().is_relative_to((ROOT/'.runtime').resolve()) and sha(path)==record['sha256'] and path.stat().st_size==record['bytes'],f'Private command {i} {stream}')
    try:
        build=bound(folder/'report.json');qualified=bound(folder/'qualification.json')
        need(build['passed'] and build['installed_qualification_passed'] and qualified['installed_qualification_passed'] and
             build['candidate_image_id']==qualified['candidate_image_id'],'Build and immutable qualification agree')
        source_rows(build['source_inputs'],folder/'source-snapshots')
        for row in build['commands']:
            for stream in ['stdout','stderr']:
                item=row[stream];p=folder/item['path'];need(sha(p)==item['sha256'] and p.stat().st_size==item['bytes'],'Build command bytes '+item['path'])
        compiled_path=ROOT/'evidence/operations/password-session-build'/build['session_build']/'report.json'
        compiled=bound(compiled_path)
        need(compiled['passed'] and compiled['byte_identical_to_build']=='compile-03','Standalone JDK recompiles the previously tested bytes')
        source_rows(compiled['inputs'],compiled_path.parent/'source-snapshots')
        need(compiled['resources_unchanged'] and compiled['container_retired'] and compiled['private_scratch_removed'],'Compiler cleanup')
        for artifact in compiled['candidates']:
            jar=ROOT/artifact['path'];members=read(compiled_path.parent/(artifact['component']+'-members.json'))
            with zipfile.ZipFile(jar) as archive:
                need(sha(jar)==artifact['sha256'] and archive.testzip() is None and len(archive.namelist())==len(members),'Candidate JAR '+artifact['component'])
                need(all(hashlib.sha256(archive.read(row['path'])).hexdigest()==row['sha256'] for row in members),'Every compiled member '+artifact['component'])
        for kind in ['core_test','node_test']:
            artifact=build[kind];parent_path=ROOT/artifact['path'];parent=bound(parent_path)
            need(sha(parent_path)==artifact['sha256'] and parent['passed'] and parent['installed_core_image']==build['candidate_image_id'],'Installed parent '+kind)
            source_rows(parent['inputs'],parent_path.parent/'source-snapshots')
            private_commands(parent['commands'],ROOT/'.runtime/atomic-reset'/parent_path.parent.name)
            need(parent['resources_unchanged'] and parent['source_unchanged'] and not parent['source_database_contacted'],'Parent resource/source preservation '+kind)
            need({r['id'] for r in parent['created_containers']}=={r['id'] for r in parent['retired_containers']},'All parent containers retired '+kind)
            for role,mounts in parent['installed_core_mounts'].items():need(all(not m['Destination'].startswith('/opt/expertauth/') for m in mounts),'No installed Core overlays '+role)
            if kind=='core_test':
                for file,key in [('probe-report.json','probe_sha256'),('password-session-report.json','password_session_probe_sha256')]:
                    p=parent_path.parent/file;actual=bound(p)
                    need(sha(p)==parent[key] and actual['subset_passed'] and len(actual['rows'])==8 and all(r['status']=='passed' for r in actual['rows']),'Eight actual Core cases '+file)
            else:
                p=ROOT/parent['node_child']['path'];child=bound(p)
                need(sha(p)==parent['node_child']['sha256'] and child['passed'] and child['installed_image_tested'] and
                     child['core_adaptation']['installed_core_image']==build['candidate_image_id'] and child['images']['node']==build['node_image'],'Exact installed Core/Node child')
                source_rows(child['inputs'],p.parent/'source-snapshots');private_commands(child['commands'],ROOT/'.runtime/password-reset'/p.parent.name)
                need(child['resources_restored'] and child['source_processes_and_mounts_unchanged'] and
                     {r['id'] for r in child['created_containers']}=={r['id'] for r in child['retired_containers']},'All installed Node child resources restored')
                for filename,count in [('probe-results.json',18),('browser-results.json',9)]:
                    actual=bound(p.parent/filename);need(len(actual['rows'])==count and all(r['status']=='passed' for r in actual['rows']),'Actual installed Node cases '+filename)
                tls=bound(p.parent/'tls-results.json');need(tls['passed'] and len(tls['checks'])==10 and all(r['passed'] for r in tls['checks']),'Ten actual TLS cases')
                for role,count,code,status in [('good',38,200,'OK'),('missing-writer',1,503,'PASSWORD_SESSION_REJECTED')]:
                    rows=[json.loads(line) for line in (p.parent/'wire'/(role+'.jsonl')).read_text().splitlines()]
                    need(len(rows)==count and all(r['path']=='/expertauth/password/session' and r['http']==code and r['status']==status and
                         set(r)=={'path','http','status','policy'} for r in rows),'Bounded actual session wire '+role)
        replacement_path=ROOT/build['replacement']['path'];replacement=bound(replacement_path)
        need(sha(replacement_path)==build['replacement']['sha256'] and replacement['passed'] and replacement['committed'] and
             not replacement['fixture_cleanup_pending'] and replacement['image_report']['sha256']==sha(folder/'qualification.json'),'Successful exact replacement qualification')
        source_rows(replacement['inputs'],replacement_path.parent/'source-snapshots')
        private_commands(replacement['commands'],ROOT/'.runtime/atomic-core-replacement'/args.name)
        for phase,count in [('seed',1),('upgraded',4),('rollback',4),('final',4),('cleanup',1)]:
            actual=bound(replacement_path.parent/(phase+'.json'))
            need(actual['passed'] and len(actual['rows'])==count and all(r['status']=='passed' for r in actual['rows']) and actual['original_identity_count']==52,'Actual migration/rollback phase '+phase)
        need(replacement['schema_before_sha256']==replacement['schema_after_sha256'] and replacement['database_before']==replacement['database_after'],'Database schema/process/mount preservation')
        need(len(replacement['helpers'])==8 and all(r['retired'] for r in replacement['helpers']),'All upgrade helpers retired')
        for p,h in replacement['private_configuration'].items():need(sha(ROOT/p)==h,'Preserved private configuration '+p)
        notices=bound(folder/'notice-manifest.json')
        need(sha(folder/'notice-manifest.json')==build['installed_files']['licenses/manifest.json'] and
             all(sha(ROOT/p)==h for p,h in notices['input_sha256'].items()),'Notice package binds current inputs')
        bom=bound(folder/'adaptation-runtime.cdx.json')
        need(len(bom['components'])==87 and not notices['full_distribution_approved'],'87-component scope preserves licensing limits')
        current=inspect('image',TAG);require_atomic_core(current)
        need(current['Id']==build['candidate_image_id']==replacement['new_image'],'Current owned image matches qualification')
        actual=subprocess.check_output(['docker','exec','expertauth-oss-core-a','sh','-c','cd /opt/expertauth && find lib plugin licenses version.yaml -type f -exec sha256sum {} +'],timeout=30).decode()
        files={line.split('  ',1)[1]:line.split('  ',1)[0] for line in actual.splitlines()}
        need(files==build['installed_files'],'Every running JAR and notice file matches')
        need(inventory()==replacement['resources_after']==build['resources_after'],'Full final resource inventory including untagged images')
        need(subprocess.run(['docker','image','inspect',replacement['old_image_retired']],capture_output=True,timeout=20).returncode!=0,'Old runtime image retired')
        need(build['context_removed'] and build['private_scratch_removed'],'Build scratch removed')
        need(not build['foundation_passed'] and not build['full_distribution_approved'] and not replacement['complete'],'Full gates remain unapproved')
        report['passed']=True
    except Exception as error:report['error']=str(error) if isinstance(error,ValueError) else type(error).__name__
    report['finished']=datetime.now(timezone.utc).isoformat();output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'error':report.get('error'),'complete':False}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
