"""Verify recorded source/log/runtime correspondence; not another auth test run."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
from run_sdk_session_faults import inspect,inventory
from node_runtime_identity import TAG,require_owned_node
from atomic_core_identity import current_core_image

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())

def main():
    output=ROOT/'evidence/foundation/refresh-grace/evidence-validation-01.json'
    if output.exists():raise ValueError('Preserve prior correspondence evidence')
    checks=[]
    def check(label,value):
        checks.append({'check':label,'passed':bool(value)})
        if not value:raise ValueError(label)
    report={'kind':'refresh-grace-evidence-correspondence','started':datetime.now(timezone.utc).isoformat(),
        'passed':False,'complete':False,'independent_review':False,'authentication_tests_executed':False,
        'tool_sha256':sha(Path(__file__)),'checks':checks,'errors':[]}
    try:
        current_core=current_core_image();current_node=inspect('image',TAG);require_owned_node(current_node)
        check('current installed Node pin',current_node['Id']=='sha256:e02ab9bcd78eb1e2f24d8ba7dc0a6424ec98261ba192f205d11f5aed291fed55')
        build_path=ROOT/'evidence/operations/node-image-build/cdi56-grace-01/report.json';build=read(build_path)
        check('installed image builder and both qualification children pass',build['passed'] and build['image_promoted'] and
            build['refresh_grace_qualification_required'] and build['candidate_image_id']==current_node['Id'] and
            build['reset_child']['exit_code']==build['refresh_grace_child']['exit_code']==0)
        check('previous image retired',build['retired_previous_image'] not in inventory()['images'])
        base=ROOT/'evidence/foundation/refresh-grace'
        for name in ('run-01','installed-cdi56-grace-01'):
            directory=base/name;lab=read(directory/'report.json');private=ROOT/'.runtime/refresh-grace'/name
            check(name+' actual lab passed without full claims',lab['passed'] and not lab['foundation_passed'] and not lab['sdk_qualified'] and not lab['complete'])
            check(name+' same installed Core',lab['images']['core']==current_core and not lab['source_database_contacted'])
            check(name+' resource and source preservation',lab['resources_unchanged'] and lab['source_unchanged'] and lab['inputs_unchanged'])
            check(name+' no persistent resources introduced',lab['images_built']==lab['image_downloads']==lab['new_volumes']==lab['new_networks']==0 and not lab['published_ports'])
            check(name+' all exact owned helpers retired',len(lab['created_containers'])==(5 if name=='run-01' else 6) and
                {r['id'] for r in lab['created_containers']}=={r['id'] for r in lab['retired_containers']} and
                not {r['id'] for r in lab['created_containers']}.intersection(inventory()['containers']))
            check(name+' private configuration unchanged',sha(private/'secrets/core.yaml')==lab['configuration_sha256'])
            for path,digest in lab['inputs'].items():
                copied=directory/'source-snapshots'/path.replace('.cache/engine-build/','audited-upstream/')
                check(name+' recorded producer '+path,sha(copied)==digest)
                # The Core-only runner later gained the separate Node mode. Its
                # original producer is captured above; its actual probe/engine
                # inputs must still match, as must every installed-run input.
                if name!='run-01' or path!='tools/run_refresh_grace_lab.py':
                    check(name+' current source '+path,sha(ROOT/path)==digest)
            for i,command in enumerate(lab['commands'],1):
                for stream in ('stdout','stderr'):
                    path=private/f'command-{i:03d}.{stream}';record=command[stream]
                    check(f'{name} private command {i} {stream}',path.stat().st_size==record['bytes'] and sha(path)==record['sha256'])
            for role,mounts in lab['installed_mounts'].items():
                check(name+' installed Core without JAR overlays '+role,not any(m['Destination'].startswith('/opt/expertauth/') for m in mounts))
        core=read(base/'run-01/probe-report.json')
        check('twelve real Core cases',core['passed'] and len(core['rows'])==12 and all(r['status']=='passed' for r in core['rows']))
        by_id={r['id']:r for r in core['rows']}
        check('after-update database abort and retry',by_id['GRACE56-TRANSACTION-ABORT-AFTER-UPDATE']['all_rotation_columns_rolled_back'] and
              by_id['GRACE56-TRANSACTION-ABORT-AFTER-UPDATE']['same_token_retry_succeeded'])
        check('eight responses converge on one stored successor',by_id['GRACE56-EIGHT-REQUEST-CONVERGENCE']['requests']==8 and
              by_id['GRACE56-EIGHT-REQUEST-CONVERGENCE']['authoritative_current_successors']==1)
        installed=base/'installed-cdi56-grace-01';lab=read(installed/'report.json');sdk=read(installed/'sdk-results.json');browser=read(installed/'browser-results.json')
        check('exact installed qualification bound into builder',build['refresh_grace_report']['sha256']==sha(installed/'report.json'))
        check('exact SDK and browser artifacts',lab['sdk_sha256']==sha(installed/'sdk-results.json') and lab['browser_sha256']==sha(installed/'browser-results.json'))
        check('eleven SDK rows including wire and cleanup',sdk['passed']==11 and sdk['failed']==sdk['skipped']==0 and not sdk['fatal'] and
              len(sdk['rows'])==11 and all(r['outcome']=='passed' for r in sdk['rows']))
        check('adapted profile remains explicit',not sdk['unmodified_sdk_qualified'] and not sdk['foundation_passed'] and not sdk['complete'])
        check('Node application has no source overlay',lab['installed_node_image']==current_node['Id'] and not any(m['Destination'].startswith('/app') for m in lab['installed_node_mounts']))
        for path,digest in sdk['inputs'].items():check('actual installed app source '+path,sha(ROOT/'examples/node-react'/path)==digest)
        session=[r for r in sdk['wire'] if r['path'].endswith(('/recipe/session/refresh','/recipe/session/verify'))]
        check('wire observes only adapted CDI5.6 on both Core replicas',bool(session) and all(r['cdi']=='5.6' for r in session) and {r['replica'] for r in session}=={0,1})
        check('atomic password-session creation keeps its established protocol',any(r['path'].endswith('/expertauth/password/session') and r['cdi']=='5.4' for r in sdk['wire']))
        check('two actual successful responses lost or truncated',len(sdk['faults'])==2 and all(r['upstream_status']=='OK' and r['upstream_received'] for r in sdk['faults']) and
              {r['downstream_body_bytes'] for r in sdk['faults']}=={0,8})
        check('browser cases all passed without skips',len(browser['rows'])==3 and browser['skipped']==0 and all(r['outcome']=='passed' for r in browser['rows']))
        tabs=browser['rows'][0];logout=browser['rows'][1]
        check('real four-tab coordinated refresh',tabs['tabs']==4 and tabs['concurrent_requests']==32 and tabs['statuses']==[200]*32 and 1<=tabs['refresh_requests']<=4)
        check('all four tabs denied after logout',logout['statuses']==[401]*4)
        reuse=read(ROOT/'reuse/session-grace-components.json')
        check('file-specific reuse and full licensing boundary',len(reuse['files'])==9 and not reuse['full_distribution_approved'] and not reuse['independent_review'])
        check('adaptation reuse corresponds to current source',reuse['adaptation']['sha256']==sha(ROOT/reuse['adaptation']['path']))
        for item in reuse['files']:
            for key in ('source_manifest','license_artifact'):check('reuse '+key+' '+item['source_path'],sha(ROOT/item[key]['path'])==item[key]['sha256'])
        report['source_reports']={str(p.relative_to(ROOT)):sha(p) for p in (build_path,base/'run-01/report.json',base/'run-01/probe-report.json',installed/'report.json',installed/'sdk-results.json',installed/'browser-results.json')}
        report['passed']=True
    except Exception as error:report['errors'].append(str(error))
    report['finished']=datetime.now(timezone.utc).isoformat();output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'checks':len(checks),'errors':report['errors'],'report':output.relative_to(ROOT).as_posix()}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
