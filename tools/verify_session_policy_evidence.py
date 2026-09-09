"""Read-only correspondence of effective-policy code, installed bytes and real tests.

Produces integrity evidence, never new authentication cases or an independent review.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile
from atomic_core_identity import current_core_image
from node_runtime_identity import TAG, require_owned_node
from password_session_candidates import validate_pair
from run_sdk_session_faults import inspect, inventory

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())

def main():
    output=ROOT/'evidence/foundation/refresh-grace/policy-evidence-validation-01.json'
    if output.exists():raise ValueError('Preserve previous correspondence report')
    checks=[];sources={}
    report={'kind':'effective-session-policy-evidence-correspondence','started':datetime.now(timezone.utc).isoformat(),
        'passed':False,'complete':False,'authentication_tests_executed':False,'independent_review':False,
        'tool_sha256':sha(Path(__file__)),'checks':checks,'source_reports':sources,'errors':[]}
    def check(name,ok):
        checks.append({'check':name,'passed':bool(ok)})
        if not ok:raise ValueError(name)
    def evidence(name):
        path=ROOT/name;sources[name]=sha(path);return read(path)
    def bound(parent,key):
        row=parent[key];child=evidence(row['path']);check('bound child '+row['path'],sources[row['path']]==row['sha256'] and child['passed']);return child
    try:
        resources=inventory();core=current_core_image();node=inspect('image',TAG);require_owned_node(node)
        compiled=evidence('evidence/operations/password-session-build/policy-01/report.json');validate_pair(ROOT,compiled)
        check('old compiler pair preserved until qualified replacement',compiled['previous_pair_preserved'] and compiled['container_retired'] and compiled['resources_unchanged'])
        for name,digest in compiled['inputs'].items():check('current compiler/engine source '+name,sha(ROOT/name)==digest)
        for row in compiled['candidates']:
            previous=next(r for r in compiled['previous_build']['candidates'] if r['component']==row['component'])
            old_members=read(ROOT/'evidence/operations/password-session-build/compile-04'/(row['component']+'-members.json'))
            members=read(ROOT/'evidence/operations/password-session-build/policy-01'/(row['component']+'-members.json'))
            old={r['path']:r['sha256'] for r in old_members};new={r['path']:r['sha256'] for r in members}
            changed=[p for p in new if new[p]!=old.get(p)]
            check('only intended '+row['component']+' class changed',set(old)==set(new) and changed==(['io/expertauth/core/AtomicPasswordSessionAPI.class'] if row['component']=='core' else []))
            if row['component']=='postgresql':check('plugin remains byte-identical',previous['sha256']==row['sha256'])
            with zipfile.ZipFile(ROOT/row['path']) as archive:
                check('candidate JAR full CRC and member hashes '+row['component'],archive.testzip() is None and len(archive.namelist())==len(new) and
                    all(hashlib.sha256(archive.read(p)).hexdigest()==h for p,h in new.items()))
        core_build=evidence('evidence/operations/atomic-core-image/policy-01/report.json')
        check('installed Core qualified with bounded cleanup',core_build['passed'] and core_build['candidate_image_id']==core and core_build['context_removed'] and core_build['private_scratch_removed'])
        check('old Core image retired',core_build['previous_image'] not in resources['images'])
        for key in ('core_test','node_test','refresh_grace_test'):bound(core_build,key)
        replacement=bound(core_build,'replacement')
        check('actual upgrade rollback re-upgrade preserves database',replacement['committed'] and not replacement['fixture_cleanup_pending'] and
            replacement['schema_before_sha256']==replacement['schema_after_sha256'] and replacement['database_before']==replacement['database_after'] and
            not replacement['production_changed'] and not replacement['database_container_replaced'])
        for command in replacement['commands']:
            for stream in ('stdout','stderr'):
                r=command[stream];p=ROOT/r['path'];check('private replacement log '+r['path'],p.stat().st_size==r['bytes'] and sha(p)==r['sha256'])
        retirement=evidence('evidence/operations/hygiene/password-session-retirement-policy-01.json')
        check('only superseded binary pair retired',retirement['passed'] and retirement['image_build']['sha256']==sources['evidence/operations/atomic-core-image/policy-01/report.json'] and
            all(not (ROOT/r['path']).exists() for r in retirement['retired']) and all(sha(ROOT/r['path'])==r['sha256'] for r in retirement['retained']))
        node_build=evidence('evidence/operations/node-image-build/policy-02/report.json')
        check('installed Node qualified including mismatch refusal',node_build['passed'] and node_build['image_promoted'] and node_build['candidate_image_id']==node['Id'] and
            node_build['retired_previous_image'] not in resources['images'] and node_build['session_policy_child']['exit_code']==0)
        for key in ('atomic_parent_report','reset_report','refresh_grace_report','session_policy_report'):bound(node_build,key)
        for run in ('image-core-policy-01','policy-source-01','installed-policy-02','policy-policy-02'):
            directory=ROOT/'evidence/foundation/refresh-grace'/run;private=ROOT/'.runtime/refresh-grace'/run
            lab=evidence((directory/'report.json').relative_to(ROOT).as_posix())
            check(run+' passed within declared boundaries',lab['passed'] and not lab['complete'] and not lab['foundation_passed'] and not lab['source_database_contacted'])
            check(run+' resource and source preservation',lab['resources_unchanged'] and lab['source_unchanged'] and lab['inputs_unchanged'] and
                lab['images_built']==lab['image_downloads']==lab['new_volumes']==lab['new_networks']==0 and not lab['published_ports'])
            check(run+' all owned containers retired',len(lab['created_containers'])==(5 if run=='image-core-policy-01' else 6) and
                {r['id'] for r in lab['created_containers']}=={r['id'] for r in lab['retired_containers']} and
                not {r['id'] for r in lab['created_containers']}.intersection(resources['containers']))
            check(run+' exact installed Core',lab['images']['core']==core)
            expected={('/opt/expertauth/lib/' if r['component']=='core' else '/opt/expertauth/plugin/')+Path(r['path']).name:r['sha256'] for r in compiled['candidates']}
            for role,hashes in lab['installed_binary_hashes'].items():
                check(run+' installed pair '+role,hashes==expected and not any(m['Destination'].startswith('/opt/expertauth/') for m in lab['installed_mounts'][role]))
            for path,digest in lab['inputs'].items():
                captured=directory/'source-snapshots'/path.replace('.cache/engine-build/','audited-upstream/')
                check(run+' captured producer '+path,sha(captured)==digest)
                if path.startswith(('examples/','engine-extensions/')):check(run+' current product source '+path,sha(ROOT/path)==digest)
            for i,command in enumerate(lab['commands'],1):
                for stream in ('stdout','stderr'):
                    r=command[stream];p=private/f'command-{i:03d}.{stream}'
                    check(f'{run} actual command {i} {stream}',p.stat().st_size==r['bytes'] and sha(p)==r['sha256'])
            for file,key in [('probe-report.json','probe_sha256'),('sdk-results.json','sdk_sha256'),('browser-results.json','browser_sha256'),('policy-results.json','policy_readiness_sha256')]:
                if key not in lab:continue
                actual=evidence((directory/file).relative_to(ROOT).as_posix());check(run+' exact result '+file,sha(directory/file)==lab[key])
                check(run+' no failed/skipped cases '+file,not actual.get('fatal',False) and actual.get('skipped',0)==0 and
                    all(r.get('outcome',r.get('status'))=='passed' for r in actual['rows']))
            if lab.get('installed_node_image'):
                check(run+' exact installed Node without overlays',lab['installed_node_image']==node['Id'] and not any(m['Destination'].startswith('/app') for m in lab['installed_node_mounts']))
        base=ROOT/'evidence/foundation/refresh-grace'
        policy=read(base/'policy-policy-02/policy-results.json');by_id={r['id']:r for r in policy['rows']}
        check('eight policy rows include seven checks and cleanup',len(policy['rows'])==8 and by_id['POLICY56-OWNED-FIXTURE-CLEANUP']['owned_users_removed']==1)
        for key in ('POLICY56-ZERO-GRACE-REJECTED','POLICY56-REUSE-BEHAVIOUR-REJECTED','POLICY56-UNAVAILABLE-REJECTED'):
            r=by_id[key];check(key+' refusal evidence',r['ready_http']==503 and r['live_http']==200 and r['rejected_requests']==8 and r['business_requests']==0 and r['offline_jwt_http']==200)
        check('concurrent refusals and unchanged-session recovery',by_id['POLICY56-CONCURRENT-MISMATCH-REJECTED']['http_statuses']==[503]*8 and
            by_id['POLICY56-RECOVERY-WITHOUT-APP-RESTART']['refresh_http']==200 and not by_id['POLICY56-RECOVERY-WITHOUT-APP-RESTART']['app_restarted'])
        sdk=read(base/'installed-policy-02/sdk-results.json');browser=read(base/'installed-policy-02/browser-results.json')
        check('actual adapted SDK and browser regression',len(sdk['rows'])==11 and len(browser['rows'])==3 and
            browser['rows'][0]['statuses']==[200]*32 and browser['rows'][1]['statuses']==[401]*4 and not sdk['unmodified_sdk_qualified'])
        for p,h in sdk['inputs'].items():check('installed current Node application '+p,sha(ROOT/'examples/node-react'/p)==h==policy['inputs'][p])
        session=[r for r in sdk['wire'] if r['path'].endswith(('/recipe/session/refresh','/recipe/session/verify'))]
        check('actual adapted wire on both replicas',session and {r['replica'] for r in session}=={0,1} and all(r['cdi']=='5.6' for r in session))
        check('real committed responses lost or truncated',len(sdk['faults'])==2 and all(r['upstream_received'] and r['upstream_status']=='OK' for r in sdk['faults']) and {r['downstream_body_bytes'] for r in sdk['faults']}=={0,8})
        reuse=evidence('reuse/session-grace-components.json')
        check('file-specific adaptation/license boundary',sha(ROOT/reuse['adaptation']['path'])==reuse['adaptation']['sha256'] and not reuse['full_distribution_approved'] and not reuse['independent_review'])
        for row in reuse['files']:
            for key in ('source_manifest','license_artifact'):check('reuse binding '+key+' '+row['source_path'],sha(ROOT/row[key]['path'])==row[key]['sha256'])
        report['passed']=True
    except Exception as error:report['errors'].append(str(error))
    report['finished']=datetime.now(timezone.utc).isoformat();output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'checks':len(checks),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
