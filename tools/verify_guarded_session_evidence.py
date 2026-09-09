"""Bind guarded-operation implementation, installed binaries and real test evidence.

Integrity checks do not execute authentication tests or provide independent review.
"""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import zipfile
from atomic_core_identity import current_core_image
from node_runtime_identity import TAG,require_owned_node
from password_session_candidates import validate_pair
from patch_session_policy import REFRESH,VERIFY,guarded_api
from run_sdk_session_faults import inspect,inventory

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())

def main():
    output=ROOT/'evidence/foundation/refresh-grace/guarded-evidence-validation-01.json'
    if output.exists():raise ValueError('Preserve previous evidence')
    checks=[];sources={}
    report={'kind':'guarded-session-source-binary-evidence-correspondence','started':datetime.now(timezone.utc).isoformat(),
        'passed':False,'complete':False,'authentication_tests_executed':False,'independent_review':False,
        'tool_sha256':sha(Path(__file__)),'checks':checks,'source_reports':sources,'errors':[]}
    def check(name,ok):
        checks.append({'check':name,'passed':bool(ok)})
        if not ok:raise ValueError(name)
    def evidence(name):
        path=ROOT/name;sources[name]=sha(path);return read(path)
    def bound(parent,key):
        row=parent[key];d=evidence(row['path']);check('bound '+row['path'],sources[row['path']]==row['sha256'] and d['passed']);return d
    try:
        runtime=inventory();core=current_core_image();node=inspect('image',TAG);require_owned_node(node)
        compiled=evidence('evidence/operations/password-session-build/guarded-01/report.json');validate_pair(ROOT,compiled)
        for path,digest in compiled['inputs'].items():check('current compiled source '+path,sha(ROOT/path)==digest)
        check('bounded compiler preserved prior pair and removed helper',compiled['passed'] and compiled['previous_pair_preserved'] and compiled['container_retired'] and compiled['resources_unchanged'])
        for row in compiled['candidates']:
            members=read(ROOT/'evidence/operations/password-session-build/guarded-01'/(row['component']+'-members.json'))
            with zipfile.ZipFile(ROOT/row['path']) as archive:
                check('full compiled '+row['component']+' CRC/member identity',archive.testzip() is None and len(archive.namelist())==len(members) and
                    all(hashlib.sha256(archive.read(r['path'])).hexdigest()==r['sha256'] for r in members))
            if row['component']=='core':
                for cls in ['RefreshSessionAPI','VerifySessionAPI']:
                    r=next(r for r in members if r['path']=='io/supertokens/webserver/api/session/'+cls+'.class')
                    check('original API class unchanged '+cls,r['sha256']==r['original_sha256'] and not r['changed'])
            else:check('plugin unchanged from preceding implementation',row['sha256']=='d7a7ae7cefd18724658e3bc24f3351bcacc69439245433429d10879da487624c')
        original=ROOT/'.cache/reuse-audit/source/supertokens__supertokens-core/b2219c4aa019a501e4dfea76cf06ef802ca93fc0'
        for path in [REFRESH,VERIFY]:
            derived=guarded_api((original/path).read_text(),path==REFRESH)
            notice='\n/* Modified by ExpertAuth contributors (2026): private password-session/reset API registration or transaction-aware session insertion callback. Original token minting and licensing checks retained. */\n'
            file='Guarded'+Path(path).name;actual=ROOT/'evidence/operations/password-session-build/guarded-01'/file
            check('exact Apache derivative '+file,actual.read_bytes()==(derived+notice).encode() and b'Apache License, Version 2.0' in actual.read_bytes())
        core_build=evidence('evidence/operations/atomic-core-image/guarded-01/report.json')
        check('current installed Core and bounded build cleanup',core_build['passed'] and core_build['candidate_image_id']==core and core_build['context_removed'] and core_build['private_scratch_removed'])
        check('superseded Core image retired',core_build['previous_image'] not in runtime['images'])
        for key in ('core_test','node_test','refresh_grace_test','guarded_session_test'):bound(core_build,key)
        replacement=bound(core_build,'replacement')
        check('actual replacement/rollback preserves database',replacement['committed'] and not replacement['fixture_cleanup_pending'] and
            replacement['database_before']==replacement['database_after'] and replacement['schema_before_sha256']==replacement['schema_after_sha256'] and
            not replacement['production_changed'] and not replacement['database_container_replaced'])
        for command in replacement['commands']:
            for stream in ('stdout','stderr'):
                r=command[stream];p=ROOT/r['path'];check('private replacement '+r['path'],p.stat().st_size==r['bytes'] and sha(p)==r['sha256'])
        retired=evidence('evidence/operations/hygiene/password-session-retirement-guarded-01.json')
        check('superseded binary pair retired after qualification',retired['passed'] and all(not (ROOT/r['path']).exists() for r in retired['retired']) and
            all(sha(ROOT/r['path'])==r['sha256'] for r in retired['retained']))
        node_build=evidence('evidence/operations/node-image-build/guarded-01/report.json')
        check('current Node qualified before promotion',node_build['passed'] and node_build['image_promoted'] and node_build['candidate_image_id']==node['Id'] and
            node_build['retired_previous_image'] not in runtime['images'] and node_build['session_policy_child']['exit_code']==0)
        for key in ('atomic_parent_report','reset_report','refresh_grace_report','session_policy_report'):bound(node_build,key)
        runs={'image-guarded-guarded-01':7,'image-core-guarded-01':5,'guarded-source-01':6,'installed-guarded-01':6,'policy-guarded-01':6}
        for run,count in runs.items():
            directory=ROOT/'evidence/foundation/refresh-grace'/run;private=ROOT/'.runtime/refresh-grace'/run
            lab=evidence((directory/'report.json').relative_to(ROOT).as_posix())
            check(run+' passed without broad claims',lab['passed'] and not lab['complete'] and not lab['foundation_passed'] and not lab['source_database_contacted'])
            check(run+' resources/source preserved',lab['resources_unchanged'] and lab['source_unchanged'] and lab['inputs_unchanged'] and
                lab['images_built']==lab['image_downloads']==lab['new_volumes']==lab['new_networks']==0 and not lab['published_ports'])
            created={r['id'] for r in lab['created_containers']}
            check(run+' all exact helpers retired',len(created)==count and created=={r['id'] for r in lab['retired_containers']} and not created.intersection(runtime['containers']))
            check(run+' exact current Core',lab['images']['core']==core)
            for role,mounts in lab['installed_mounts'].items():
                check(run+' installed without JAR overlays '+role,not any(m['Destination'].startswith('/opt/expertauth/') for m in mounts))
            for path,digest in lab['inputs'].items():
                p=directory/'source-snapshots'/path.replace('.cache/engine-build/','audited-upstream/')
                check(run+' recorded producer '+path,sha(p)==digest)
                if path.startswith(('examples/','engine-extensions/')):check(run+' current product '+path,sha(ROOT/path)==digest)
            for i,command in enumerate(lab['commands'],1):
                for stream in ('stdout','stderr'):
                    r=command[stream];p=private/f'command-{i:03d}.{stream}'
                    check(f'{run} actual command {i} {stream}',p.stat().st_size==r['bytes'] and sha(p)==r['sha256'])
            for file,key in [('guarded-report.json','guarded_sha256'),('probe-report.json','probe_sha256'),('sdk-results.json','sdk_sha256'),('browser-results.json','browser_sha256'),('policy-results.json','policy_readiness_sha256')]:
                if key not in lab:continue
                d=evidence((directory/file).relative_to(ROOT).as_posix())
                check(run+' exact successful '+file,sha(directory/file)==lab[key] and not d.get('fatal',False) and d.get('skipped',0)==0 and
                    all(r.get('outcome',r.get('status'))=='passed' for r in d['rows']))
            if lab.get('installed_node_image'):
                check(run+' exact Node without overlays',lab['installed_node_image']==node['Id'] and not any(m['Destination'].startswith('/app') for m in lab['installed_node_mounts']))
        base=ROOT/'evidence/foundation/refresh-grace'
        guarded=read(base/'image-guarded-guarded-01/guarded-report.json');g={r['id']:r for r in guarded['rows']}
        check('nine direct behavior checks plus cleanup',len(g)==10 and g['GUARD56-OWNED-FIXTURE-CLEANUP']['owned_users_removed']==1)
        for key in ['GUARD56-PREFLIGHT-ZERO-GRACE-OPERATION','GUARD56-PREFLIGHT-OTHER-REUSE-OPERATION']:
            r=g[key];check(key,r['healthy_preflight_http']==200 and r['refresh_http']==r['verify_http']==503 and r['session_columns_unchanged'] and r['retry_http']==200)
        check('actual old replica cannot perform guarded operations',g['GUARD56-OLD-REPLICA-FAILS-CLOSED']['guarded_refresh_http']==g['GUARD56-OLD-REPLICA-FAILS-CLOSED']['guarded_verify_http']==404 and g['GUARD56-OLD-REPLICA-FAILS-CLOSED']['original_refresh_http']==200)
        check('16 mixed Core requests converge',g['GUARD56-CONCURRENT-MIXED-POLICY']['successful_refreshes']==g['GUARD56-CONCURRENT-MIXED-POLICY']['mismatched_refusals']==8 and g['GUARD56-CONCURRENT-MIXED-POLICY']['authoritative_successors']==1)
        policy=read(base/'policy-guarded-01/policy-results.json');p={r['id']:r for r in policy['rows']}
        check('installed guarded Node profile complete',len(p)==11 and policy['guarded_operations_tested'] and not policy['fatal'])
        for key in ['POLICY56-GUARDED-ZERO-REPLICA-AFTER-PREFLIGHT','POLICY56-GUARDED-REUSE-REPLICA-AFTER-PREFLIGHT']:
            r=p[key];check(key,r['preflight_http']==200 and r['core_operation_http']==503 and r['sdk_refresh_http']==r['sdk_verify_http']==500 and
                not r['original_route_fallback'] and r['same_session_recovery_http']==200)
        check('mixed Node requests converge',p['POLICY56-GUARDED-CONCURRENT-MIXED-REPLICAS']['successful_refreshes']==p['POLICY56-GUARDED-CONCURRENT-MIXED-REPLICAS']['mismatched_refusals']==2 and p['POLICY56-GUARDED-CONCURRENT-MIXED-REPLICAS']['online_valid_successors']==1)
        sdk=read(base/'installed-guarded-01/sdk-results.json');browser=read(base/'installed-guarded-01/browser-results.json')
        check('unchanged browser coordination and logout',len(browser['rows'])==3 and browser['rows'][0]['statuses']==[200]*32 and browser['rows'][1]['statuses']==[401]*4)
        check('SDK behavior/wire/cleanup all pass',len(sdk['rows'])==11 and not sdk['unmodified_sdk_qualified'] and sdk['failed']==0)
        operations=[r for r in sdk['wire'] if r['path'].endswith(('/expertauth/session/refresh','/expertauth/session/verify'))]
        check('guarded CDI5.6 wire on both replicas without fallback',operations and all(r['cdi']=='5.6' for r in operations) and {r['replica'] for r in operations}=={0,1} and
            not any(r['path'].endswith(('/recipe/session/refresh','/recipe/session/verify')) for r in sdk['wire']))
        check('actual committed guarded responses lost/truncated',len(sdk['faults'])==2 and all(r['path']=='/expertauth/session/refresh' and r['upstream_received'] and r['upstream_status']=='OK' for r in sdk['faults']) and {r['downstream_body_bytes'] for r in sdk['faults']}=={0,8})
        for path,digest in sdk['inputs'].items():check('actual installed app '+path,sha(ROOT/'examples/node-react'/path)==digest==policy['inputs'][path])
        reuse=evidence('reuse/session-grace-components.json')
        check('current file-specific adaptation binding',sha(ROOT/reuse['adaptation']['path'])==reuse['adaptation']['sha256'] and not reuse['full_distribution_approved'])
        report['passed']=True
    except Exception as error:report['errors'].append(str(error))
    report['finished']=datetime.now(timezone.utc).isoformat();output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'checks':len(checks),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
