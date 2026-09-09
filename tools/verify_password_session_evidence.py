"""Verify exact sources, binaries and executed cases; not full authentication acceptance."""
import hashlib
import json
from pathlib import Path
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    output=ROOT/'evidence/operations/atomic-reset/password-session-validation.json'
    if output.exists(): raise ValueError('Preserve prior validation')
    def read(p): return json.loads((ROOT/p).read_text())
    checks=[]
    def need(ok,label):
        checks.append({'check':label,'passed':bool(ok)})
        if not ok: raise ValueError(label)
    report={'kind':'password-session-source-binary-evidence-correspondence','passed':False,'complete':False,
            'independent_human_review':False,'checks':checks,'tool_sha256':sha(Path(__file__))}
    try:
        build_dir='evidence/operations/password-session-build/compile-03'
        core_dir='evidence/operations/atomic-reset/session-02'
        parent_dir='evidence/operations/atomic-reset/session-node-02'
        child_dir='evidence/operations/password-reset/atomic-session-node-02'
        build,core,parent,child=[read(p+'/report.json') for p in [build_dir,core_dir,parent_dir,child_dir]]
        need(build['byte_identical_to_build']=='compile-02','source notices preserve actual tested binaries')
        for folder,result in [(build_dir,build),(core_dir,core),(parent_dir,parent),(child_dir,child)]:
            need(result['passed'] and not result['foundation_passed'],'bounded result '+folder)
            need(result.get('resources_unchanged',result.get('resources_restored')) is True,'resources restored '+folder)
            for path,expected in result['inputs'].items():
                need(sha(ROOT/folder/'source-snapshots'/path)==expected,'executed source snapshot '+folder+' '+path)
                if folder in [build_dir,child_dir] or path.endswith('.java'):
                    need(sha(ROOT/path)==expected,'current relevant source '+folder+' '+path)
        expected={r['component']:r['sha256'] for r in build['candidates']}
        for result in [core,parent]:
            need({r['component']:r['sha256'] for r in result['core_artifacts']}==expected,'runtime Core and plugin match compile03')
            need(not result['source_database_contacted'],'original database uncontacted')
        need(child['core_adaptation']['jar_sha256']==expected['core'] and
             child['core_adaptation']['transactional_session_plugins'][0]['sha256']==expected['postgresql'],'Node child uses exact two-JAR adaptation')
        for row in build['candidates']:
            path=ROOT/row['path'];need(sha(path)==row['sha256'],'retained candidate '+row['component'])
            members=read(build_dir+'/'+row['component']+'-members.json')
            with zipfile.ZipFile(path) as z:
                need(z.testzip() is None and len(z.namelist())==len(members) and set(z.namelist())=={m['path'] for m in members},'candidate full member set '+row['component'])
                need(all(hashlib.sha256(z.read(m['path'])).hexdigest()==m['sha256'] for m in members),'candidate every member hash '+row['component'])
        for filename,key in [('probe-report.json','probe_sha256'),('password-session-report.json','password_session_probe_sha256')]:
            p=ROOT/core_dir/filename;r=read(core_dir+'/'+filename)
            need(sha(p)==core[key] and r['subset_passed'] and len(r['rows'])==8 and all(x['status']=='passed' for x in r['rows']),'actual eight Core cases '+filename)
        need(sha(ROOT/child_dir/'report.json')==parent['node_child']['sha256'],'parent binds completed child')
        probe=read(child_dir+'/probe-results.json');browser=read(child_dir+'/browser-results.json');tls=read(child_dir+'/tls-results.json')
        need(probe['passed'] and probe['skipped']==0 and len(probe['rows'])==17 and all(r['status']=='passed' for r in probe['rows']),'fourteen actual HTTP cases plus browser wrapper, wire, cleanup')
        need(len(browser['rows'])==9 and all(r['status']=='passed' for r in browser['rows']),'nine browser cases')
        need(tls['passed'] and len(tls['checks'])==10,'ten transport cases')
        wire=[json.loads(line) for line in (ROOT/child_dir/'wire/good.jsonl').read_text().splitlines()]
        need(len(wire)==36 and all(set(r)=={'path','http','status','policy'} and r['path']=='/expertauth/password/session' and r['http']==200 and r['status']=='OK' and r['policy']=='EXPERTAUTH-PASSWORD-SESSION-1' for r in wire),'36 real private session responses; no legacy path or credential bodies')
        for result in [core,parent,child]:
            need({r['id'] for r in result['created_containers']}=={r['id'] for r in result['retired_containers']},'all exact run containers retired')
        need(child['source_before']==child['source_after'],'stable complete source projection')
        reuse=read('reuse/password-session-components.json')
        need(len(reuse['upstream_files'])==16 and all(sha(ROOT/r['path'])==r['sha256'] for r in reuse['new_or_adapted_sources']),'file-specific new source provenance')
        report['artifact_sha256']={p:sha(ROOT/p) for p in [build_dir+'/report.json',core_dir+'/report.json',parent_dir+'/report.json',child_dir+'/report.json','reuse/password-session-components.json']}
        report['passed']=True
    except Exception as error: report['error']=str(error) if isinstance(error,ValueError) else type(error).__name__
    output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'checks':len(checks),'error':report.get('error'),'complete':False}))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
