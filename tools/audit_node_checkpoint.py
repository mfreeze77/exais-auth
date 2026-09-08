"""Bind the current Node/React lock and installed files to a fresh npm advisory check."""
import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
app=ROOT/'examples/node-react'
lock_path=app/'package-lock.json'
digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
lock=json.loads(lock_path.read_text())
rows=[]
for relative,meta in lock['packages'].items():
    if not relative: continue
    directory=app/relative
    package=directory/'package.json'
    row={'lock_path':relative,'version':meta['version'],'license':meta.get('license'),'integrity':meta.get('integrity'),'resolved':meta.get('resolved'),'optional':meta.get('optional',False),'installed':package.is_file()}
    if package.is_file():
        installed=json.loads(package.read_text())
        assert installed['version']==meta['version'], f'Installed version drift: {relative}'
        row['name']=installed['name']
        row['files']=[{'path':path.relative_to(app).as_posix(),'sha256':digest(path)} for path in sorted(directory.rglob('*')) if path.is_file() and 'node_modules' not in path.relative_to(directory).parts]
        row['license_files']=[r for r in row['files'] if Path(r['path']).name.lower().startswith(('license','notice','copying'))]
    rows.append(row)
argv=['docker','run','--rm','-v',f'{app}:/app:ro','-w','/app','node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436','npm','audit','--json']
run=subprocess.run(argv,capture_output=True,text=True)
audit=json.loads(run.stdout)
assert run.returncode in (0,1) and 'metadata' in audit, 'Advisory service failure'
out=ROOT/'evidence/reuse/node-current-checkpoint'
out.mkdir(parents=True,exist_ok=False)
(out/'npm-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
report={'timestamp':datetime.now(timezone.utc).isoformat(),'lock_sha256':digest(lock_path),'command':argv,'exit_code':run.returncode,'packages':rows,'modification':'supertokens-node scoped nodemailer9.1.1 override; jose6.2.12 offline verification dependency','prior_qualification':'evidence/reuse/nodemailer-9.1.1-qualification.json','limitation':'File/lock and published-advisory accounting only; no complete license distribution, engine selection or security-review approval'}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'packages':len(rows),'installed':sum(r['installed'] for r in rows),'vulnerabilities':audit['metadata']['vulnerabilities'],'report':str(out/'report.json')}))
raise SystemExit(run.returncode)
