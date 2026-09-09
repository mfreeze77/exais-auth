"""Retire only the exact superseded reset-only JAR after current proof and mount checks."""
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    output=ROOT/'evidence/operations/hygiene/reset-only-candidate-retirement.json'
    if output.exists(): raise ValueError('Preserve previous retirement evidence')
    old=json.loads((ROOT/'evidence/operations/core-reset-build/compile-03/report.json').read_text())['candidate']
    current=json.loads((ROOT/'evidence/operations/password-session-build/compile-03/report.json').read_text())
    qualification=json.loads((ROOT/'evidence/operations/atomic-reset/password-session-validation.json').read_text())
    assert current['passed'] and qualification['passed']
    for row in current['candidates']: assert sha(ROOT/row['path'])==row['sha256']
    path=(ROOT/old['path']).resolve();folder=(ROOT/'.cache/core-reset').resolve()
    assert path.parent==folder and path.name=='core-12.2.0-atomic-reset.jar' and folder.parent==ROOT/'.cache'
    assert path.is_file() and not path.is_symlink() and not getattr(path.lstat(),'st_file_attributes',0)&0x400
    assert sha(path)==old['sha256']=='8fc49b17a4521b8d704a27a39bcfac1aab3821db854bc7ee5f10c3c73dde9523'
    assert path.stat().st_size==1254808 and list(folder.iterdir())==[path]
    cids=subprocess.check_output(['docker','ps','-aq','--no-trunc']).decode().splitlines()
    # Mount metadata only; never inspect unrelated environments or filesystem data.
    mounts=[]
    if cids:
        raw=subprocess.check_output(['docker','inspect','--format','{{json .Mounts}}',*cids]).decode().splitlines()
        mounts=[m for line in raw for m in json.loads(line)]
    assert all(Path(m['Source']).resolve()!=path for m in mounts if m.get('Type')=='bind')
    members=json.loads((ROOT/'evidence/operations/core-reset-build/compile-03/jar-members.json').read_text())
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None and len(archive.namelist())==len(members)
        assert all(hashlib.sha256(archive.read(r['path'])).hexdigest()==r['sha256'] for r in members)
    report={'kind':'exact-superseded-candidate-retirement','passed':False,'path':old['path'],'sha256':old['sha256'],
            'bytes':path.stat().st_size,'source_and_build_evidence_preserved':True,'current_candidates':current['candidates'],
            'old_candidate_unmounted':True,'tool_sha256':sha(Path(__file__))}
    output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    path.unlink();folder.rmdir()
    report['passed']=not path.exists() and all(sha(ROOT/r['path'])==r['sha256'] for r in current['candidates'])
    output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print(json.dumps({'passed':report['passed'],'retired_bytes':report['bytes'],'current_candidate_bytes':sum(r['bytes'] for r in current['candidates'])}))
if __name__=='__main__':main()
