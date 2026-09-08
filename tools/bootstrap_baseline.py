"""Preserve the supplied acceptance contract without rewriting any input."""
from __future__ import annotations
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT.parent

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> None:
    source = INPUT / 'expert-auth-full-parity-plan-v1.0'
    manifest = json.loads((source / 'PACKAGE_MANIFEST.json').read_text())
    results = []
    for row in manifest['files']:
        path = source / row['path']
        assert path.is_file(), f'Missing original file: {path}'
        assert path.stat().st_size == row['bytes'], f'Size mismatch: {path}'
        assert sha(path) == row['sha256'], f'Hash mismatch: {path}'
        results.append({'path': row['path'], 'sha256': sha(path), 'verified': True})
    destination = ROOT / 'baseline' / source.name
    for path in source.rglob('*'):
        if not path.is_file():
            continue
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            assert sha(target) == sha(path), f'Refusing to overwrite baseline: {target}'
        else:
            shutil.copyfile(path, target)
    for name in ['EXPERTAUTH_KICKOFF.md', 'KICKOFF_MANIFEST.json', 'ExpertAuth_Full_Parity_Plan.md', 'super-tokens-engineering-report.md']:
        target = ROOT / 'baseline' / name
        if target.exists():
            assert sha(target) == sha(INPUT / name)
        else:
            shutil.copyfile(INPUT / name, target)
    archive = INPUT / 'expert-auth-full-parity-plan-v1.0.zip'
    archive_state = 'missing-original-archive-extracted-files-verified'
    if archive.exists():
        assert sha(archive) == '58f013dc0ae6fe9981206d4594e78d8efd0cde2f1a00f15bbdfbaec12ee918ed'
        shutil.copyfile(archive, ROOT / 'baseline' / archive.name)
        archive_state = 'original-archive-verified'
    evidence = ROOT / 'evidence' / 'baseline'
    evidence.mkdir(parents=True, exist_ok=True)
    command = ['python', str(destination / 'tools/validate_plan.py'), '--output', str(evidence / 'plan-validation.json')]
    run = subprocess.run(command, capture_output=True, text=True)
    (evidence / 'validation-command.json').write_text(json.dumps({'command': command, 'exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}, indent=2) + '\n')
    assert run.returncode == 0, run.stdout + run.stderr
    lock = {'original_archive_state': archive_state, 'expected_archive_sha256': '58f013dc0ae6fe9981206d4594e78d8efd0cde2f1a00f15bbdfbaec12ee918ed', 'manifest_files': results,
            'files': [{'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p)} for p in sorted((ROOT / 'baseline').rglob('*')) if p.is_file()]}
    lock_path = ROOT / 'baseline-lock.json'
    if lock_path.exists():
        assert json.loads(lock_path.read_text()) == lock, 'Baseline lock changed'
    else:
        lock_path.write_text(json.dumps(lock, indent=2) + '\n')
    print(json.dumps({'manifest_files_verified': len(results), 'archive': archive_state, 'plan_validator_exit': run.returncode}))

if __name__ == '__main__':
    main()
