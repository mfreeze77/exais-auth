"""Build pinned permitted SuperTokens projects, without official EE packaging helpers.

Source cache is populated by tools/audit_sources.py. Binary/license closure and
runtime tests are separate gates; a successful compilation never approves release.
"""
from __future__ import annotations
import hashlib
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2'
SOURCES = {
    'supertokens-core':'b2219c4aa019a501e4dfea76cf06ef802ca93fc0',
    'supertokens-plugin-interface':'2550750188069110753decd06265a59fadefb427',
    'supertokens-postgresql-plugin':'0b68fd14ca10baee2d0e3c31466984fccfb36c8a',
}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clean', action='store_true', help='Use a new isolated build directory; never delete previous output')
    parser.add_argument('--evidence-name', default='oss-core')
    args = parser.parse_args()
    assert args.evidence_name.replace('-','').replace('_','').isalnum(), 'Simple evidence name required'
    build = ROOT/'.cache'/('engine-build-'+str(time.time_ns()) if args.clean else 'engine-build')
    evidence = ROOT/'evidence/build'/args.evidence_name
    evidence.mkdir(parents=True,exist_ok=True)
    build.mkdir(parents=True,exist_ok=True)
    files = []
    for name, commit in SOURCES.items():
        source = ROOT/'.cache/reuse-audit/source'/f'supertokens__{name}'/commit
        manifest_file = ROOT/'reuse/files'/f'supertokens__{name}__{commit}.json'
        if not manifest_file.exists():
            manifest_file = ROOT/'reuse/files'/f'supertokens__{name}.json'
        manifest = json.loads(manifest_file.read_text())
        assert manifest['commit'] == commit, f'Audit revision differs for {name}'
        assert source.is_dir(), f'Run tools/audit_sources.py first: {source}'
        recorded = {r['source_path']:r for r in manifest['files']}
        # Windows can normalize directory casing (userRoles/userroles). Iterate the
        # immutable manifest spelling and verify bytes, never infer upstream paths.
        for original, item in recorded.items():
            rel = Path(original)
            path = source/rel
            assert 'ee' not in rel.parts, 'Restricted directory in source cache'
            # Never use checked-in prebuilt core, CLI, downloader or native executables.
            # Telemetry resource JARs remain separately audited upstream dependencies.
            if path.suffix in {'.jar','.exe','.dll','.so','.dylib'}:
                cached = (build/name/rel).resolve()
                assert cached.is_relative_to(build.resolve())
                if cached.is_file():
                    assert sha(cached) == item['sha256'], 'Refuse removing an unknown cached binary'
                    cached.unlink()
                continue
            assert sha(path) == item['sha256'], f'Source changed after audit: {name}/{rel}'
            target = build/name/rel
            target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists() or sha(target) != sha(path):
                shutil.copyfile(path,target)
            files.append({'repository':f'supertokens/{name}','commit':commit,'path':rel.as_posix(),'sha256':sha(path)})
    # Resource telemetry binaries are excluded from this minimal source probe.
    # Full telemetry support remains required and separately license-audited.
    for name in ['settings.gradle','build.gradle']:
        shutil.copyfile(ROOT/'engine-extensions/oss-build'/name,build/name)
    # Normal builds consume reviewed locks/checksums; they never trust new bytes
    # by regenerating verification metadata during the build.
    lock_root = ROOT/'engine-extensions/oss-build/locks'
    for lock in lock_root.rglob('*'):
        if lock.is_file():
            target = build/lock.relative_to(lock_root)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(lock,target)
    assert (build/'gradle/verification-metadata.xml').is_file(), 'Reviewed dependency checksums required'
    command = ['docker','run','--rm','--name','expertauth-oss-build',
               '-v',f'{build}:/workspace','-v','expertauth-gradle-cache:/home/gradle/.gradle',
               '-w','/workspace',IMAGE,'gradle','--no-daemon','--max-workers=2','--console=plain',
               '--dependency-verification','strict',
               ':supertokens-core:jar',':supertokens-core:copyJars',
               ':supertokens-plugin-interface:jar',':supertokens-postgresql-plugin:jar',
               ':supertokens-postgresql-plugin:copyJars','runtimeInventory']
    start = time.time()
    attempt = evidence/'attempts'/str(time.time_ns())
    attempt.mkdir(parents=True)
    with (attempt/'build.log').open('w',encoding='utf-8') as log:
        run = subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    record = {'command':command,'exit_code':run.returncode,'started_unix':start,'elapsed_seconds':round(time.time()-start,3),
              'image':IMAGE,'sources':SOURCES,'source_files':files,'tests_executed':False,'build_directory':str(build),
              'scope':'source compilation; runtime, transitive license and security qualification are separate'}
    (attempt/'command.json').write_text(json.dumps(record,indent=2)+'\n')
    for name in ['build.log','command.json']:
        shutil.copyfile(attempt/name,evidence/name)
    for path in [build/'dependencies.json',*build.rglob('gradle.lockfile'),build/'gradle/verification-metadata.xml']:
        if path.exists():
            target = evidence/path.relative_to(build)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,target)
    artifacts = [{'path':p.relative_to(build).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
                 for name in SOURCES for p in sorted((build/name/'build').rglob('*.jar')) if p.is_file()]
    (evidence/'artifacts.json').write_text(json.dumps(artifacts,indent=2)+'\n')
    print(json.dumps({'exit_code':run.returncode,'artifacts':len(artifacts),'log':str(evidence/'build.log')}))
    raise SystemExit(run.returncode)

if __name__ == '__main__':
    main()
