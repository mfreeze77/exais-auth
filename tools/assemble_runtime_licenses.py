"""Collect exact upstream notice bytes for the audited OSS runtime image.

This preserves notices and records gaps; it does not decide that source-offer,
native-library or final distribution obligations have been discharged.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
NAME=re.compile(r'^(?:license|licence|notice|copying|copyright)(?:[._-].*)?$',re.I)
def sha(raw): return hashlib.sha256(raw).hexdigest()

def assemble(destination: Path):
    destination=destination.resolve()
    assert destination.is_relative_to((ROOT/'.cache').resolve()), 'Generated image context must stay in .cache'
    assert not destination.exists(), 'Use a new notice output directory; preserve prior evidence'
    destination.mkdir(parents=True)
    dependencies=json.loads((ROOT/'reuse/runtime-dependencies.json').read_text())['dependencies']
    expected={r['path']:r['sha256'] for r in json.loads((ROOT/'evidence/build/oss-core/artifacts.json').read_text())}
    rows=[]
    def write(relative,raw):
        pure=PurePosixPath(relative)
        assert not pure.is_absolute() and '..' not in pure.parts and '\\' not in relative
        path=destination/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        assert not path.exists() or path.read_bytes()==raw
        path.write_bytes(raw)
        return {'path':relative,'sha256':sha(raw),'bytes':len(raw)}
    for dependency in dependencies:
        jar=ROOT/dependency['jar']['file']
        digest=sha(jar.read_bytes())
        assert digest==dependency['jar']['sha256']==dependency['build_record']['sha256']
        assert expected[jar.relative_to(ROOT/'.cache/engine-build').as_posix()]==digest
        coordinate=dependency['coordinate']
        prefix=coordinate.replace(':','/')
        notices=[]
        with zipfile.ZipFile(jar) as archive:
            for name in sorted(archive.namelist()):
                pure=PurePosixPath(name)
                if not NAME.match(pure.name) or pure.suffix.lower() in ('.class','.jar','.exe','.dll','.so'):
                    continue
                raw=archive.read(name)
                try: raw.decode('utf-8-sig')
                except UnicodeError: continue
                if b'\x00' in raw: continue
                entry=write(prefix+'/'+name,raw)
                notices.append({**entry,'archive_member':name})
        pom=dependency['license']['pom']
        group,artifact,version=coordinate.split(':')
        pom_path=ROOT/'reuse/licenses/poms'/f'{group}.{artifact}-{version}.pom'
        assert sha(pom_path.read_bytes())==pom['sha256'], f'POM provenance changed: {coordinate}'
        declaration=write(prefix+'/maven-pom.xml',pom_path.read_bytes())
        rows.append({'coordinate':coordinate,'runtime_jar_sha256':digest,'notices':notices,'pom':declaration,
                     'declared_licenses':dependency['license']['licenses'],
                     'upstream_pom':pom['url'],'notice_text_present':bool(notices),
                     'qualification':'notice preservation only; full distribution review remains required'})
    projects=json.loads((ROOT/'evidence/build/oss-core/command.json').read_text())['sources']
    for name,commit in projects.items():
        path=ROOT/'reuse/licenses'/f'supertokens__{name}'/commit/'LICENSE.md'
        write(f'own-source/{name}/LICENSE.md',path.read_bytes())
    write('THIRD_PARTY_NOTICES.md',(ROOT/'THIRD_PARTY_NOTICES.md').read_bytes())
    write('oss-core-runtime.cdx.json',(ROOT/'reuse/oss-core-runtime.cdx.json').read_bytes())
    gaps=[row['coordinate'] for row in rows if not row['notice_text_present']]
    report={'schema':'runtime-notice-preservation-v1','dependencies':rows,'runtime_dependency_count':len(rows),
            'embedded_notice_text_count':sum(len(row['notices']) for row in rows),'no_embedded_notice_text':gaps,
            'full_distribution_approved':False,'remaining':['Source/relink obligations for applicable LGPL/EPL/native components','Resolve dependencies without embedded license text from their pinned source','Container operating-system license closure and independent review'],
            'input_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):sha(p.read_bytes()) for p in [Path(__file__),ROOT/'reuse/runtime-dependencies.json',ROOT/'evidence/build/oss-core/artifacts.json',ROOT/'THIRD_PARTY_NOTICES.md']}}
    write('manifest.json',(json.dumps(report,indent=2)+'\n').encode())
    return report

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    report=assemble(args.output)
    print(json.dumps({'dependencies':report['runtime_dependency_count'],'notice_texts':report['embedded_notice_text_count'],'missing_embedded_text':len(report['no_embedded_notice_text']),'full_distribution_approved':False}))
