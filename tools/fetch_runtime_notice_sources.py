"""Fetch version-pinned Maven source siblings for the already audited runtime JARs.

Source archives are local dependency cache, not automatically approved release
contents. The report distinguishes unavailable sources and preserves binary linkage.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import urllib.error
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def sha(raw): return hashlib.sha256(raw).hexdigest()
def fetch(row):
    coordinate=row['coordinate']
    group,name,version=coordinate.split(':')
    # Some audited artifacts are published in their own maintained repository.
    # Use the recorded POM origin instead of assuming every release is in Central.
    pom_url=row['license']['pom']['final_url']
    prefixes=('https://repo.maven.apache.org/maven2/','https://build.shibboleth.net/maven/releases/')
    assert pom_url.startswith(prefixes), 'Unreviewed Maven source origin'
    url=pom_url.rsplit('/',1)[0]+f'/{name}-{version}-sources.jar'
    base={'coordinate':coordinate,'runtime_jar_sha256':row['jar']['sha256'],'url':url}
    try:
        with urllib.request.urlopen(url,timeout=45) as response:
            assert response.url.startswith(prefixes)
            raw=response.read()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            assert archive.testzip() is None
            members=archive.namelist()
        target=ROOT/'.cache/runtime-source-jars'/f'{group}.{name}-{version}-sources.jar'
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():
            assert target.read_bytes()==raw, 'Previously fetched source bytes changed'
        else:
            tmp=target.with_suffix('.jar.tmp')
            tmp.write_bytes(raw)
            tmp.replace(target)
        return {**base,'status':'available','sha256':sha(raw),'bytes':len(raw),'members':len(members),'path':target.relative_to(ROOT).as_posix()}
    except urllib.error.HTTPError as error:
        return {**base,'status':'unavailable','http_status':error.code}
    except Exception as error:
        return {**base,'status':'failed','error_type':type(error).__name__}

if __name__=='__main__':
    dependencies=json.loads((ROOT/'reuse/runtime-dependencies.json').read_text())['dependencies']
    # One source archive may correspond to more than one classified binary.
    unique={row['coordinate']:row for row in dependencies}
    with ThreadPoolExecutor(max_workers=6) as executor:
        rows=list(executor.map(fetch,unique.values()))
    output=ROOT/'evidence/reuse/runtime-source-notices'
    output.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    report={'timestamp_utc':stamp,'sources':rows,'input_sha256':sha((ROOT/'reuse/runtime-dependencies.json').read_bytes()),
            'scope':'Maven version-sibling source acquisition; native corresponding-source and final distribution approval not established',
            'full_distribution_approved':False}
    target=output/f'fetch-{stamp}.json'
    target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'report':str(target),'available':sum(r['status']=='available' for r in rows),'unavailable':sum(r['status']=='unavailable' for r in rows),'failed':sum(r['status']=='failed' for r in rows)}))
    raise SystemExit(any(row['status']=='failed' for row in rows))
