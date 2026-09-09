"""Use the pinned JDK base and audited original JAR cache, not a retired runtime image."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
IMAGE='gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2'
ARTIFACTS='evidence/build/oss-core/artifacts.json'
CORE='/audited-build/supertokens-core/build/libs/core-12.2.0.jar'

def compiler_inputs():
    folder=(ROOT/'.cache/engine-build').resolve()
    if folder.parent!=(ROOT/'.cache').resolve(): raise ValueError('Compiler cache outside workspace')
    rows=json.loads((ROOT/ARTIFACTS).read_text())
    if len(rows)!=87: raise ValueError('Original full JAR inventory required')
    classpath=[]
    for row in rows:
        path=folder/row['path']
        if (not path.resolve().is_relative_to(folder) or not path.is_file() or path.is_symlink() or
            getattr(path.lstat(),'st_file_attributes',0)&0x400 or path.suffix!='.jar' or
            hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']):
            raise ValueError('Original compiler dependency differs')
        classpath.append('/audited-build/'+row['path'])
    if len(set(classpath))!=87: raise ValueError('Duplicate compiler artifact')
    return {'image_reference':IMAGE,'classpath':':'.join(classpath),'core_path':CORE,
            'mount':f'type=bind,source={folder},target=/audited-build,readonly',
            'original_artifacts':rows,'artifact_manifest_sha256':hashlib.sha256((ROOT/ARTIFACTS).read_bytes()).hexdigest()}
