"""Replace three pinned BC dependencies and retire unused archived scrypt in context.

All originals remain in the audited build cache. No cryptographic primitive is patched.
"""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ACQUISITION='evidence/reuse/bouncycastle/runtime-1852-02/acquisition.json'
PINS={
    'bcprov-jdk18on':('1.85.2','986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5','b37ac84b1d5435ab7b8d166c16ab9f75e09f68f8ec50479bae433939b241b03f'),
    'bcutil-jdk18on':('1.85','590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d','b470a692878f92abf00b9c3af9147a45453250a80930df8f23f1d092c55e2d5e'),
    'bcpkix-jdk18on':('1.85','c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996','e5331f467331aba29bda6ddfb0df0da6d568928e29c2b0f20ea2fe123d802d20')}
SOURCES=['tools/install_bouncycastle.py',ACQUISITION,'evidence/reuse/bouncycastle/runtime-1852-02/container.json']


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs():
    report=json.loads((ROOT/ACQUISITION).read_text());need(report['passed'],'Dependency acquisition incomplete')
    need({r['artifact'] for r in report['artifacts']}==set(PINS),'Dependency set differs')
    for row in report['artifacts']:
        name=row['artifact'];version,binary,source=PINS[name]
        need(row['version']==version and row['binary']['sha256']==binary and row['source']['sha256']==source,'Dependency pins differ')
        for kind in ('binary','source'):
            p=ROOT/'.cache/bouncycastle-runtime'/row[kind]['filename']
            need(p.resolve().parent==(ROOT/'.cache/bouncycastle-runtime').resolve() and not p.is_symlink() and
                 p.stat().st_size==row[kind]['bytes'] and sha(p)==row[kind]['sha256'],'Locked dependency cache differs')
        pom=ROOT/Path(ACQUISITION).parent/row['pom']['filename'];need(sha(pom)==row['pom']['sha256'],'Dependency POM differs')
    return report['artifacts']


def install(context,expected,notices,bom,compiled):
    need(compiled.get('firebase_scrypt_profile')=='bouncycastle-utf8-v1','Do not remove an active scrypt dependency')
    context=context.resolve();need(context.parent==(ROOT/'.cache').resolve() and context.name.startswith('runtime-image-'),'Bounded image context required')
    dependencies={r['coordinate']:r for r in json.loads((ROOT/'reuse/runtime-dependencies.json').read_text())['dependencies']}
    removed=[];added=[];reused_sources=[]
    def remove(name,coordinate):
        path='lib/'+name;need(expected[path]==sha(context/path)==dependencies[coordinate]['jar']['sha256'],'Original dependency differs')
        removed.append({'path':path,'sha256':expected[path],'coordinate':coordinate});(context/path).unlink();del expected[path]
        members=[c for c in bom['components'] if c.get('group')==coordinate.split(':')[0] and c.get('name')==coordinate.split(':')[1]]
        need(len(members)==1,'Original SBOM dependency ambiguous');bom['components'].remove(members[0])
    def put(path,body):
        p=context/path;need(not p.exists(),'Context file collision');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);expected[path]=sha(p)
        if path.startswith('licenses/'):notices['files'].append({'path':path.removeprefix('licenses/'),'sha256':sha(p),'bytes':len(body)})
    for row in inputs():
        artifact=row['artifact'];remove(artifact+'-1.84.jar','org.bouncycastle:'+artifact+':1.84')
        record=row['binary'];path='lib/'+record['filename'];put(path,(ROOT/'.cache/bouncycastle-runtime'/record['filename']).read_bytes());added.append({'path':path,**record})
        put('licenses/expertauth/bouncycastle/'+row['pom']['filename'],(ROOT/Path(ACQUISITION).parent/row['pom']['filename']).read_bytes())
        bom['components'].append({'type':'library','group':'org.bouncycastle','name':artifact,'version':row['version'],
            'bom-ref':'pkg:maven/'+row['coordinate'].replace(':','/',1).replace(':','@'),'licenses':[{'license':{'name':'Bouncy Castle Licence','url':'https://www.bouncycastle.org/licence.html'}}],
            'hashes':[{'alg':'SHA-256','content':record['sha256']}],'externalReferences':[{'type':'distribution','url':record['url']},{'type':'vcs','url':'https://github.com/bcgit/bc-java'}],
            'properties':[{'name':'expertauth:distribution-approval','value':'pending'}]})
        if artifact=='bcprov-jdk18on':
            with zipfile.ZipFile(ROOT/'.cache/bouncycastle-runtime'/row['source']['filename']) as archive:
                for member in ('org/bouncycastle/LICENSE.java','org/bouncycastle/crypto/generators/SCrypt.java'):
                    body=archive.read(member);dest='licenses/expertauth/bouncycastle/source/'+member;put(dest,body)
                    reused_sources.append({'source_archive':row['source'],'member':member,'destination':dest,'sha256':hashlib.sha256(body).hexdigest(),'modifications':'none'})
    # Inspect all remaining bytecode before dropping the old primitive/loader bundle.
    references=[]
    for path in [p for p in expected if p.endswith('.jar') and not p.endswith('/scrypt-1.4.0.jar')]:
        with zipfile.ZipFile(context/path) as archive:
            for member in archive.namelist():
                if member.endswith('.class') and b'com/lambdaworks/' in archive.read(member):references.append(path+'!'+member)
    need(not references,'An installed class still needs the old scrypt dependency')
    with zipfile.ZipFile(context/'lib/core-12.2.0.jar') as archive:
        body=archive.read('io/supertokens/emailpassword/PasswordHashingUtils.class')
        need(b'org/bouncycastle/crypto/generators/SCrypt' in body and b'UTF_8' in body,'Candidate verifier not installed')
    remove('scrypt-1.4.0.jar','com.lambdaworks:scrypt:1.4.0')
    mapping={'kind':'installed-bouncycastle-firebase-scrypt-profile','complete':False,'full_distribution_approved':False,
        'removed':removed,'installed':added,'upstream_sources':reused_sources,'source_archives':inputs(),
        'no_remaining_lambdaworks_bytecode_references':True,'source_archives_in_image':False,
        'limits':['Only the exact Java KDF dependency call is adapted; no primitive copied or modified.',
                  'Full transitive/source/relink/OS distribution, full API/migration/SDK and independent review remain open.']}
    put('licenses/expertauth/bouncycastle/source-map.json',(json.dumps(mapping,indent=2)+'\n').encode())
    dockerfile=context/'Dockerfile'
    dockerfile.write_bytes(dockerfile.read_bytes()+b'\nLABEL org.expertauth.firebase-scrypt.profile="bouncycastle-utf8-v1" org.expertauth.bouncycastle.version="1.85.2"\n')
    return mapping
