"""File-specific adaptation provenance with current versus retained-source limits explicit."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    output=ROOT/'reuse/password-session-components.json'
    if output.exists(): raise ValueError('Preserve previous provenance report')
    selection={
        'supertokens-core':('b2219c4aa019a501e4dfea76cf06ef802ca93fc0',[
            'src/main/java/io/supertokens/'+p for p in ['session/Session.java','webserver/Webserver.java',
            'emailpassword/PasswordHashing.java','authRecipe/AuthRecipe.java','webserver/api/session/SessionAPI.java','storageLayer/StorageLayer.java']]),
        'supertokens-postgresql-plugin':('0b68fd14ca10baee2d0e3c31466984fccfb36c8a',[
            'src/main/java/io/supertokens/storage/postgresql/'+p for p in ['queries/SessionQueries.java','queries/UserLockingQueries.java','QueryExecutorTemplate.java','Start.java']]),
        'supertokens-node':('9b82aefb46da4c0f0a388d8f6656c39a62d7642c',[
            'lib/ts/querier.ts','lib/ts/types.ts','lib/ts/recipe/emailpassword/api/implementation.ts','lib/ts/recipe/session/sessionFunctions.ts'])}
    entries=[]
    for repo,(rev,paths) in selection.items():
        slug='supertokens__'+repo
        manifest_path=next(p for p in [ROOT/'reuse/files'/f'{slug}__{rev}.json',ROOT/'reuse/files'/f'{slug}.json'] if p.exists())
        manifest=json.loads(manifest_path.read_text()); assert manifest['commit']==rev
        for path in paths:
            row=next(r for r in manifest['files'] if r['source_path']==path)
            source=ROOT/'.cache/reuse-audit/source'/slug/rev/path
            current=source.is_file()
            if current: assert sha(source)==row['sha256']
            modification='Dependency/API use only; original file unchanged'; destination='Compiled dependency'
            if path.endswith('/Session.java') or path.endswith('/Webserver.java'):
                modification='Build-time insertion callback retaining original token minting, or private route registration'
                destination='evidence/operations/password-session-build/compile-02/'+Path(path).name
            elif path.endswith('/SessionQueries.java'):
                modification='Same INSERT columns/values adapted to caller transaction; Core owns lock and commit'
                destination='engine-extensions/core-reset/postgresql/io/supertokens/storage/postgresql/ExpertAuthSessionWriter.java'
            elif path.endswith('/SessionAPI.java'):
                modification='Private API adapts session input/output parsing; explicit CDI5.4 profile'
                destination='engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSessionAPI.java'
            licenses=[p.relative_to(ROOT).as_posix() for p in (ROOT/'reuse/licenses'/slug/rev).rglob('*') if p.is_file()]
            assert licenses
            entry={'repository':'https://github.com/supertokens/'+repo,'commit':rev,'source_path':path,'sha256':row['sha256'],
                'source_bytes_currently_verified':current,'manifest_path':manifest_path.relative_to(ROOT).as_posix(),'manifest_sha256':sha(manifest_path),
                'license':'Apache-2.0','retained_license_files':licenses,'modification':modification,'destination_or_dependency':destination}
            if repo=='supertokens-node':
                runtime=ROOT/'examples/node-react/node_modules/supertokens-node'/path.replace('lib/ts/','lib/build/').replace('.ts','.js')
                if runtime.is_file(): entry['runtime']={'path':runtime.relative_to(ROOT).as_posix(),'sha256':sha(runtime)}
                entry['qualification']='Upstream TS hashes retained in prior archive audit; sparse source cache does not retain these files. Runtime JS is independently hashed; Node package lock and prior original-archive member correspondence remain separate evidence.'
            entries.append(entry)
    proxy=ROOT/'examples/node-react/node_modules/supertokens-js-override'
    package=json.loads((proxy/'package.json').read_text())
    lock=json.loads((ROOT/'examples/node-react/package-lock.json').read_text())['packages']['node_modules/supertokens-js-override']
    for name in ['lib/build/getProxyObject.js','lib/build/index.js']:
        entries.append({'repository':package.get('repository'),'package':'supertokens-js-override','version':package['version'],
            'archive_integrity':lock['integrity'],'source_commit':None,'source_path':name,'sha256':sha(proxy/name),'license':package['license'],
            'destination_or_dependency':'examples/node-react/package-lock.json; original runtime dependency, not copied',
            'modification':'None; application wrapper preserves original proxy receiver',
            'qualification':'Exact npm release pinned; complete source-commit/maintenance provenance remains unqualified'})
    paths=list((ROOT/'engine-extensions/core-reset/src/io/expertauth/core').glob('*Session*.java'))+[ROOT/'engine-extensions/core-reset/postgresql/io/supertokens/storage/postgresql/ExpertAuthSessionWriter.java']
    report={'kind':'file-specific-password-session-reuse','full_distribution_approved':False,'independent_review':False,
        'mapped_requirements':['PWD-006','SES-001','SES-005','SES-006'],'upstream_files':entries,
        'new_or_adapted_sources':[{'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'license':'Apache-2.0'} for p in paths],
        'report_tool_sha256':sha(Path(__file__)),'boundaries':'Core owns credential recheck/transaction/minting; PostgreSQL plugin owns insert. No adapter SQL or duplicate identity/session state.',
        'primary_documentation':['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/ServiceLoader.html','https://www.postgresql.org/docs/17/explicit-locking.html']}
    output.write_bytes((json.dumps(report,indent=2)+'\n').encode()); print(json.dumps({'upstream_rows':len(entries),'local_source_rows':len(paths)}))
if __name__=='__main__':main()
