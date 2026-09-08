"""Attach partial implementation and candidate evidence without certifying acceptance.

Explicit checkpoint mappings only. This does not convert harness runs to the
strict release schema, infer missing tests, or mark any baseline row verified.
"""
from pathlib import Path
from ledger import ROOT, read_json, write_json, integrity_errors, artifact as _artifact

def artifact(root, path):
    return _artifact(root,root/path)

def main():
    path = ROOT/'ledger/implementation.json'
    data = read_json(path)
    assert not any(row['status']=='verified' for group in ('requirements','apis','sdks','plugins','integrations','milestones','work_packages') for row in data[group]), 'Preserve reviewed claims; update mappings manually'
    index = {row['id']:row for group in ('requirements','apis','sdks','plugins','integrations','milestones','work_packages') for row in data[group]}
    def attach(ids, sources, reports, note, *, state='implemented-unverified', tests=()):
        for identifier in ids:
            row = index[identifier]
            row['status'] = state
            row['implementation'] = [artifact(ROOT, p) for p in sources]
            row['candidate_evidence'] = [artifact(ROOT,p) for p in reports]
            row['qualification_note'] = note
            row['observed_test_ids'] = list(tests)
            row['blockers'] = [note] if state in ('blocked','failed') else ['Full original acceptance and final-engine qualification remain open.']
    attach(['BAS-001','BAS-008','TST-001'],['tools/bootstrap_baseline.py','tools/ledger.py','tools/validate_release.py','tools/capture_contracts.py'],['evidence/contracts/capture-report.json'], 'Integrity/accounting only. All original IDs retained; no behavior completion inferred.')
    attach(['BAS-002','BAS-004','BAS-005'],['tools/audit_sources.py','tools/fetch_pinned_sources.py','tools/build_oss_core.py'],['evidence/build/oss-core/command.json','evidence/runs/source-reconstruction-01/command.json'], 'Pinned alternative source build exists; final dependency distribution and engine selection remain open.')
    attach(['BAS-003','BAS-006','IDN-011','LNK-001'],['tools/launch_oss_probe.py','tests/foundation/oss_core_probe.py'],['evidence/foundation/oss-core/results.json'], 'Alternative source candidate returns402 for required native app/tenant/link operations without entitlement; no enforcement was modified.',state='blocked')
    attach(['IDN-001','IDN-003','IDN-004','IDN-006'],['tests/foundation/keycloak_organizations.py','tests/foundation/keycloak_identity.py'],['evidence/foundation/keycloak-organizations/results.json','evidence/foundation/keycloak-identity/results.json'], 'Candidate realm/broker/organization behavior characterized, not product tenancy implementation; final foundation is blocked.',state='blocked')
    attach(['IDN-012','LNK-003','LNK-006','LNK-007','LNK-008'],['tests/foundation/keycloak_identity.py'],['evidence/foundation/keycloak-identity/results.json','evidence/foundation/keycloak-identity/independent-persistence-reread.json'], 'Keycloak candidate concurrent provider ownership and final-method unlink checks failed in fresh realms. Corrective agent turn rejected by automatic review; no extension implemented.',state='failed')
    attach(['PWD-001','SES-001','SES-002','SES-005','SES-006','SES-007','SES-011','CFG-002','CFG-004'],['examples/node-react/server.js','examples/python/app.py'],['evidence/runs/node-live-03/command.json','evidence/clients/python/probe-report.json'], 'Real password/default-public-tenant session slice in audited OSS candidate; full criteria, tenant/app profiles and final engine remain unqualified.',tests=['NODE-PWD-001','NODE-PWD-002','NODE-SESSION-002','NODE-OFFLINE-001','NODE-OFFLINE-002','NODE-COOKIE-001'])
    attach(['SDK-001','SDKP-01'],['examples/node-react/server.js','examples/node-react/package-lock.json'],['evidence/runs/node-live-03/command.json'], 'Representative Node password/session integration only. Exact upstream SDK with qualified Nodemailer override; complete SDK feature matrix remains open.')
    attach(['SDK-002','SDKP-02'],['examples/python/app.py','examples/python/requirements.lock'],['evidence/clients/python/probe-report.json'], 'Representative FastAPI integration:19 live HTTP checks, not complete Python profile. Cookie-client correction disclosed; no Python browser proof.')
    attach(['SDK-005','SDKP-05','TST-007'],['examples/node-react/client.jsx','tests/browser/oss-password.mjs'],['evidence/runs/browser-oss-05/command.json','evidence/browser/oss-password-05/results.json'], 'Chromium signup/signin/logout and320px layout passed after actual component/layout fixes. Not full accessibility, native or React feature qualification.',tests=['BROWSER-OSS-001','BROWSER-OSS-002','BROWSER-OSS-003','BROWSER-OSS-004'])
    attach(['SES-003','SES-004'],['tools/run_keycloak_cluster.py','tests/foundation/keycloak_sessions.py','tests/foundation/oss_core_probe.py'],['evidence/foundation/keycloak-sessions/probe-report.json','evidence/foundation/oss-core/results.json'], 'Both candidate strict rotation profiles fail required legitimate concurrency/response-loss behavior. Keycloak cluster7 passes/3 failures; no accepted rotation profile.',state='failed')
    for identifier in ('SDK-007','SDKP-07'):
        index[identifier]['status']='blocked'
        index[identifier]['blockers']=['Native iOS/macOS execution environment unavailable; native build/device tests unexecuted, not passed. Full implementation also remains open.']
    for row in data['apis']:
        row['status']='blocked'
        row['contract_reference']=artifact(ROOT,'contracts/api-contracts.json')
        row['blockers']=['All205 original IDs accounted; source-schema redistribution and complete runtime/differential qualification remain unresolved. Candidate routes are not full API parity.']
    for identifier, note in [('M0','Exact schemas, full license/distribution closure and unavailable advanced reference behavior remain unqualified.'),('M1','Identity/link concurrency gate failed; headless/client/session evidence cannot select an engine until every foundation case passes.'),('WP-001','205 IDs captured as source facts, not schema-complete behavior-qualified contracts.'),('WP-002','Full SDK/plugin/native/container license distribution closure incomplete.'),('WP-003','Owned reference labs operate; advanced entitled reference cases unavailable.'),('WP-004','Candidate proof is incomplete and has failed identity safety cases.'),('TST-006','Required independent human security review has not occurred.'),('WP-036','Required independent human security review and final release acceptance unavailable.')]:
        index[identifier]['status']='blocked'
        index[identifier]['blockers']=[note]
    data['checkpoint_claim']='PARTIAL: narrow candidate implementation only; zero complete baseline requirements or API operations certified'
    data['foundation_candidate_artifacts']=[artifact(ROOT,path) for path in ['evidence/foundation/keycloak-headless/build-report.json','evidence/foundation/keycloak-headless/probe-report.json','evidence/foundation/keycloak-clients/commands.json','evidence/foundation/keycloak-clients/http-results.json','evidence/foundation/keycloak-clients/browser-results.json','evidence/foundation/keycloak-sessions/probe-report.json']]
    index['WP-004']['implementation']=[artifact(ROOT,path) for path in ['engine-extensions/keycloak-headless/src/main/java/org/expertauth/keycloak/JsonPasswordAuthenticator.java','engine-extensions/keycloak-headless/src/main/java/org/expertauth/keycloak/JsonOtpAuthenticator.java','examples/keycloak-clients/server.mjs','examples/keycloak-clients/python_client.py','tools/run_keycloak_cluster.py']]
    index['WP-004']['candidate_evidence']=data['foundation_candidate_artifacts']
    data['dependency_lock_paths']=['examples/node-react/package-lock.json','examples/python/requirements.lock','tests/browser/package-lock.json','engine-extensions/oss-build/locks/gradle/verification-metadata.xml','engine-extensions/keycloak-headless/gradle.lockfile','engine-extensions/keycloak-headless/gradle/verification-metadata.xml','examples/keycloak-clients/package-lock.json','examples/keycloak-clients/requirements-test.txt']
    assert not integrity_errors(ROOT,data), integrity_errors(ROOT,data)
    write_json(path,data)
    print('Partial traceability updated; no verified acceptance claims were created.')

if __name__=='__main__':
    main()
