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
    python_regression = 'evidence/operations/python-readiness/notice-core-regression-01/regression/probe-report.json'
    attach(['PWD-001','SES-001','SES-002','SES-005','SES-006','SES-007','SES-011','CFG-002','CFG-004'],['examples/node-react/server.js','examples/python/app.py'],['evidence/runs/node-live-03/command.json',python_regression], 'Real password/default-public-tenant session slice in audited OSS candidate; Python19 HTTP checks rerun against the current storage-readiness image. Full criteria, tenant/app profiles and final engine remain unqualified.',tests=['NODE-PWD-001','NODE-PWD-002','NODE-SESSION-002','NODE-OFFLINE-001','NODE-OFFLINE-002','NODE-COOKIE-001'])
    attach(['SDK-001','SDKP-01'],['examples/node-react/server.js','examples/node-react/package-lock.json'],['evidence/runs/node-live-03/command.json'], 'Representative Node password/session integration only. Exact upstream SDK with qualified Nodemailer override; complete SDK feature matrix remains open.')
    attach(['SDK-002','SDKP-02'],['examples/python/app.py','examples/python/requirements.lock','tests/clients/python_probe.py'],[python_regression], 'Representative FastAPI integration:19 live HTTP checks against the current image, not complete Python profile. Cookie-client correction disclosed; no Python browser proof. Its two synthetic users were removed after the test.')
    readiness_sources = ['examples/python/app.py','examples/python/.dockerignore','tools/run_python_readiness.py','tools/refresh_python_image.py','tools/run_sdk_session_faults.py','tests/operations/python_readiness.py','tests/clients/python_probe.py','tools/run_python_probe_cleanup_fault.py','tests/operations/python_probe_cleanup_fault.py']
    readiness_reports = ['evidence/operations/python-readiness/run-03/report.json','evidence/operations/python-readiness/run-03/probe-report.json','evidence/operations/python-readiness/image-02/report.json','evidence/operations/python-readiness/image-06/report.json',python_regression,'evidence/runs/python-readiness-repro-03/command.json','evidence/runs/python-current-image-regression-06/command.json','evidence/operations/python-probe-cleanup-fault/run-02/report.json','evidence/operations/python-probe-cleanup-fault/run-02/probe/fault-report.json']
    attach(['OPS-004','OPS-011'],readiness_sources,readiness_reports, 'Representative Python readiness now requires authenticated exact storage access and returns503 during a real owned PostgreSQL outage while liveness stays200. Same-volume recovery and existing-session continuity pass;6 checks include one cleanup row. No traffic removal, other dependency failures, load, HA, backup restore or full OPS acceptance is qualified.',tests=['PY-READY-HEALTHY-STORAGE','PY-READY-AUTH-BEFORE-OUTAGE','PY-READY-DATABASE-OUTAGE','PY-READY-DATABASE-RECOVERY','PY-READY-SESSION-CONTINUITY','PY-READY-SYNTHETIC-CLEANUP'])
    data['operational_candidate_artifacts'] = [artifact(ROOT,path) for path in readiness_reports]
    data['harness_lifecycle_sources'] = [artifact(ROOT,path) for path in ['tools/check_python_image_lifecycle.py','tools/refresh_python_image.py','tests/clients/python_probe.py']]
    data['harness_lifecycle_artifacts'] = [artifact(ROOT,path) for path in ['evidence/operations/python-image-lifecycle/source-drift-01/report.json','evidence/operations/python-image-lifecycle/source-drift-01/helper-evidence/report.json','evidence/operations/python-readiness/image-04/failure-diagnosis-and-retirement.json','evidence/operations/python-readiness/image-05/report.json']]
    for identifier in ('SDK-002','SDKP-02'):
        index[identifier]['candidate_evidence'] += data['operational_candidate_artifacts']
    attach(['SDK-005','SDKP-05','TST-007'],['examples/node-react/client.jsx','tests/browser/oss-password.mjs'],['evidence/runs/browser-oss-05/command.json','evidence/browser/oss-password-05/results.json'], 'Chromium signup/signin/logout and320px layout passed after actual component/layout fixes. Not full accessibility, native or React feature qualification.',tests=['BROWSER-OSS-001','BROWSER-OSS-002','BROWSER-OSS-003','BROWSER-OSS-004'])
    attach(['SES-003','SES-004'],['tools/run_keycloak_cluster.py','tests/foundation/keycloak_sessions.py','tests/foundation/oss_core_probe.py'],['evidence/foundation/keycloak-sessions/probe-report.json','evidence/foundation/oss-core/results.json'], 'Keycloak strict-profile7 passes/3 failures and separate Core CDI5.6 zero-grace availability failure remain. Maintained Node CDI5.4 has narrow transport/restart/browser passes but fails uncoordinated raw-header availability; complete versioned policy and foundation remain unqualified.',state='failed')
    for identifier in ('SDK-007','SDKP-07'):
        index[identifier]['status']='blocked'
        index[identifier]['blockers']=['Native iOS/macOS execution environment unavailable; native build/device tests unexecuted, not passed. Full implementation also remains open.']
    for row in data['apis']:
        row['status']='blocked'
        row['contract_reference']=artifact(ROOT,'contracts/api-contracts.json')
        row['blockers']=['All205 original IDs accounted; source-schema redistribution and complete runtime/differential qualification remain unresolved. Candidate routes are not full API parity.']
    for identifier in ('FDI-026','CDI-099','CDI-104','CDI-116'):
        row = index[identifier]
        row['implementation'] = [artifact(ROOT, path) for path in ['contracts/runtime-path-resolutions.json','tests/contracts/runtime_path_probe.py']]
        row['candidate_evidence'] = [artifact(ROOT, path) for path in ['evidence/contracts/runtime-paths/probe-report.json','evidence/contracts/runtime-paths/source-report.json','evidence/contracts/runtime-paths/validation-report.json']]
        row['qualification_note'] = 'ASCII wire paths independently derived from pinned Apache sources and tested;9 actual checks across4 original IDs passed. Original capture unchanged. Complete schemas/versions/tenants and operation qualification remain blocked; CDI-104 legacy identifier discrepancy preserved.'
    for identifier, note in [('M0','Exact schemas, full license/distribution closure and unavailable advanced reference behavior remain unqualified.'),('M1','Identity/link concurrency gate failed; headless/client/session evidence cannot select an engine until every foundation case passes.'),('WP-001','205 IDs captured as source facts, not schema-complete behavior-qualified contracts.'),('WP-002','Full SDK/plugin/native/container license distribution closure incomplete.'),('WP-003','Owned reference labs operate; advanced entitled reference cases unavailable.'),('WP-004','Candidate proof is incomplete and has failed identity safety cases.'),('TST-006','Required independent human security review has not occurred.'),('WP-036','Required independent human security review and final release acceptance unavailable.')]:
        index[identifier]['status']='blocked'
        index[identifier]['blockers']=[note]
    data['checkpoint_claim']='PARTIAL: narrow candidate implementation only; zero complete baseline requirements or API operations certified'
    data['delivery_checkpoint_artifacts'] = [artifact(ROOT, path) for path in ['evidence/extracted-checkpoint/20260908T222920Z-23f3d2/report.json','evidence/operations/hygiene/verification-20260909T010630Z.json','evidence/runs/hygiene-runner-integrity-03/command.json']]
    data['foundation_candidate_artifacts']=[artifact(ROOT,path) for path in ['evidence/foundation/keycloak-headless/build-report.json','evidence/foundation/keycloak-headless/probe-report.json','evidence/foundation/keycloak-clients/commands.json','evidence/foundation/keycloak-clients/http-results.json','evidence/foundation/keycloak-clients/browser-results.json','evidence/foundation/keycloak-sessions/probe-report.json']]
    runtime_sources = ['tools/build_oss_runtime.py','tools/assemble_runtime_licenses.py','tools/fetch_runtime_notice_sources.py','tools/replace_oss_notice_image.py','deploy/oss-core.Dockerfile','reuse/runtime-source-archives.lock.json']
    runtime_sources += ['tools/capture_native_sources.py','tools/run_native_source_capture.py','tools/qualify_native_argon2.py','tools/verify_notice_revision.py','reuse/native-header-notices.lock.json','tests/reuse/test_native_source_capture.py','tests/reuse/test_runtime_distribution.py']
    runtime_reports = ['evidence/runtime/oss-core-notices/preserved-notices-01/report.json','evidence/runtime/oss-core-notices/replacement-20260908T232129Z-99cdc5/report.json','evidence/runtime/oss-core-notices/same-image-guard-verification.json','evidence/runs/runtime-notice-package-tests-03/command.json','evidence/reuse/runtime-distribution-review/supplemental-notices.json','evidence/reuse/runtime-distribution-review/archive-inventory.json']
    runtime_reports += ['evidence/reuse/native-correspondence/notice-packaging/run-02/report.json','evidence/runs/native-source-and-notice-tests-01/command.json','evidence/reuse/native-correspondence/scrypt/source-manifest.json','evidence/reuse/native-correspondence/scrypt/verification.json','evidence/reuse/native-correspondence/argon2/release-bindings.json','evidence/reuse/native-correspondence/jna/acquired-review.json','evidence/reuse/native-correspondence/sqlite/research/release-bindings.json','evidence/reuse/native-correspondence/sqlite/research/acquired-verification.json','evidence/reuse/native-correspondence/validation/hash-mismatch/run-01/container.json']
    data['runtime_distribution_artifacts'] = [artifact(ROOT,path) for path in runtime_reports]
    data['runtime_distribution_artifacts'] += [artifact(ROOT,'evidence/runs/native-source-request-prefix-fix-02/command.json')]
    current_notice_reports = ['evidence/runtime/oss-core-notices/buildkit-notices-01/report.json','evidence/runtime/oss-core-notices/buildkit-notices-02/report.json','evidence/runtime/oss-core-notices/buildkit-notices-03/report.json','evidence/runtime/oss-core-notices/replacement-20260909T021339Z-af0c4b/report.json','evidence/runs/runtime-notice-cutover-01/command.json','evidence/runs/runtime-notice-same-image-guard-02/command.json','evidence/operations/python-readiness/notice-core-regression-01/report.json','evidence/operations/hygiene/verification-20260909T021650Z.json','evidence/reuse/native-correspondence/jna/grant-review/findings.json']
    data['runtime_distribution_artifacts'] += [artifact(ROOT,path) for path in current_notice_reports]
    for identifier in ('BAS-002','BAS-004','BAS-005'):
        index[identifier]['implementation'] += [artifact(ROOT,path) for path in runtime_sources]
        index[identifier]['candidate_evidence'] += data['runtime_distribution_artifacts']
        index[identifier]['qualification_note'] = 'Corrected notice package installed in Core5ec6ccc3fd5d:479 files match, including87 unchanged JARs and89 archive notice texts. Same-container PostgreSQL state/mounts preserved;19Python HTTP regressions pass with2own-user cleanups. BuildKit failure candidate and oldCore container/image retired; current-image repeat replacement rejected. Native release bytes identified, not reproducibly built; full selected-engine/native/OS distribution, source/relink and human review remain unqualified.'
    index['WP-002']['implementation'] = [artifact(ROOT,path) for path in runtime_sources]
    index['WP-002']['candidate_evidence'] = data['runtime_distribution_artifacts']
    index['WP-004']['implementation']=[artifact(ROOT,path) for path in ['engine-extensions/keycloak-headless/src/main/java/org/expertauth/keycloak/JsonPasswordAuthenticator.java','engine-extensions/keycloak-headless/src/main/java/org/expertauth/keycloak/JsonOtpAuthenticator.java','examples/keycloak-clients/server.mjs','examples/keycloak-clients/python_client.py','tools/run_keycloak_cluster.py']]
    index['WP-004']['candidate_evidence']=data['foundation_candidate_artifacts']
    session_sources = ['contracts/session-policy-oss-node-cdi54-v1.json','tools/run_sdk_session_faults.py','tests/foundation/sdk_session_faults.mjs','tests/browser/session-coordination.mjs']
    session_reports = ['evidence/foundation/sdk-session-faults/run-05/report.json','evidence/foundation/sdk-session-faults/run-05/sdk-results.json','evidence/foundation/sdk-session-faults/run-05/browser-results.json','evidence/runs/sdk-session-memory-proof-05/command.json','evidence/foundation/session-policy-review/README.md']
    data['session_candidate_artifacts'] = [artifact(ROOT,path) for path in session_reports]
    for identifier in ('SES-003','SES-004','SES-005','SDK-001','SDKP-01','SDK-005','SDKP-05','TST-007','WP-004'):
        index[identifier]['implementation'] += [artifact(ROOT,path) for path in session_sources]
        index[identifier]['candidate_evidence'] += data['session_candidate_artifacts']
    for identifier in ('SES-003','SES-004'):
        index[identifier]['observed_test_ids'] += ['SDK54-WIRE-PROTOCOL','SDK54-SERIAL-PROMOTION','SDK54-LOSS-BEFORE-FORWARD','SDK54-LOSS-AFTER-UPSTREAM-BODY','SDK54-LOSS-PARTIAL-BODY','SDK54-COMMITTED-PROMOTION-CRASH','SDK54-UNCOORDINATED-CLIENT-AVAILABILITY','SDK54-BROWSER-FOUR-TAB-REFRESH']
    data['dependency_lock_paths']=['examples/node-react/package-lock.json','examples/python/requirements.lock','tests/browser/package-lock.json','engine-extensions/oss-build/locks/gradle/verification-metadata.xml','engine-extensions/keycloak-headless/gradle.lockfile','engine-extensions/keycloak-headless/gradle/verification-metadata.xml','examples/keycloak-clients/package-lock.json','examples/keycloak-clients/requirements-test.txt','reuse/runtime-source-archives.lock.json']
    assert not integrity_errors(ROOT,data), integrity_errors(ROOT,data)
    write_json(path,data)
    print('Partial traceability updated; no verified acceptance claims were created.')

if __name__=='__main__':
    main()
