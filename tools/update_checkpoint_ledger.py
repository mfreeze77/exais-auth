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
    python_regression = 'evidence/operations/python-readiness/offline-build-buildkit-02/regression/probe-report.json'
    attach(['PWD-001','SES-001','SES-002','SES-005','SES-006','SES-007','SES-011','CFG-002','CFG-004'],['examples/node-react/server.js','examples/python/app.py'],['evidence/runs/node-live-03/command.json',python_regression], 'Real password/default-public-tenant session slice in audited OSS candidate; Python19 HTTP checks rerun against the current storage-readiness image. Full criteria, tenant/app profiles and final engine remain unqualified.',tests=['NODE-PWD-001','NODE-PWD-002','NODE-SESSION-002','NODE-OFFLINE-001','NODE-OFFLINE-002','NODE-COOKIE-001'])
    attach(['SDK-001','SDKP-01'],['examples/node-react/server.js','examples/node-react/package-lock.json'],['evidence/runs/node-live-03/command.json'], 'Representative Node password/session integration only. Exact upstream SDK with qualified Nodemailer override; complete SDK feature matrix remains open.')
    attach(['SDK-002','SDKP-02'],['examples/python/app.py','examples/python/requirements.lock','tests/clients/python_probe.py'],[python_regression], 'Representative FastAPI integration:19 live HTTP checks against the current image, not complete Python profile. Cookie-client correction disclosed; no Python browser proof. Its two synthetic users were removed after the test.')
    readiness_sources = ['examples/python/app.py','examples/python/.dockerignore','tools/run_python_readiness.py','tools/refresh_python_image.py','tools/run_sdk_session_faults.py','tests/operations/python_readiness.py','tests/clients/python_probe.py','tools/run_python_probe_cleanup_fault.py','tests/operations/python_probe_cleanup_fault.py']
    readiness_reports = ['evidence/operations/python-readiness/run-03/report.json','evidence/operations/python-readiness/run-03/probe-report.json','evidence/operations/python-readiness/image-02/report.json','evidence/operations/python-readiness/image-06/report.json',python_regression,'evidence/runs/python-readiness-repro-03/command.json','evidence/runs/python-current-image-regression-06/command.json','evidence/operations/python-probe-cleanup-fault/run-02/report.json','evidence/operations/python-probe-cleanup-fault/run-02/probe/fault-report.json']
    attach(['OPS-004','OPS-011'],readiness_sources,readiness_reports, 'Representative Python readiness now requires authenticated exact storage access and returns503 during a real owned PostgreSQL outage while liveness stays200. Same-volume recovery and existing-session continuity pass;6 checks include one cleanup row. No traffic removal, other dependency failures, load, HA, backup restore or full OPS acceptance is qualified.',tests=['PY-READY-HEALTHY-STORAGE','PY-READY-AUTH-BEFORE-OUTAGE','PY-READY-DATABASE-OUTAGE','PY-READY-DATABASE-RECOVERY','PY-READY-SESSION-CONTINUITY','PY-READY-SYNTHETIC-CLEANUP'])
    data['operational_candidate_artifacts'] = [artifact(ROOT,path) for path in readiness_reports]
    recovery_sources = ['tools/recovery_bundle.py','tools/run_recovery_drill.py','tests/operations/recovery_probe.py','tests/operations/test_recovery_bundle.py','reuse/recovery-components.json']
    recovery_reports = ['evidence/operations/recovery/run-01/report.json','evidence/operations/recovery/run-01/probe-report.json','evidence/operations/recovery/run-01/bundle-unittest.log','evidence/operations/recovery/run-01/evidence-validation.json','evidence/runs/encrypted-recovery-drill-01/command.json','evidence/runs/encrypted-recovery-evidence-validation-01/command.json']
    recovery_note = 'Reference-candidate encrypted backup/configuration restore into isolated tmpfs PostgreSQL/Core:28 real format tests,19 operational passes and1 historical-state characterization. Two owned post-snapshot revoke/delete actions replayed before restored-app startup; unexpired refresh tokens and deleted credentials denied, signing keys preserved. All9temporary containers and2fixture identities cleaned; original52identity set restored. No generalized durable reconciliation journal, off-machine key custody/rotation, PITR/HA, large-data/ACLs, failure-path injection, final engine or independent review qualification. WP-032/WP-033 dependency gates remain unmet.'
    recovery_probe = read_json(ROOT/'evidence/operations/recovery/run-01/probe-report.json')
    attach(['OPS-006'],recovery_sources,recovery_reports,recovery_note,
           tests=[row['id'] for row in recovery_probe['rows'] if row['status']=='passed'])
    data['recovery_candidate_artifacts'] = [artifact(ROOT,p) for p in recovery_reports]
    index['WP-033']['implementation'] = [artifact(ROOT,p) for p in recovery_sources]
    index['WP-033']['candidate_evidence'] = data['recovery_candidate_artifacts']
    index['WP-033']['qualification_note'] = recovery_note
    index['WP-033']['blockers'] = ['WP-032 and foundation prerequisites unmet; bounded independent reference-lab tooling does not close this package.']
    data['harness_lifecycle_sources'] = [artifact(ROOT,path) for path in ['tools/check_python_image_lifecycle.py','tools/refresh_python_image.py','tests/clients/python_probe.py']]
    data['harness_lifecycle_artifacts'] = [artifact(ROOT,path) for path in ['evidence/operations/python-image-lifecycle/source-drift-01/report.json','evidence/operations/python-image-lifecycle/source-drift-01/helper-evidence/report.json','evidence/operations/python-readiness/image-04/failure-diagnosis-and-retirement.json','evidence/operations/python-readiness/image-05/report.json']]
    for identifier in ('SDK-002','SDKP-02'):
        index[identifier]['candidate_evidence'] += data['operational_candidate_artifacts']
    attach(['SDK-005','SDKP-05','TST-007'],['examples/node-react/client.jsx','tests/browser/oss-password.mjs'],['evidence/runs/browser-oss-05/command.json','evidence/browser/oss-password-05/results.json'], 'Chromium signup/signin/logout and320px layout passed after actual component/layout fixes. Not full accessibility, native or React feature qualification.',tests=['BROWSER-OSS-001','BROWSER-OSS-002','BROWSER-OSS-003','BROWSER-OSS-004'])
    reset_sources = ['examples/node-react/server.js','examples/node-react/email-delivery.js','examples/node-react/client.jsx','examples/node-react/Dockerfile','examples/node-react/test/email-delivery.test.js','tests/browser/password-reset.mjs','tests/operations/password_reset_probe.mjs','tests/operations/password_reset_tls.py','tests/operations/password_reset_cleanup.py','tools/run_password_reset_lab.py','tools/build_node_client.py','reuse/password-reset-components.json']
    reset_reports = ['evidence/operations/password-reset/run-16/report.json','evidence/operations/password-reset/run-16/probe-results.json','evidence/operations/password-reset/run-16/browser-results.json','evidence/operations/password-reset/run-16/tls-results.json','evidence/operations/password-reset/run-16/runner-source.py','evidence/operations/password-reset/run-16/probe-source.mjs','evidence/operations/password-reset/cleanup-fault-01/report.json','evidence/operations/password-reset/cleanup-fault-01/cleanup-followup.json','evidence/runs/password-reset-unit-01/command.json','evidence/runs/password-reset-cleanup-fault-01/command.json','evidence/operations/node-client-build/reset-client-03/report.json']
    reset_reports.append('evidence/operations/password-reset/evidence-validation.json')
    reset_note = 'Reference-candidate reset through real authenticated TLS SMTP:10 transport,11 HTTP/SMTP and9 Chromium checks;55 configuration/content unit checks separately. Eight concurrent consumers yield exactly1winner; replay/expiry/sibling invalidation and post-reset online/refresh denial pass. All12containers/11fixtures cleaned and original52identities restored. Separate intentional exit73 proves one real fallback deletion and6container retirements. Exact run16 runner/probe snapshots retained; later cleanup-fault changes qualified separately. No configured cross-tenant/link, atomic password-commit/session-revocation, timing-enumeration resistance, durable outbox/retry, fresh deployment, full SDK/API/foundation or human-review qualification.'
    reset_probe = read_json(ROOT/'evidence/operations/password-reset/run-16/probe-results.json')
    attach(['PWD-006'],reset_sources,reset_reports,reset_note,
           tests=[row['id'] for row in reset_probe['rows'] if row['status']=='passed'])
    data['password_reset_candidate_artifacts'] = [artifact(ROOT,p) for p in reset_reports]
    for identifier in ('SDK-001','SDKP-01','SDK-005','SDKP-05'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in reset_sources]
        index[identifier]['candidate_evidence'] += data['password_reset_candidate_artifacts']
        index[identifier]['qualification_note'] += ' ' + reset_note
    for identifier, prerequisite in (('WP-009','WP-008'),('WP-010','WP-007')):
        index[identifier]['implementation'] = [artifact(ROOT,p) for p in reset_sources]
        index[identifier]['candidate_evidence'] = data['password_reset_candidate_artifacts']
        index[identifier]['qualification_note'] = reset_note
        index[identifier]['blockers'] = [prerequisite + ' and foundation prerequisites unmet; this independent reference slice does not close the package.']
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
    data['delivery_checkpoint_artifacts'] = [artifact(ROOT, path) for path in ['evidence/extracted-checkpoint/20260908T222920Z-23f3d2/report.json','evidence/operations/hygiene/verification-20260909T032659Z.json','evidence/runs/encrypted-recovery-hygiene-01/command.json','evidence/operations/hygiene/legacy-python-intermediates.json','evidence/operations/hygiene/legacy-python-fixture-parent.json']]
    data['delivery_checkpoint_artifacts'].append(artifact(ROOT,'evidence/operations/hygiene/checkpoint-retention-before-recovery.json'))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in ['evidence/operations/hygiene/verification-20260909T050303Z.json','evidence/operations/hygiene/password-reset-host-cache-blocked.json','evidence/operations/hygiene/checkpoint-retention-before-password-reset.json']]
    for identifier in ('BAS-001','TST-001'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in ['tools/package_checkpoint.py','tests/evidence/test_checkpoint_secrets.py']]
        index[identifier]['candidate_evidence'] += [artifact(ROOT,'evidence/runs/checkpoint-secret-file-tests-03/command.json')]
        index[identifier]['qualification_note'] += ' Packager scans actual credential bytes for the exact private SMTP mount and enforces a three-ZIP ceiling. Fourteen focused secret-file cases pass; link/reparse branches and full generic secret scanning remain unqualified.'
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
    python_build_sources = ['tools/build_python_runtime.py','tools/fetch_python_wheels.py','tools/verify_python_distribution.py','tools/refresh_python_image.py','examples/python/Dockerfile','examples/python/requirements.lock','examples/python/dependency-resolution.json']
    python_build_reports = ['evidence/operations/python-offline-build/buildkit-01/report.json','evidence/operations/python-offline-build/buildkit-01/VERIFIER_CORRECTION.md','evidence/operations/python-offline-build/buildkit-02/report.json','evidence/operations/python-offline-build/buildkit-02/distribution/distribution.json','evidence/reuse/python-wheel-cache/buildkit-01/acquisition.json','evidence/reuse/python-wheel-cache/buildkit-02/acquisition.json','evidence/operations/python-readiness/offline-build-buildkit-02/report.json','evidence/runs/python-offline-build-02/command.json','evidence/runs/python-wheel-offline-missing-01/command.json']
    data['python_build_candidate_artifacts'] = [artifact(ROOT,path) for path in python_build_reports]
    for identifier in ('BAS-002','BAS-004','BAS-005','SDK-002','SDKP-02','WP-002'):
        index[identifier]['implementation'] += [artifact(ROOT,path) for path in python_build_sources]
        index[identifier]['candidate_evidence'] += data['python_build_candidate_artifacts']
        if identifier == 'WP-002':
            index[identifier]['qualification_note'] = 'Full dependency closure remains open.'
        index[identifier]['qualification_note'] += ' Python5bffadb83aa3 full offline BuildKit build uses49 locked wheels and verifies3349 installed wheel files,63 notices,418 SDK source files and19 HTTP checks. Prior image and test clients retired; Core/database unchanged. Empty-directory checker correction disclosed. Native/OS/source obligations, fresh-stack and new lifecycle fault qualification remain open.'
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
    node_build_sources = ['examples/node-react/Dockerfile','examples/node-react/.dockerignore',
        'tools/build_node_runtime.py','tools/node_runtime_identity.py','tools/build_node_client.py',
        'tools/export_node_packages.mjs','tools/verify_node_runtime.mjs','tests/reuse/node_package_boundaries.mjs',
        'tools/audit_nodemailer_correspondence.py','reuse/nodemailer-9.1.1-source-correspondence.json',
        'tools/verify_node_build_evidence.py','tools/retire_legacy_node_images.py','tools/retire_node_checkpoint_zip.py']
    node_build_reports = ['evidence/operations/node-image-build/offline-build-02/report.json',
        'evidence/operations/node-image-build/offline-build-02/candidate-runtime/runtime-report.json',
        'evidence/operations/node-image-build/offline-build-02/previous-runtime/runtime-report.json',
        'evidence/operations/node-image-build/offline-build-02/parser-boundaries/node-package-boundaries.json',
        'evidence/operations/node-image-build/offline-build-02/command-016.log',
        'evidence/operations/node-image-build/evidence-validation-02.json',
        'evidence/operations/node-client-build/promoted-node-01/report.json',
        'reuse/nodemailer-9.1.1-source-correspondence.json']
    installed_reset_reports = ['evidence/operations/password-reset/installed-offline-build-02/' + name
        for name in ('report.json','probe-results.json','tls-results.json','browser-results.json')]
    node_build_sources += ['tools/fetch_node_packages.mjs','tools/run_node_bootstrap.py',
        'tests/reuse/node_bootstrap_probe.mjs','tools/verify_node_bootstrap_evidence.py',
        'tools/retire_bootstrap_checkpoint_zip.py']
    node_build_reports += ['evidence/operations/node-image-build/deterministic-source-mode-02/' + name
        for name in ('report.json','candidate-runtime/runtime-report.json','previous-runtime/runtime-report.json',
                     'parser-boundaries/node-package-boundaries.json')]
    node_build_reports += ['evidence/operations/node-image-build/evidence-validation-deterministic-02.json',
        'evidence/operations/node-image-build/deterministic-source-mode-01/report.json',
        'evidence/operations/node-image-build/copy-mode-diagnosis-01/report.json',
        'evidence/operations/node-image-build/copy-mode-diagnosis-01/inventory-followup.json',
        'evidence/operations/node-bootstrap/evidence-validation-02.json']
    bootstrap_reports = ['evidence/operations/node-bootstrap/fresh-registry-03/' + name for name in
        ('report.json','online-probe.json','offline-probe.json','fresh-registry.json','fresh-runtime-report.json','offline-commands.json')]
    data['node_bootstrap_candidate_artifacts'] = [artifact(ROOT,p) for p in bootstrap_reports]
    node_build_reports += bootstrap_reports
    installed_reset_reports += ['evidence/operations/password-reset/installed-deterministic-source-mode-02/' + name
        for name in ('report.json','probe-results.json','tls-results.json','browser-results.json')]
    node_build_note = 'Current offline image4c03d7306e1e uses deterministic0644 application files and0755 public directory;143 packages,7629 original members and the complete dependency tree match the earlier audit. All8 application files match source/generated bytes;55 unit,8 actual-parser and30 installed reset/transport/browser checks pass. All16 build/reset containers and11 owned identities retired, original52 identities and persistent processes/configuration preserved; previous image2c4ad0be07b8 removed after promotion with no parent/global prune. Fresh registry bootstrap passes11 actual online concurrency/integrity/resume and disconnected offline cache/install/compile checks; one temporary container retired, no extra host cache/image/volume/network retained. Single cache14,891,202 bytes includes14,580,488 archive bytes. Failed noexec, file/directory-mode and cleanup-race observations are preserved; evidence validators qualify source/log integrity only. Full first-image/stack bootstrap, cache-crash/stale-lock/partial-file recovery, actual HTTP timeout/redirect/oversize/truncation, native/OS distribution, deprecated dependency replacement and new lifecycle faults remain unqualified. No foundation/full requirement/API/profile or independent human review pass inferred. Earlier build/report history remains preserved.'
    data['node_build_candidate_artifacts'] = [artifact(ROOT,p) for p in node_build_reports + installed_reset_reports]
    for identifier in ('BAS-002','BAS-004','BAS-005','SDK-001','SDKP-01','SDK-005','SDKP-05','PWD-006','WP-002','WP-009','WP-010'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in node_build_sources]
        index[identifier]['candidate_evidence'] += data['node_build_candidate_artifacts']
        index[identifier]['qualification_note'] += ' ' + node_build_note
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/legacy-node-intermediates.json',
        'evidence/operations/hygiene/verification-20260909T055142Z.json',
        'evidence/operations/hygiene/node-build-disk-inventory.json',
        'evidence/operations/hygiene/checkpoint-retention-before-node-build.json')]
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T064650Z.json',
        'evidence/operations/hygiene/node-bootstrap-disk-inventory.json',
        'evidence/operations/hygiene/checkpoint-retention-before-node-bootstrap.json')]
    data['dependency_lock_paths']=['examples/node-react/package-lock.json','examples/python/requirements.lock','tests/browser/package-lock.json','engine-extensions/oss-build/locks/gradle/verification-metadata.xml','engine-extensions/keycloak-headless/gradle.lockfile','engine-extensions/keycloak-headless/gradle/verification-metadata.xml','examples/keycloak-clients/package-lock.json','examples/keycloak-clients/requirements-test.txt','reuse/runtime-source-archives.lock.json']
    atomic_sources = ['engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordReset.java',
        'engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordResetAPI.java',
        'engine-extensions/core-reset/reuse.json', 'tools/build_core_reset.py', 'tools/run_atomic_reset_lab.py',
        'tests/operations/AtomicResetProbe.java', 'examples/node-react/server.js', 'tools/run_password_reset_lab.py',
        'tests/operations/password_reset_probe.mjs', 'tools/verify_atomic_reset_evidence.py', 'docs/atomic-password-reset.md']
    atomic_reports = ['evidence/operations/core-reset-build/compile-03/report.json',
        'evidence/operations/core-reset-build/compile-03/jar-members.json',
        'evidence/operations/atomic-reset/run-02/report.json', 'evidence/operations/atomic-reset/run-02/probe-report.json',
        'evidence/operations/atomic-reset/node-03/report.json', 'evidence/operations/atomic-reset/evidence-validation.json']
    atomic_reports += ['evidence/operations/password-reset/atomic-node-03/' + name for name in
        ('report.json','probe-results.json','browser-results.json','tls-results.json','reset-success.png')]
    atomic_note = 'Current opt-in atomic-v1 profile uses explicit Core JAR and Node source mounts; retained images contain earlier code. Core transaction commits context-bound token consumption/password update/existing-session deletion together. Eight real Core cases include two-replica eight-consumer race, actual PostgreSQL backend abort at session deletion with complete rollback and same-token retry, external-ID revocation and expiry. Node child passes13 HTTP/SMTP,10 TLS and9 Chromium cases including legacy-token rejection/reissue and older-Core API mismatch/readiness503 without fallback; fixture cleanup passes and all17 containers retire. Persistent database never contacted, no new images/volumes/networks retained.105 correspondence checks are integrity only. Node-02 product cases passed but preservation check failed on varying mount order; its report stays failed, node-03 compares all sorted mount values and records both projections. Sign-in validation followed by post-reset session issuance, mixed legacy writers, linked/configured namespace contexts, optional SDK email-verification/link/new-password-method side effects, lost commit responses, installed/fresh deployment, complete baseline API/SDK/profile behavior and independent human security review remain unqualified. Historical image/reset artifacts are bound to their original source; no current-source pass is inferred from them. No baseline requirement is verified.'
    data['atomic_reset_candidate_artifacts'] = [artifact(ROOT,p) for p in atomic_reports]
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T074428Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-atomic-reset.json',
        'evidence/operations/atomic-reset/checkpoint-checks.json')]
    for identifier in ('PWD-006','SES-005','SES-006','SDK-001','SDKP-01','SDK-005','SDKP-05','WP-009','WP-010'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in atomic_sources]
        index[identifier]['candidate_evidence'] += data['atomic_reset_candidate_artifacts']
        index[identifier]['qualification_note'] += ' ' + atomic_note
        index[identifier]['observed_test_ids'] = list(dict.fromkeys(index[identifier].get('observed_test_ids',[]) +
            [r['id'] for r in read_json(ROOT/'evidence/operations/atomic-reset/run-02/probe-report.json')['rows']] +
            [r['id'] for r in read_json(ROOT/'evidence/operations/password-reset/atomic-node-03/probe-results.json')['rows']]))
    password_session_sources = ['engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSession.java',
        'engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSessionAPI.java',
        'engine-extensions/core-reset/src/io/expertauth/core/TransactionalSessionWriter.java',
        'engine-extensions/core-reset/postgresql/io/supertokens/storage/postgresql/ExpertAuthSessionWriter.java',
        'tools/build_password_session.py','tools/run_atomic_reset_lab.py','tools/run_password_reset_lab.py',
        'examples/node-react/server.js','tests/operations/PasswordSessionProbe.java','tests/operations/password_reset_probe.mjs',
        'tests/operations/password_session_wire.mjs','tools/report_password_session_reuse.py',
        'reuse/password-session-components.json','tools/verify_password_session_evidence.py','docs/password-session-transactions.md']
    password_session_reports = ['evidence/operations/password-session-build/compile-03/'+name for name in
        ('report.json','Session.java','Webserver.java','core-members.json','postgresql-members.json')]
    password_session_reports += ['evidence/operations/atomic-reset/session-02/'+name for name in
        ('report.json','probe-report.json','password-session-report.json')]
    password_session_reports += ['evidence/operations/atomic-reset/session-node-02/report.json',
        'evidence/operations/atomic-reset/password-session-validation.json']
    password_session_reports += ['evidence/operations/password-reset/atomic-session-node-02/'+name for name in
        ('report.json','probe-results.json','browser-results.json','tls-results.json','wire/good.jsonl','reset-success.png')]
    password_session_note = 'Current explicit atomic-v1 Node sign-in/signup profile uses supported request-scoped SDK API/network overrides and Core password-session API, CDI5.4. Original hasher and token minting are reused; credential/hash/identity-mapping recheck and session insertion share one user-locked transaction through a PostgreSQL storage writer, without nested connection borrow or adapter-owned state.16 actual Core cases pass (8 reset and8 password-session), including both lock orderings, backend termination at insertion with no leaked session/retry, eight concurrent creations and external IDs. Node passes14 HTTP/SMTP,10 TLS and9 Chromium behavior cases; eight distinct concurrent users preserve subjects. Test-only unmodified-fetch observation records36 successful new private session calls and zero legacy calls; all17 final-lab containers retire, original database uncontacted, no images/volumes/networks retained. Compile03 adds explicit source modification notices and reproduces tested compile02 Core/plugin bytes exactly.128 correspondence checks are integrity only. Prior wrong-table test and lost-proxy-receiver failures remain preserved. This resolves the demonstrated validation/insertion race for this profile only; earlier atomic-only evidence and limitations remain historical. Other SDKs/legacy writers, configured namespace/link/MFA/step-up, missing-writer deployment faults, lost committed responses, load/pool saturation, migration/rolling deployment, complete transitive/native/OS distribution and independent human review remain unqualified. No foundation or full requirement/API/profile pass is inferred.'
    data['password_session_candidate_artifacts'] = [artifact(ROOT,p) for p in password_session_reports]
    for identifier in ('PWD-006','SES-001','SES-005','SES-006','SDK-001','SDKP-01','SDK-005','SDKP-05','WP-009','WP-010'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in password_session_sources]
        index[identifier]['candidate_evidence'] += data['password_session_candidate_artifacts']
        index[identifier]['qualification_note'] += ' ' + password_session_note
        index[identifier]['observed_test_ids'] = list(dict.fromkeys(index[identifier].get('observed_test_ids',[]) +
            [r['id'] for r in read_json(ROOT/'evidence/operations/atomic-reset/session-02/password-session-report.json')['rows']] +
            [r['id'] for r in read_json(ROOT/'evidence/operations/password-reset/atomic-session-node-02/probe-results.json')['rows']]))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/checkpoint-retention-before-password-session.json',
        'evidence/operations/hygiene/reset-only-candidate-retirement.json',
        'evidence/operations/hygiene/verification-20260909T083106Z.json',
        'evidence/operations/atomic-reset/password-session-checkpoint-checks.json')]
    assert not integrity_errors(ROOT,data), integrity_errors(ROOT,data)
    write_json(path,data)
    print('Partial traceability updated; no verified acceptance claims were created.')

if __name__=='__main__':
    main()
