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
    index['WP-004']['qualification_note']='Original foundation identity mapping and concurrency acceptance remain incomplete; candidate evidence cannot select an engine.'
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
    installed_atomic_sources = ['tools/build_node_runtime.py','tools/run_atomic_reset_lab.py','tools/run_password_reset_lab.py',
        'tools/verify_node_build_evidence.py','tests/operations/password_reset_probe.mjs','tests/operations/password_session_wire.mjs',
        'examples/node-react/server.js','examples/node-react/Dockerfile','docs/atomic-node-installation.md']
    installed_atomic_reports = ['evidence/operations/node-image-build/atomic-password-session-02/'+p for p in
        ('report.json','candidate-runtime/runtime-report.json','previous-runtime/runtime-report.json','parser-boundaries/node-package-boundaries.json')]
    installed_atomic_reports += ['evidence/operations/node-image-build/evidence-validation-atomic-password-session-02.json',
        'evidence/operations/atomic-reset/installed-atomic-password-session-02/report.json']
    installed_atomic_reports += ['evidence/operations/password-reset/atomic-installed-atomic-password-session-02/'+p for p in
        ('report.json','probe-results.json','tls-results.json','browser-results.json','wire/good.jsonl','wire/missing-writer.jsonl','reset-success.png')]
    data['installed_atomic_node_candidate_artifacts']=[artifact(ROOT,p) for p in installed_atomic_reports]
    installed_atomic_note = 'Current installed Node image9375a5bc093d contains atomic reset/password-session integration and passes15 HTTP/SMTP,10 TLS and9 browser behavior cases without application mounts. Core remains mounted as the exact compile03 JAR pair. Actual new-Core/old-PostgreSQL-plugin mismatch stays live200/not-ready503, rejects sign-in500/Core503 without tokens/cookies or session insertion, preserves the prior session and permits healthy-writer retry.38 real successful private session calls and1 rejected call are observed without token/credential bodies or legacy insertion.22 owned fixtures removed; no source database contact. Four build helpers and19 runtime containers retired per run; no image downloads, new volumes/networks/ports. Installed143 packages/7629 original members/dependency tree unchanged,8 app files match current bytes,55 delivery unit and8 parser checks pass. Corrected observer allowlist resolves the preserved first-run test defect; all7 application/dependency build layers reused on corrected run. Successful image replaces and retires4c03d7306e1e.267 source/log/binary correspondence checks are integrity only. Docker registry metadata resolution is not an air-gapped build proof. Installed Core/fresh-stack, other SDK/namespace/link/MFA, load/migration/rolling upgrade, complete distribution and independent human review remain unqualified. No full baseline row or foundation gate is certified.'
    for identifier in ('BAS-002','BAS-004','BAS-005','PWD-006','SES-001','SDK-001','SDKP-01','SDK-005','SDKP-05','OPS-004','OPS-011','WP-002','WP-009','WP-010'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in installed_atomic_sources]
        index[identifier]['candidate_evidence'] += data['installed_atomic_node_candidate_artifacts']
        index[identifier]['qualification_note'] += ' '+installed_atomic_note
        index[identifier]['observed_test_ids']=list(dict.fromkeys(index[identifier].get('observed_test_ids',[])+
            [r['id'] for r in read_json(ROOT/'evidence/operations/password-reset/atomic-installed-atomic-password-session-02/probe-results.json')['rows']]))
    for identifier in ('BAS-001','TST-001'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in ['tools/package_checkpoint.py','tests/evidence/test_checkpoint_secrets.py']]
        index[identifier]['candidate_evidence'] += [artifact(ROOT,'evidence/runs/checkpoint-secret-file-tests-05/command.json')]
        index[identifier]['qualification_note'] += ' Current missing-writer SMTP mount is included in the exact credential scan;16 focused scanner tests pass. Generic secret discovery and independent review remain unqualified.'
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'tools/retire_checkpoint.py',
        'tools/verify_extracted_node.py',
        'evidence/operations/hygiene/verification-20260909T084810Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-atomic-node-install.json')]
    installed_core_sources = ['tools/core_compiler_inputs.py','tools/build_password_session.py',
        'tools/atomic_core_identity.py','tools/build_atomic_core_runtime.py','tools/replace_atomic_core.py',
        'tools/run_atomic_reset_lab.py','tools/run_password_reset_lab.py','tools/run_recovery_drill.py',
        'tools/run_sdk_session_faults.py','tools/verify_atomic_core_installation.py',
        'tests/operations/core_upgrade_probe.py','docs/installed-atomic-core.md']
    installed_core_reports = ['evidence/operations/password-session-build/compile-04/'+p for p in
        ('report.json','core-members.json','postgresql-members.json','Session.java','Webserver.java')]
    installed_core_reports += ['evidence/operations/atomic-core-image/installed-02/'+p for p in
        ('report.json','qualification.json','notice-manifest.json','adaptation-runtime.cdx.json','correspondence.json')]
    installed_core_reports += ['evidence/operations/atomic-reset/image-core-installed-02/'+p for p in
        ('report.json','probe-report.json','password-session-report.json')]
    installed_core_reports += ['evidence/operations/atomic-reset/image-node-installed-02/report.json']
    installed_core_reports += ['evidence/operations/password-reset/atomic-image-node-installed-02/'+p for p in
        ('report.json','probe-results.json','tls-results.json','browser-results.json',
         'wire/good.jsonl','wire/missing-writer.jsonl','reset-success.png')]
    installed_core_reports += ['evidence/operations/atomic-core-replacement/installed-02/'+p for p in
        ('report.json','seed.json','upgraded.json','rollback.json','final.json','cleanup.json')]
    data['installed_atomic_core_candidate_artifacts'] = [artifact(ROOT,p) for p in installed_core_reports]
    data['installed_atomic_core_failed_history'] = [artifact(ROOT,'evidence/operations/atomic-core-image/installed-01/report.json')]
    installed_core_note = ('Current Core image03b4458c532f contains the compile04 atomic Core/plugin pair; '
        'healthy Core and Node flows have no application/JAR overlays. Direct pinned JDK compilation with87 '
        'audited original cache JARs reproduces compile03 bytes. All483 installed files match;85 original JARs '
        'unchanged and4 adaptation license/source-map/SBOM files added.16 actual Core,34 installed Node/SMTP/TLS/browser '
        'and14 local upgrade/rollback cases pass. Legacy sessions/refresh/password sign-in survive upgrade, rollback '
        'and re-upgrade; a new atomic-session write remains usable after rollback. The sole synthetic identity is '
        'removed and the exact original52 identity set, PostgreSQL process/volume and private configuration are '
        'preserved. Schema dumps match after excluding only generated psql restriction nonces. The private193742-byte '
        'pre-upgrade dump is hashed, not restore-tested. Controller switches one active Core at a time with interruption; '
        'only after qualification does it promote and retire oldCore5ec6ccc3fd5d and its container.34 temporary helpers '
        'and59986010-byte context retire; no downloads/new persistent volumes/networks/ports. First-run26 helpers and '
        'failed candidate also retire; its default Docker image-list omission is preserved and fixed using --all, '
        'not by ignoring unexpected resources.481 correspondence checks are integrity only. This supersedes earlier '
        'Core-mount/installation gaps only. Full fresh-host startup, rolling/HA and injected cutover failures, all SDK '
        'versions, imported factors/tenants/linking, general reconciliation, distribution and independent review remain '
        'unqualified. No full baseline requirement/API/profile, foundation or migration gate is certified.')
    installed_core_test_ids = []
    for report_path in ('evidence/operations/atomic-reset/image-core-installed-02/probe-report.json',
                        'evidence/operations/atomic-reset/image-core-installed-02/password-session-report.json',
                        'evidence/operations/password-reset/atomic-image-node-installed-02/probe-results.json'):
        installed_core_test_ids += [r['id'] for r in read_json(ROOT/report_path)['rows'] if r['status']=='passed']
    for phase in ('seed','upgraded','rollback','final','cleanup'):
        installed_core_test_ids += [r['id'] for r in read_json(ROOT/('evidence/operations/atomic-core-replacement/installed-02/'+phase+'.json'))['rows'] if r['status']=='passed']
    # These three rows have only this bounded slice; preserve their planned status.
    # Reset this updater-owned mapping so repeat execution does not accumulate it.
    for identifier in ('OPS-007','MIG-010','WP-031'):
        index[identifier]['implementation'] = []
        index[identifier]['candidate_evidence'] = []
        index[identifier]['qualification_note'] = ''
        index[identifier]['observed_test_ids'] = []
        index[identifier]['blockers'] = ['Full original rolling/SDK or migration/reconciliation criteria and prerequisite packages remain unmet.']
    for identifier in ('BAS-002','BAS-004','BAS-005','PWD-006','SES-001','SES-005','SES-006',
                       'SDK-001','SDKP-01','SDK-005','SDKP-05','OPS-004','OPS-007','OPS-011','MIG-010',
                       'WP-002','WP-009','WP-010','WP-031','WP-033'):
        row = index[identifier]
        row['implementation'] += [artifact(ROOT,p) for p in installed_core_sources]
        row.setdefault('candidate_evidence',[]).extend(data['installed_atomic_core_candidate_artifacts'])
        row['qualification_note'] = row.get('qualification_note','') + ' ' + installed_core_note
        row['observed_test_ids'] = list(dict.fromkeys(row.get('observed_test_ids',[])+installed_core_test_ids))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'tools/verify_checkpoint_hygiene.py',
        'evidence/operations/hygiene/verification-20260909T085940Z.json',
        'evidence/operations/hygiene/verification-20260909T093045Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-installed-atomic-core.json')]
    for identifier in ('BAS-001','TST-001'):
        index[identifier]['implementation'] += [artifact(ROOT,p) for p in ('tools/package_checkpoint.py','tests/evidence/test_checkpoint_secrets.py')]
        index[identifier]['candidate_evidence'] += [artifact(ROOT,'evidence/runs/checkpoint-secret-file-tests-06/command.json')]
        index[identifier]['qualification_note'] += ' Rollback-journal passwords and both session generations are now scanned, including interrupted temporary saves.22 focused scanner cases pass; malformed, oversized and incomplete journals fail closed. Link/reparse branches and generic secret discovery remain unqualified.'
    grace_sources = ['contracts/session-policy-oss-cdi56-grace-v1.json','examples/node-react/server.js',
        'tools/run_refresh_grace_lab.py','tests/foundation/RefreshGraceProbe.java','tests/foundation/sdk_refresh_grace.mjs',
        'tests/browser/session-grace.mjs','tools/build_node_runtime.py','tools/verify_refresh_grace_evidence.py',
        'reuse/session-grace-components.json','docs/session-refresh-grace.md']
    grace_reports = ['evidence/foundation/refresh-grace/run-01/'+p for p in ('report.json','probe-report.json')]
    for run in ('node-03','installed-cdi56-grace-01'):
        grace_reports += ['evidence/foundation/refresh-grace/'+run+'/'+p for p in
            ('report.json','sdk-results.json','browser-results.json','signed-out.png')]
    grace_reports += ['evidence/foundation/refresh-grace/evidence-validation-01.json',
        'evidence/operations/node-image-build/cdi56-grace-01/report.json',
        'evidence/operations/node-image-build/cdi56-grace-01/candidate-runtime/runtime-report.json',
        'evidence/operations/node-image-build/evidence-validation-cdi56-grace-01.json',
        'evidence/operations/atomic-reset/installed-cdi56-grace-01/report.json']
    grace_reports += ['evidence/operations/password-reset/atomic-installed-cdi56-grace-01/'+p for p in
        ('report.json','probe-results.json','tls-results.json','browser-results.json','wire/good.jsonl','wire/missing-writer.jsonl')]
    data['session_grace_candidate_artifacts']=[artifact(ROOT,p) for p in grace_reports]
    data['session_grace_failed_history']=[artifact(ROOT,'evidence/foundation/refresh-grace/'+run+'/report.json') for run in
        ('node-01','node-02','startup-01','startup-02')]
    grace_note = ('Historical checkpoint0498a025fcc5 installed Nodee02ab9bcd78e explicitly adapted only private refresh/verify calls toCDI5.6 through '
        'the existing SDK network interceptor; upstream Node24.0.3 still declares5.4, and atomic password-session creation '
        'keeps5.4. Core03b4458c532f alone owns rotation/signing/revocation, with no new engine/JAR changes. The separately '
        'declared five-second grace profile passes12 direct Core cases, including8 concurrent responses converging on one '
        'stored successor, an actual PostgreSQL backend termination after UPDATE before commit with rollback/retry, '
        'three server-side replay/family-revocation classifications, committed response loss/eight-byte truncation, '
        'late delivery after logout and an explicit5.4/5.6 transition sequence. Installed Node passes9 HTTP behavior '
        'cases plus1wire and1cleanup row; real React passes4-tab/32-request expiry recovery with1refresh and4denials '
        'after logout, plus cleanup.11backend users and1browser user removed;6grace containers retired. Both images '
        'have no healthy application/JAR overlays. The builder also passes55delivery unit,8parser and34installed atomic '
        'reset/SMTP/TLS/browser regressions. All8appfiles/7629original package members match; dependencies unchanged. '
        'Previous Node9375a5bc093d and all29build/qualification containers retire only after qualification; original '
        'Core/PostgreSQL processes/configuration preserved.288build and287grace correspondence checks are integrity only. '
        'Initial HTTP-origin flag/hostname startup failures and the offline log-option diagnostic defect remain recorded; '
        'no auth requests occurred in those failed Node runs, and their containers retire. Readiness advertises5.6 but '
        'does not attest effective grace configuration; retained source Core still uses zero grace. Arbitrary concurrent '
        'client credential installation, unmodified/other SDKs, native/live providers, configured tenancy/link/factors, '
        'revocation crashes/all orderings/restarts/failover/load, bounded offline window, full migration/distribution and '
        'independent review remain unqualified. Original zero-grace and legacy raw-client failures are preserved. No '
        'foundation, full baseline requirement/API/profile or original SDK-version claim is promoted.')
    grace_ids = [r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/run-01/probe-report.json')['rows']]
    grace_ids += [r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/installed-cdi56-grace-01/sdk-results.json')['rows']]
    grace_ids += [r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/installed-cdi56-grace-01/browser-results.json')['rows']]
    # SES-017 has a narrow error-contract candidate only; keep the full row planned.
    row=index['SES-017'];row.update(implementation=[],candidate_evidence=[],qualification_note='',observed_test_ids=[],
        blockers=['All original SDK error distinctions and profile/version combinations remain unqualified.'])
    for identifier in ('BAS-002','BAS-004','BAS-005','SES-003','SES-004','SES-005','SES-006','SES-007','SES-017',
                       'SDK-001','SDKP-01','SDK-005','SDKP-05','PWD-006','OPS-004','OPS-007','OPS-011',
                       'WP-002','WP-004','WP-009','WP-010','WP-033'):
        row=index[identifier];row['implementation'] += [artifact(ROOT,p) for p in grace_sources]
        row.setdefault('candidate_evidence',[]).extend(data['session_grace_candidate_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+grace_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+grace_ids))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T101607Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-refresh-grace.json')]
    policy_sources=['engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSessionAPI.java',
        'examples/node-react/server.js','tools/build_password_session.py','tools/password_session_candidates.py',
        'tools/retire_password_session_candidate.py','tools/build_atomic_core_runtime.py','tools/build_node_runtime.py',
        'tools/run_refresh_grace_lab.py','tests/foundation/session_policy_readiness.mjs','tests/operations/PasswordSessionProbe.java',
        'tests/foundation/RefreshGraceProbe.java','tests/browser/password-reset.mjs','tests/evidence/test_password_session_candidates.py',
        'tools/verify_session_policy_evidence.py','reuse/password-session-components.json','reuse/session-grace-components.json',
        'docs/session-policy-readiness.md']
    policy_reports=['evidence/operations/password-session-build/policy-01/'+p for p in ('report.json','core-members.json','postgresql-members.json')]
    policy_reports+=['evidence/operations/password-session-build/candidate-guard-tests-01/report.json',
        'evidence/operations/atomic-core-image/policy-01/report.json','evidence/operations/atomic-core-image/policy-01/qualification.json',
        'evidence/operations/atomic-core-replacement/policy-01/report.json','evidence/operations/atomic-reset/image-core-policy-01/report.json',
        'evidence/operations/atomic-reset/image-core-policy-01/probe-report.json','evidence/operations/atomic-reset/image-core-policy-01/password-session-report.json',
        'evidence/operations/hygiene/password-session-retirement-policy-01.json',
        'evidence/operations/node-image-build/policy-02/report.json','evidence/operations/node-image-build/evidence-validation-policy-02.json',
        'evidence/operations/atomic-reset/installed-policy-02/report.json','evidence/foundation/refresh-grace/policy-evidence-validation-01.json',
        'evidence/operations/atomic-reset/policy-browser-01/report.json','evidence/operations/password-reset/atomic-policy-browser-01/browser-results.json']
    for run in ('atomic-image-node-policy-01','atomic-installed-policy-02'):
        policy_reports+=['evidence/operations/password-reset/'+run+'/'+p for p in ('report.json','probe-results.json','tls-results.json','browser-results.json')]
    for run,files in [('image-core-policy-01',('report.json','probe-report.json')),
                      ('policy-source-01',('report.json','policy-results.json')),
                      ('installed-policy-02',('report.json','sdk-results.json','browser-results.json','signed-out.png')),
                      ('policy-policy-02',('report.json','policy-results.json'))]:
        policy_reports+=['evidence/foundation/refresh-grace/'+run+'/'+p for p in files]
    for phase in ('seed','upgraded','rollback','final','cleanup'):
        policy_reports+=['evidence/operations/atomic-core-replacement/policy-01/'+phase+'.json']
    data['effective_session_policy_artifacts']=[artifact(ROOT,p) for p in policy_reports]
    data['effective_session_policy_failed_history']=[artifact(ROOT,p) for p in (
        'evidence/operations/node-image-build/policy-01/report.json','evidence/operations/atomic-reset/installed-policy-01/report.json',
        'evidence/operations/password-reset/atomic-installed-policy-01/report.json',
        'evidence/operations/password-reset/atomic-installed-policy-01/browser-results.json',
        'evidence/operations/password-reset/atomic-installed-policy-01/browser-progress.json')]
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T105924Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-session-policy.json')]
    policy_note=('Historical checkpoint40c8589b0921 Core3e15c927a662 returns authenticated effective tenant grace/reuse settings using the original Core '
        'configuration. Only its existing ExpertAuth capability class changed relative to compile-04; the plugin is byte-identical. '
        'Installed Node7964df6fe51e requires exactly5 seconds/TOKEN_THEFT for readiness and per-request auth/online preflight. '
        'Actual zero-grace, alternate-reuse and transport-loss cases return503 while liveness stays200, without tokens or auth '
        'business requests. Eight concurrent refusals and same-session recovery without app restart pass; offline JWT remains '
        'explicitly signature/claim-only. Seven policy checks plus one owned-user cleanup pass, with three differently configured '
        'real Cores all advertisingCDI5.6. Core16 transaction,12 refresh-policy,34 Node regression and14 actual upgrade/rollback '
        'phase cases pass. That installed Node also passes34 reset regressions,9 SDK HTTP cases plus wire/cleanup, real4-tab '
        'browser coordination/logout, and the policy-refusal child. Historical failures remain retained. The first Node candidate '
        'was not promoted after a browser response/navigation timing failure; early response parsing preserves every assertion, '
        'nine focused browser cases and the full installed regression now pass. That original unclassified mechanism remains an '
        'inference, not a fabricated exception. Superseded Core/Node images and old two-JAR cache retire only after successful '
        'replacement; all temporary helpers retire. Eight filesystem candidate guards are tooling checks, and correspondence '
        'checks are not auth tests or independent review. Retained source Core configuration remains zero grace. Heterogeneous '
        'load-balancer configuration and check/operation policy races, all configured tenants/SDKs/native/providers, remaining '
        'security/migration/operational orderings and foundation/distribution/independent review remain unqualified.')
    policy_ids=[r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/policy-policy-02/policy-results.json')['rows']]
    for identifier in ('BAS-002','BAS-004','BAS-005','SES-003','SES-004','SES-005','SES-006','SES-007','SES-017',
                       'SDK-001','SDKP-01','SDK-005','SDKP-05','PWD-006','OPS-004','OPS-007','OPS-011',
                       'WP-002','WP-004','WP-009','WP-010','WP-033'):
        row=index[identifier];row['implementation'] += [artifact(ROOT,p) for p in policy_sources]
        row.setdefault('candidate_evidence',[]).extend(data['effective_session_policy_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+policy_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+policy_ids))
    guarded_sources=['engine-extensions/core-reset/src/io/expertauth/core/SessionPolicy.java',
        'engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSessionAPI.java','tools/patch_session_policy.py',
        'tools/build_password_session.py','tools/build_atomic_core_runtime.py','tools/run_refresh_grace_lab.py',
        'tools/build_node_runtime.py','tools/retire_password_session_candidate.py','tools/verify_guarded_session_evidence.py',
        'examples/node-react/server.js','tests/foundation/GuardedSessionProbe.java','tests/foundation/RefreshGraceProbe.java',
        'tests/foundation/sdk_refresh_grace.mjs','tests/foundation/session_policy_readiness.mjs',
        'reuse/password-session-components.json','reuse/session-grace-components.json','docs/guarded-session-operations.md']
    guarded_sources+=['evidence/operations/password-session-build/guarded-01/'+p for p in
        ('Session.java','Webserver.java','GuardedRefreshSessionAPI.java','GuardedVerifySessionAPI.java')]
    guarded_reports=['evidence/operations/password-session-build/guarded-01/'+p for p in ('report.json','core-members.json','postgresql-members.json')]
    guarded_reports+=['evidence/operations/atomic-core-image/guarded-01/'+p for p in ('report.json','qualification.json','adaptation-runtime.cdx.json','notice-manifest.json')]
    guarded_reports+=['evidence/operations/atomic-core-replacement/guarded-01/'+p for p in ('report.json','seed.json','upgraded.json','rollback.json','final.json','cleanup.json')]
    guarded_reports+=['evidence/operations/atomic-reset/image-core-guarded-01/'+p for p in ('report.json','probe-report.json','password-session-report.json')]
    guarded_reports+=['evidence/operations/atomic-reset/image-node-guarded-01/report.json','evidence/operations/atomic-reset/installed-guarded-01/report.json',
        'evidence/operations/node-image-build/guarded-01/report.json','evidence/operations/node-image-build/evidence-validation-guarded-01.json',
        'evidence/operations/hygiene/password-session-retirement-guarded-01.json','evidence/foundation/refresh-grace/guarded-evidence-validation-01.json']
    for run in ('atomic-image-node-guarded-01','atomic-installed-guarded-01'):
        guarded_reports+=['evidence/operations/password-reset/'+run+'/'+p for p in ('report.json','probe-results.json','tls-results.json','browser-results.json')]
    for run,files in [('image-guarded-guarded-01',('report.json','guarded-report.json')),
                      ('image-core-guarded-01',('report.json','probe-report.json')),
                      ('guarded-source-01',('report.json','policy-results.json')),
                      ('installed-guarded-01',('report.json','sdk-results.json','browser-results.json','signed-out.png')),
                      ('policy-guarded-01',('report.json','policy-results.json'))]:
        guarded_reports+=['evidence/foundation/refresh-grace/'+run+'/'+p for p in files]
    data['guarded_session_operation_artifacts']=[artifact(ROOT,p) for p in guarded_reports]
    data['guarded_session_transform_failed_history']=[artifact(ROOT,'evidence/operations/session-policy-transform/anchors-01/'+p) for p in ('report.json','patch_session_policy.py')]
    guarded_note=('Historical Coredb1d29ba6244 and current Node2a02e08d5fcb use private guarded refresh/verify routes with explicit '
        'OSS-CDI56-GRACE5-V1 policy validation in Core. The token tenant and the exact CoreConfig used by the refresh '
        'transaction are checked; recursive retries retain the constraint. No ThreadLocal context, adapter identity/session '
        'store or alternate crypto/rotation algorithm exists. Original API classes and signatures retain their behavior; '
        'Apache private derivatives retain original authorization and licensing checks. Actual healthy preflight followed '
        'by mismatched Core settings fails closed without session-column changes; an actual pre-guard replica returns404 '
        'for both private routes. Sixteen mixed Core requests yield8rotations/8refusals and one authoritative successor. '
        'Nine direct behavior cases plus cleanup pass. Installed Node proves the same preflight/operation mismatch through '
        'real routing: Core503 becomes a fixed SDK service500, no credentials or original-route fallback, and same-session '
        'recovery succeeds. Four mixed Node requests yield2rotations/2refusals and one online-valid successor. Existing7policy '
        'checks plus3guarded checks and cleanup pass; all6policy containers retire. Core also passes16atomic cases,34Node '
        'regressions,12refresh-policy cases and14actual upgrade/rollback phases. Node passes55delivery unit,8parser,34reset '
        'behavior cases,9SDK HTTP cases plus wire/cleanup, and4-tab/32-request browser recovery with1refresh and4logout '
        'denials. Actual guarded response loss/truncation recovers; all3private Core paths are404 on the public app. Old '
        'Core/Node images and superseded JARs retire after qualification; all35Node build/qualification containers retire. '
        '303Node-build and878guarded correspondence checks are integrity only. The initial source-transform catch-anchor '
        'failure is preserved and resolved without runtime activity. Other auth-operation/configuration races, live reload, '
        'rolling deployment, required namespace/linking/factors, all SDK/native/provider versions, full native/source/relink '
        'distribution closure and independent human review remain unqualified. Original failures and all acceptance IDs remain '
        'binding; no foundation or full requirement/profile claim is promoted.')
    guarded_ids=[r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/image-guarded-guarded-01/guarded-report.json')['rows']]
    guarded_ids += [r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/policy-guarded-01/policy-results.json')['rows']]
    for identifier in ('BAS-002','BAS-004','BAS-005','SES-003','SES-004','SES-005','SES-006','SES-007','SES-017',
                       'SDK-001','SDKP-01','SDK-005','SDKP-05','PWD-006','OPS-004','OPS-007','OPS-011',
                       'WP-002','WP-004','WP-009','WP-010','WP-033'):
        row=index[identifier];row['implementation'] += [artifact(ROOT,p) for p in guarded_sources]
        row.setdefault('candidate_evidence',[]).extend(data['guarded_session_operation_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+guarded_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+guarded_ids))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T113300Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-guarded-sessions.json')]
    native_sources=['tools/build_native_argon2.py','tools/capture_native_sources.py','tools/run_native_source_capture.py',
        'tools/run_refresh_grace_lab.py','tests/foundation/NativePasswordProbe.java','tools/verify_extracted_native.py',
        'reuse/native-argon2-components.json','docs/native-argon2-build.md','tools/package_checkpoint.py',
        'tests/evidence/test_checkpoint_committed_files.py']
    native_reports=['evidence/reuse/native-correspondence/argon2/native-metadata-01/acquisition.json',
        'evidence/reuse/native-correspondence/argon2/native-source-request.json',
        'evidence/reuse/native-correspondence/argon2/native-source/acquisition.json',
        'evidence/reuse/native-correspondence/argon2/native-build/linux-03/report.json',
        'evidence/reuse/native-correspondence/argon2/native-build/fresh-source-01/report.json',
        'evidence/reuse/native-correspondence/argon2/native-build/fresh-source-01/child-report.json',
        'evidence/foundation/refresh-grace/native-argon2-01/report.json',
        'evidence/foundation/refresh-grace/native-argon2-01/native-password-report.json',
        'evidence/reuse/native-correspondence/argon2/package-completeness-01/report.json',
        'evidence/reuse/native-correspondence/argon2/package-completeness-01/failure.json']
    native_reports += ['evidence/reuse/native-correspondence/argon2/package-fresh-parent-failure/diagnosis.json']
    data['native_argon2_candidate_artifacts']=[artifact(ROOT,p) for p in native_reports]
    data['native_argon2_failed_history']=[artifact(ROOT,'evidence/reuse/native-correspondence/argon2/native-build/'+run+'/'+p)
        for run in ('linux-01','linux-02') for p in ('report.json','build_native_argon2.py')]
    native_note=('Historical source-mounted checkpoint: PHC62358ba2123abd17fccf2a108a301d4b52c01a7c:68 pinned native source/build/test/notice files; two Linux x86-64 '
        'builds match. Original make test produces12 KAT comparisons of6 vectors and37 API pass lines. Actual Core '
        'source/bundled-library password/import/reset/concurrency qualification passes10 behavior rows plus15-user cleanup. '
        'Both source and runtime tests use the existing cached images; all helpers retire. Native dependency mount is '
        'explicit; no installed native-image, other-platform, historical-binary, final-engine or distribution approval. '
        'Imported hashes remain unchanged after successful login: configured rehash and the full migration/hash matrix '
        'remain absent/unqualified. All namespace/link/disabled-account and independent-review gates remain binding.')
    native_ids=[r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace/native-argon2-01/native-password-report.json')['rows']]
    # These planned full rows gain a narrow candidate; retain their required scope/status.
    for identifier in ('PWD-005','MIG-002'):
        index[identifier].update(implementation=[],candidate_evidence=[],qualification_note='',observed_test_ids=[])
    for identifier in ('BAS-002','BAS-004','BAS-005','PWD-001','PWD-005','PWD-006','MIG-002','WP-002'):
        row=index[identifier];row['implementation'] += [artifact(ROOT,p) for p in native_sources]
        row.setdefault('candidate_evidence',[]).extend(data['native_argon2_candidate_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+native_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+native_ids))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T121421Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-native-argon2.json',
        'evidence/operations/hygiene/checkpoint-retention-native-incomplete.json',
        'evidence/operations/hygiene/checkpoint-retention-native-bootstrap.json',
        'evidence/reuse/native-correspondence/argon2/checkpoint-checks-01/report.json')]
    installed_native_sources=['tools/install_native_argon2.py','tools/qualify_native_startup.py',
        'deploy/native-argon2-start.sh','deploy/NativeArgon2Check.java','tools/build_atomic_core_runtime.py',
        'tools/replace_atomic_core.py','tools/run_refresh_grace_lab.py','tests/foundation/NativePasswordProbe.java',
        'tools/verify_installed_native.py','reuse/installed-native-argon2.json','docs/installed-native-argon2.md']
    installed_native_reports=['evidence/operations/atomic-core-image/native-01/'+p for p in
        ('report.json','qualification.json','notice-manifest.json','adaptation-runtime.cdx.json')]
    installed_native_reports += ['evidence/operations/native-argon2-startup/image-native-01/report.json',
        'evidence/operations/native-argon2-installation/correspondence-03.json',
        'evidence/operations/atomic-core-replacement/native-01/report.json',
        'evidence/operations/atomic-reset/image-core-native-01/report.json',
        'evidence/operations/atomic-reset/image-core-native-01/probe-report.json',
        'evidence/operations/atomic-reset/image-core-native-01/password-session-report.json',
        'evidence/operations/atomic-reset/image-node-native-01/report.json']
    for run,probe in [('image-native-native-01','native-password-report.json'),
                      ('native-installed-peer-01','native-password-report.json'),
                      ('image-guarded-native-01','guarded-report.json'),('image-core-native-01','probe-report.json')]:
        installed_native_reports += ['evidence/foundation/refresh-grace/'+run+'/'+p for p in ('report.json',probe)]
    installed_native_reports += ['evidence/operations/password-reset/atomic-image-node-native-01/'+p
        for p in ('report.json','probe-results.json','browser-results.json','tls-results.json')]
    data['installed_native_argon2_artifacts']=[artifact(ROOT,p) for p in installed_native_reports]
    data['installed_native_verifier_failed_history']=[artifact(ROOT,'evidence/operations/native-argon2-installation/'+p)
        for p in ('correspondence.json','correspondence-02.json','verify-before-retired-helper-fix.py',
                  'verify-before-diagnostic-case-fix.py')]
    installed_native_note=('Current Coree8c460664ac5 installs the source-built45aa95d580e7 Argon2 library through unchanged '
        'LGPL3 nolibs/JNA bindings; removes only the verified native-only eight-member bundle. All68 PHC source/build/test/notice '
        'files are installed. All554 installed files match;86JARs and87SBOMcomponents. Seven actual startup cases pass, separate '
        'from authentication. Source/bundled and source/source Core profiles each pass10password/import/reset/concurrency rows '
        'plus15-user cleanup and117requests. Both installed-peer process maps show the source library, with no native dependency '
        'mount. The main build snapshots preserve older runner/probe bytes; a separate installed-peer lab qualifies their only '
        'later changes without runtime rebuild. Core/plugin guarded-01 JARs and Node2a02e08d5fcb are unchanged. Sixteen atomic Core '
        'cases,34Node/SMTP/TLS/React behavior checks,12grace cases,8guarded cases plus cleanup and14actual local upgrade/rollback '
        'phases pass. Original PostgreSQL/schema/configuration/identity set preserved; operator BCRYPT and zero-grace policy '
        'unchanged. Old Coredb1d29ba6244, all helpers, build context and scratch retire.269offline correspondence checks are not '
        'authentication; two verifier failures concerning expected retired-helper absence and diagnostic case are preserved. '
        'Imported hashes still do not rehash on login. Remaining native/OS, wrapper/source/relink, maintenance, full fresh-host, '
        'migration, namespace/linking, all SDK/platform/provider profiles and independent review remain unqualified. No engine '
        'selection, entitlement bypass or original acceptance status is promoted.')
    installed_native_ids=[]
    for run in ('image-native-native-01','native-installed-peer-01'):
        installed_native_ids += [r['id'] for r in read_json(ROOT/'evidence/foundation/refresh-grace'/run/'native-password-report.json')['rows']]
    for identifier in ('BAS-002','BAS-004','BAS-005','PWD-001','PWD-005','PWD-006','MIG-002',
                       'SES-003','SES-004','SES-005','SES-006','SES-017','SDK-001','SDKP-01','SDK-005','SDKP-05',
                       'OPS-004','OPS-007','OPS-011','WP-002','WP-004','WP-009','WP-010','WP-033'):
        row=index[identifier];row['implementation'] += [artifact(ROOT,p) for p in installed_native_sources]
        row.setdefault('candidate_evidence',[]).extend(data['installed_native_argon2_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+installed_native_note
        if identifier in ('PWD-001','PWD-005','PWD-006','MIG-002','WP-002'):
            row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+installed_native_ids))
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/verification-20260909T125944Z.json',
        'evidence/operations/hygiene/checkpoint-retention-before-installed-native.json')]
    firebase_sources = ['tools/patch_firebase_scrypt.py','tools/build_password_session.py',
        'tools/acquire_bouncycastle.py','tools/install_bouncycastle.py','tools/build_atomic_core_runtime.py',
        'tools/run_atomic_reset_lab.py','tools/run_refresh_grace_lab.py','tools/replace_atomic_core.py',
        'tests/foundation/firebase-fixtures.mjs','tests/foundation/FirebaseScryptProbe.java',
        'tools/verify_firebase_checkpoint.py','docs/firebase-scrypt-runtime.md']
    firebase_reports = ['evidence/operations/password-session-build/firebase-bc-02/report.json',
        'evidence/reuse/bouncycastle/runtime-1852-02/acquisition.json',
        'evidence/reuse/bouncycastle/runtime-1852-02/container.json',
        'evidence/operations/atomic-core-image/firebase-01/report.json',
        'evidence/operations/atomic-core-image/firebase-01/notice-manifest.json',
        'evidence/operations/atomic-core-image/firebase-01/adaptation-runtime.cdx.json',
        'evidence/operations/atomic-core-replacement/firebase-01/report.json',
        'evidence/operations/bouncycastle-installation/native-reference-preflight.stdout',
        'evidence/operations/bouncycastle-installation/pause-correspondence.json']
    for run in ('firebase-bc-source-02','image-firebase-firebase-01','firebase-legacy-json-01'):
        firebase_reports += ['evidence/operations/atomic-reset/'+run+'/'+p for p in ('report.json','firebase-scrypt-report.json')]
    firebase_reports += ['evidence/operations/atomic-reset/image-core-firebase-01/'+p for p in
        ('report.json','probe-report.json','password-session-report.json')]
    firebase_reports += ['evidence/operations/atomic-reset/image-node-firebase-01/report.json',
        'evidence/operations/native-argon2-startup/image-firebase-01/report.json']
    for run, probe in [('image-native-firebase-01','native-password-report.json'),
                       ('image-guarded-firebase-01','guarded-report.json'),('image-core-firebase-01','probe-report.json')]:
        firebase_reports += ['evidence/foundation/refresh-grace/'+run+'/'+p for p in ('report.json',probe)]
    firebase_reports += ['evidence/operations/password-reset/atomic-image-node-firebase-01/'+p for p in
        ('report.json','probe-results.json','browser-results.json','tls-results.json')]
    data['firebase_scrypt_candidate_artifacts'] = [artifact(ROOT,p) for p in firebase_reports]
    firebase_note = ('Current Core b4a5f18fb782 / firebase-bc-02 uses BC provider1.85.2/util+PKIX1.85, '
        'UTF-8 Firebase passwords/default JSON reader, bounded shift checks and JDK digest comparison. '
        'Twelve actual installed Firebase rows pass; separate current historical-peer proof makes115requests '
        'and cleans17users/sixhelpers. Old-peer Unicode collision and shift alias are observed security failures. '
        'Legacy raw-UTF8 BCRYPT credential migration is explicitly BLOCKED and authentication_acceptance_pass=false; '
        'this observation is not one of the twelve passing candidate rows. An explicit migration/reset policy '
        'is required. Full cost/import parameter validation and automatic rehash remain missing. Installed '
        'native/Core/Node/browser/session regressions and14local upgrade/rollback phases pass;559files/85JARs/86SBOM '
        'components match. OldCore/scryptJAR/supersededcandidatepair and allhelpers retire.174offline correspondence '
        'checks bind current source and the earlier installation snapshots; a native-source-location verifier '
        'mistake is preserved and corrected, not an authentication pass. Current builder has a separate read-only '
        'actual-JAR-reference preflight. No finalengine/license/security/humanreview/fullrequirement/profile pass. '
        'Paused at user request; see docs/firebase-scrypt-runtime.md for exact resume and limits.')
    firebase_ids = [r['id'] for r in read_json(ROOT/'evidence/operations/atomic-reset/firebase-legacy-json-01/firebase-scrypt-report.json')['rows']]
    for identifier in ('BAS-002','BAS-004','BAS-005','PWD-001','PWD-005','PWD-006','MIG-002',
                       'SES-003','SES-004','SES-005','SES-006','SES-017','SDK-001','SDKP-01','SDK-005','SDKP-05',
                       'OPS-004','OPS-007','OPS-011','WP-002','WP-004','WP-009','WP-010','WP-033'):
        row=index[identifier]
        row['implementation'] += [artifact(ROOT,p) for p in firebase_sources]
        row.setdefault('candidate_evidence',[]).extend(data['firebase_scrypt_candidate_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+firebase_note
        if identifier in ('PWD-001','PWD-005','PWD-006','MIG-002','WP-002'):
            row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+firebase_ids))
    data['firebase_scrypt_failed_history']=[artifact(ROOT,p) for p in (
        'evidence/operations/atomic-reset/firebase-bc-source-01/report.json',
        'evidence/operations/atomic-reset/firebase-bc-source-01/diagnosis-and-retirement.json',
        'evidence/operations/bouncycastle-installation/pause-correspondence-initial.json',
        'evidence/operations/bouncycastle-installation/CORRESPONDENCE_CORRECTION.md')]
    data['delivery_checkpoint_artifacts'] += [artifact(ROOT,p) for p in (
        'evidence/operations/hygiene/password-session-retirement-firebase-01.json',
        'evidence/operations/hygiene/checkpoint-retention-before-firebase-pause.json',
        'evidence/operations/hygiene/verification-20260909T134957Z.json')]
    upgrade_sources = ['engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java',
        'engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSession.java',
        'tools/patch_password_upgrade.py','tools/build_password_session.py','tools/run_password_upgrade_lab.py',
        'tests/foundation/PasswordUpgradeTest.java','tests/evidence/test_password_upgrade_patch.py','docs/password-upgrade.md']
    data['password_upgrade_candidate_artifacts'] = [artifact(ROOT,p) for p in (
        'evidence/operations/password-upgrade/cloud-source-05/report.json','evidence/operations/password-upgrade/unit-02/report.json')]
    data['password_upgrade_failed_history'] = [artifact(ROOT,p) for p in (
        'evidence/operations/password-upgrade/cloud-source-04/report.json','evidence/operations/password-upgrade/cloud-source-03/report.json',
        'evidence/operations/password-upgrade/cloud-source-02/report.json','evidence/operations/password-upgrade/unit-01/report.json',
        'evidence/operations/password-upgrade/cloud-source-01/report.json','evidence/operations/password-upgrade/cloud-source-01/CORRECTION.md')]
    upgrade_ids = ['PWUP-'+c['name'] for c in read_json(ROOT/'evidence/operations/password-upgrade/cloud-source-05/report.json')['cases']]
    upgrade_note = ('PasswordUpgrade (EXPERTAUTH-PASSWORD-UPGRADE-2): on-login rehash to the configured Core algorithm through '
        'the storage plugin transaction API (same commit as the atomic session with one re-verifying retry after a concurrent '
        'rehash; locked best-effort on /recipe/signin) and bounded full-structure single-user and bulk-add import validation. Legacy '
        'Unicode migration closed by scope 2026-09-30: nothing live, UTF-8 only; interim fallback (-1) removed. Source-built '
        'scratch cloud lab cloud-source-05 passes 72/72 real cases (seven independent-library import fixtures, 17 rejected '
        'imports, 7 bulk-add cases, two targets, 8+8 concurrent two-replica logins, no hash in 102 responses) and 31/31 unit checks; '
        'all 84 third-party JARs match reviewed metadata. Not the installed image, retained lab, BC1.85.2 or source-built '
        'Argon2; no upgrade/rollback, SDK/browser regression, bulk-import processing or independent review. '
        'See docs/password-upgrade.md.')
    for identifier in ('PWD-001','PWD-005','MIG-002','WP-002'):
        row=index[identifier]
        row['implementation'] += [artifact(ROOT,p) for p in upgrade_sources]
        row['candidate_evidence']=row.get('candidate_evidence',[])+list(data['password_upgrade_candidate_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+upgrade_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+upgrade_ids))
    if index['PWD-005']['status']=='planned':
        index['PWD-005']['status']='implemented-unverified'
        index['PWD-005']['blockers']=['Full original acceptance and final-engine qualification remain open.']
    # 2026-09-30 product-owner decision (ADR-001): the independently authored ExpertAuth engine is the
    # product. SuperTokens-derived and Keycloak artifacts above remain reference-behavior evidence only.
    engine_sources = ['engine/src/'+p for p in ('config.ts','crypto.ts','db.ts','errors.ts','identity.ts','keys.ts',
        'linking.ts','main.ts','passwords.ts','reset.ts','schema.sql','sessions.ts','verification.ts','http/server.ts')] + [
        'engine/test/'+p for p in ('helpers.ts','identity.test.ts','linking.test.ts','sessions.test.ts','reset.test.ts','unit.test.ts','verification.test.ts')] + [
        'engine/package.json','engine/package-lock.json','engine/README.md','docs/adr/001-foundation.md','tools/record_engine_evidence.py']
    data['engine_candidate_artifacts'] = [artifact(ROOT,p) for p in (
        'evidence/engine/m1-slice-03/report.json','evidence/engine/m1-slice-03/test-output.tap',
        'evidence/engine/m1-slice-02/report.json','evidence/engine/m1-slice-02/test-output.tap',
        'evidence/engine/m1-slice-01/report.json','evidence/engine/m1-slice-01/test-output.tap')]
    engine_tests = ['EA-'+n for n in read_json(ROOT/'evidence/engine/m1-slice-03/report.json')['test_names']]
    engine_note = ('ExpertAuth engine (independently authored, ADR-001 2026-09-30; SuperTokens is reference only): '
        'native apps/tenants, tenant-scoped email identities with explicit sharing, argon2id credentials with bounded '
        'bcrypt/argon2 import and on-login rehash, RS256 sessions with deterministic-successor refresh rotation '
        '(grace convergence, lost-response retry, reuse revokes family), atomic single-winner password reset, and '
        'lock-ordered account linking (single owner under competing links, parallel unlink keeps every remaining method '
        'usable, no shared primary email per tenant, no empty users, session revocation on link/unlink), and tenant-bound '
        'single-use email verification keyed by exact email. evidence/engine/m1-slice-03: 55/55 tests against real '
        'PostgreSQL 17.11 (slice-02: 51/51, slice-01: 41/41). Not the strict release run schema; '
        'no SDK/FDI backend, browser, load/HA or independent review yet.')
    engine_rows = {'IDN-001':True,'IDN-002':True,'IDN-003':True,'IDN-004':True,'IDN-006':True,'IDN-011':True,
        'PWD-001':False,'PWD-005':False,'PWD-006':False,'SES-001':False,'SES-002':False,'SES-003':True,'SES-004':True,
        'SES-005':False,'SES-006':False,'SES-011':False,'CFG-004':False,
        'IDN-005':True,'IDN-012':True,'LNK-001':True,'LNK-002':True,'LNK-006':True,'LNK-007':True,'LNK-008':True,
        'VER-001':True,'VER-002':True}
    for identifier, promote in engine_rows.items():
        row=index[identifier]
        row['implementation'] = row.get('implementation',[]) + [artifact(ROOT,p) for p in engine_sources]
        row['candidate_evidence']=row.get('candidate_evidence',[])+list(data['engine_candidate_artifacts'])
        row['qualification_note']=row.get('qualification_note','')+' '+engine_note
        row['observed_test_ids']=list(dict.fromkeys(row.get('observed_test_ids',[])+engine_tests))
        if promote and row['status'] in ('planned','blocked','failed'):
            row['status']='implemented-unverified'
            row['blockers']=['Full original acceptance, SDK/profile qualification and independent review remain open. '
                'Rejected-candidate failures (Keycloak/SuperTokens-Core labs) are retained as reference evidence.']
    assert not integrity_errors(ROOT,data), integrity_errors(ROOT,data)
    write_json(path,data)
    print('Partial traceability updated; no verified acceptance claims were created.')

if __name__=='__main__':
    main()
