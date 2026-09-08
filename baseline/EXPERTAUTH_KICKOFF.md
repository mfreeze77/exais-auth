# ExpertAuth — full-parity implementation kickoff

## Mission

Act as the lead implementation engineer, integration owner, and release-evidence owner for ExpertAuth. Turn the supplied full-parity planning package into an actual, reproducible, self-hosted authentication platform. Produce working source code, migrations, SDKs, interfaces, deployment assets, tests, operational documentation, and release artifacts—not another plan or a scaffold presented as a finished product.

The outcome is the entire researched SuperTokens capability set, including advanced features, without mandatory authentication-vendor subscriptions, per-user charges, administrator-seat fees, MFA/SSO unlocks, activation services, or vendor-hosted administration. Hosting, maintenance, and operator-selected email/SMS transports are separate costs.

Begin execution now. Continue through dependency-ready work without asking whether to proceed at each milestone. Respect the user's actual permissions, tool availability, and runtime/budget limits. Missing prerequisites must be reported, not invented. Never turn a partial result into a full-parity claim to satisfy this goal.

## 1. Authoritative inputs and scope preservation

Locate and read `expert-auth-full-parity-plan-v1.0.zip` and `ExpertAuth_Full_Parity_Plan.md` in the workspace or provided attachments. The archive's `FULL_PARITY_PLAN.md`, all documents under `docs/`, and all machine-readable registries collectively define the acceptance contract. Do not substitute a conversation summary for those files. Follow applicable workspace instructions and later explicit user decisions.

Read the complete feature matrix, backlog, API inventory, SDK/plugin profiles, configuration/data model, harvest plan, security acceptance rules, and sources. Retrieve the original research report when accessible; when unavailable, record that evidence limitation and proceed with the supplied specification and verified primary sources wherever sufficient.

The supplied baseline declares 265 required requirements across 29 families, 36 work packages, milestones M0–M10, 49 FDI operations, and 156 CDI operations. Verify these against the actual registries. These counts are coverage checks, not a measure of implementation progress.

Preserve the original package unchanged with checksums. Keep an editable implementation ledger separate from the immutable baseline. Retain requirement IDs, original wording, source provenance, and acceptance criteria. Add newly discovered necessary subrequirements without silently deleting, combining away, or weakening original requirements. Record genuine specification conflicts and their resolution; do not resolve ambiguity by reducing scope. Do not silently expand the frozen baseline whenever upstream documentation changes.

All required capabilities remain required. “MVP,” “enterprise later,” “the engine does not support it,” and “too difficult” are not scope-change authority. Installing an identity server or connecting one application is not completion.

## 2. Initial execution and workspace safety

Inspect the workspace, Git status, existing files, and available tools before making changes. Preserve unrelated and uncommitted user work. Resume an existing implementation when present; otherwise establish an isolated `expert-auth` implementation directory. Make local checkpoints consistent with workspace instructions. Do not publish, push, create remote repositories, provision paid resources, or deploy publicly without explicit authorization.

Safely extract the planning archive into a baseline directory. Check its manifest and checksums and inspect/run `tools/validate_plan.py` from the extracted package. Save the actual command, output, and exit status. Its success proves planning consistency only—not working authentication.

Inspect available runtimes, container support, network access, writable paths, and browser/native test capabilities. Record missing capabilities accurately. Install dependencies within the authorized environment where permitted. Do not alter global security settings or bypass denied permissions.

After baseline validation, promptly produce executable contract extraction, characterization tests, and the foundation proof. Do not spend the entire run restating the specification or constructing elaborate project-management documents. Keep progress records compact and machine-checkable.

## 3. Reuse-first implementation and licensing

Use existing maintained open-source implementations wherever they genuinely satisfy the requirements. Consult current primary documentation, release notes, advisories, source code, and licenses before choosing dependencies. Pin compatible releases, source commits, container digests, SDK versions, and protocol versions rather than depending on moving branches or unqualified latest images.

Turn the supplied harvest plan into an actual file-specific reuse report. For every reused or adapted component, record upstream repository, immutable revision, source path, license and notices, dependency boundary, destination or dependency declaration, modifications, mapped requirements, and validation evidence. Prefer supported dependencies and extensions to unnecessary source copying. Produce a software bill of materials and third-party notices.

Do not treat “public on GitHub” as proof of unrestricted reuse. Exclude restricted enterprise code and binaries unless separately and explicitly authorized under an appropriate license. Do not remove license enforcement, forge entitlements, or copy restricted implementations. Implement missing unrestricted capabilities independently from lawful public specifications and permitted observations. Do not advertise such work as clean-room when its provenance does not support that description.

Retain secure upstream primitives rather than inventing cryptography, password hashing, OAuth, SAML, or WebAuthn machinery merely to increase the amount of original code.

## 4. Binding foundation gate

Follow the plan's foundation decision, not the assumption that Keycloak already equals SuperTokens parity. Evaluate the license-audited Keycloak community engine with real executable proof cases covering:

- Same-email/provider identities remaining isolated across configured applications and tenants.
- Explicitly shared identities without shared tenant sessions or permissions.
- Primary/method identities, link/unlink conflicts, proof of control, and concurrent changes.
- Headless/embedded login, intermediate authentication states, MFA, and hooks.
- Refresh concurrency, response loss, reuse, revocation, and cookie/header behavior.
- Representative Node/React and Python clients exercising the selected contracts.
- Operation without restricted binaries, trials, activation, or vendor services.

Do not use OAuth Resource Owner Password Credentials as an embedded-login shortcut. Do not pass an engine merely because redirect login works. Keep the proof bounded to these acceptance cases; it is not permission for an open-ended engine-comparison project.

If Keycloak cannot satisfy the required mapping without reconstructing most of its identity/session engine, evaluate the plan's alternative: audited Apache-licensed portions of SuperTokens Core/SDKs with independently implemented unrestricted missing components. Preserve the requirements through the decision. If the alternative also exposes blockers, record the concrete failed cases and resolve the architecture rather than asserting parity or weakening the gates.

Produce ADR-001 with evidence, selected engine, source pins, rejected alternatives, ownership boundaries, and remaining risks. Select one authoritative owner for each credential, identity-linkage, factor, signing, and refresh-state machine. Do not create competing authentication engines or an adapter-maintained duplicate refresh store. Do not write directly into upstream-owned database tables from the control plane.

## 5. Mandatory coverage

Implement every registry requirement, not merely this summary. Coverage includes password and passwordless login; the provider catalog and custom providers; passkeys; verification; complete MFA, recovery, and step-up; account linking; applications/tenants; roles and permissions; enterprise SAML; unified OAuth/OIDC login; machine identities; MCP authorization; complete sessions; user lifecycle; administration; branding and customization; plugins; migration; risk controls; and production operations.

Retain all eight original SDK families: Node.js, Python, Go, JavaScript, React, React Native, iOS, and Android. Retain all fourteen plugin surfaces and all documented integration profiles. Qualify exact supported versions and combinations; do not invent uniform feature support across every upstream SDK. Native source code that was never compiled or exercised is unverified, not a completed SDK.

Capture the exact supported API contracts. The supplied operation registry contains deliberately unfilled fields; it is not a complete OpenAPI definition. Resolve method/path, version, recipe, headers, schemas, missing-versus-null behavior, errors, cookies, claims, pagination, side effects, tenant scope, idempotency, and deprecations. Keep the private Core interface inaccessible to untrusted clients.

Account for vendor-specific licensing and telemetry operations as explicit, honest non-equivalences. Do not fabricate a commercial licensing service or use these differences to remove advanced business capabilities. Keep separate evidence for unmodified upstream SDKs and clearly labeled adapted forks.

## 6. Build–test–review loop

Work through M0–M10 and the work-package dependency graph. Start with small executable vertical slices, then expand coverage. Independent work may proceed when a separate item is blocked, but never mark a dependent gate satisfied prematurely.

For each work package: inspect the source requirements; define concrete acceptance tests; implement the real path; integrate it into the running product; execute targeted tests and regressions; review security and failure behavior; fix defects; update traceability and evidence; then select the next dependency-ready package.

Prefer depth over disconnected scaffolding. A database migration, background worker, UI action, SDK method, or configuration option must be wired into a real, tested flow. Do not count TODOs, `NotImplemented` methods, hard-coded successful responses, unused modules, mock-only providers, or routes that merely exist as finished features.

Use available subagents only for bounded tasks with explicit contracts and nonconflicting write ownership. Independently inspect and integrate their work. A subagent's statement that tests passed is not test evidence, and an AI review is not a substitute for the plan's independent security review.

## 7. Security and operational tests

Require positive, negative, concurrency, replay, failure, and recovery tests appropriate to each requirement. In particular, cover tenant/resource substitution, unsafe linking, privilege transfer, refresh races, one-time-token reuse, callback replay, account enumeration, CSRF/CORS, redirect validation, issuer/audience/scope checks, recovery/factor removal, impersonation controls, secret redaction, and server-side administrator authorization.

Keep offline JWT verification and online revocation as explicitly different profiles. Measure revocation propagation rather than claiming immediate logout from deletion of refresh state alone. Define session consequences for bans, credential changes, factor resets, linking, and tenant removal.

Implement meaningful versions of all required attack-protection signal classes. Define detection and false-positive evaluation targets before measuring them. Use licensed local data where needed and expose uncertainty. An always-allow risk endpoint, invented score, unavailable feed, or CAPTCHA alone is not a completed risk system. Do not claim equal proprietary detection accuracy without evidence.

Test persistence, migrations, outbox retries, multiple replicas, clock skew, key rotation, process crashes, database/network outages, rolling upgrades, and backup restoration. Distinguish process liveness from actual readiness. Set explicit supported load, latency, revocation, recovery-point, and recovery-time objectives before production qualification.

Prove authentication-vendor independence with egress-blocked tests of local authentication, MFA, linking, sessions, administration, roles, risk, CAPTCHA, and recovery. Declare social identity providers and configured mail/SMS transports separately. A vendor dependency hidden behind a default configuration fails this gate.

Use synthetic identities and owned/authorized systems. Keep test doubles clearly separated from real integration evidence. Missing live provider credentials, macOS/native execution, infrastructure access, or independent review remain explicit qualification blockers.

## 8. Traceability, evidence, and resumption

Maintain one implementation ledger linked to the immutable requirements. Each requirement must identify implementation paths, positive/negative test IDs, test-run evidence, environment and dependency versions, source commit/tree identity, reviewer disposition, current status, and blockers. Use a validated status schema; distinguish planned, implemented-unverified, verified, failed, and blocked states without destroying the original format.

Store redacted command outputs, exit codes, test reports, build logs, migration results, and operational evidence under `evidence/`. Invalidate affected verification after code or dependency changes and rerun the relevant tests. Do not use stale results to approve a changed release.

Add implementation and release validation separate from the original plan validator. Fail completion checks when a required ID disappears, evidence is missing, a necessary test is skipped, an API contract is unfilled, or evidence does not match the release. Never fix a failing gate by weakening acceptance criteria, deleting a test, silently adding `skip`/`xfail`, or changing the required denominator. A genuine test defect needs a documented, reviewed correction preserving the intended requirement.

Keep `PROJECT_STATE.md` and `BLOCKERS.md` concise: current revision, verified packages, failures, environment gaps, architectural decisions, next dependency-ready work, and exact resume commands. Checkpoint at milestones and before a resource boundary. On resume, inspect these records and the actual files instead of starting over or trusting a summary alone.

Provide occasional short progress updates with concrete completed behavior, evidence, and blockers. Do not repeatedly announce plans or ask for permission to continue routine authorized work.

## 9. Stop conditions and autonomy boundaries

Continue while useful authorized implementation or validation work remains and the execution environment permits it. Do not end at a convenient intermediate milestone and ask the user to type “continue.” Do not stop solely because the complete project is large.

Do not loop on an unchanged failure. After two materially identical failed attempts, investigate a different hypothesis, use a justified alternative, or record a concrete blocker and work on another dependency-ready item. Repeated status messages are not progress.

A real external prerequisite can block a requirement without ending unrelated work. If all remaining work requires unavailable permissions, credentials, hardware, review, or an exhausted runtime/budget, save a reproducible checkpoint and report BLOCKED or PARTIAL—not COMPLETE. Name the exact dependency, attempted remedies, and smallest unblock action. Do not invent capabilities, bypass safeguards, or promise work will continue after execution has stopped.

Never spend money, send real-user messages, access unrelated secrets, modify production data/DNS, publicly expose the service, publish packages, or push remote changes without appropriate user authorization. Do not change global permissions or disable approval controls to extend autonomy.

## 10. Definition of done and delivery

Declare FULL PARITY / COMPLETE only when every required requirement is verified; all API entries are accounted for with the declared business-compatibility profile proven; every original SDK/plugin/integration profile is qualified; migrations and recovery are demonstrated; no mandatory auth entitlement remains; and the required independent security review and blocking remediation are complete.

Keep functional, behavioral, API/SDK, security-effectiveness, and operational-independence results separate. A high automated test count, a clean plan validator, successful container startup, or an AI code review cannot stand in for these release gates. Pending external qualification keeps full completion and production approval blocked.

Deliver the actual source repository, pinned dependencies, migrations, SDK/UI packages, examples, deployment configuration, `.env.example` without secrets, startup/test/upgrade/backup/restore instructions, license notices, software bill of materials, file-specific reuse report, complete traceability, compatibility report, evidence, release notes, and honest build/security/readiness reports.

Package reproducible source and evidence in a versioned ZIP with a manifest and SHA-256 checksum. Preserve local Git history through a bundle when available and appropriate. Exclude secrets, private test identities, unrelated files, caches, and dependency directories. Do not redistribute restricted upstream artifacts. Validate archive integrity and rerun representative build/tests from a fresh extraction; state any unexecuted steps.

The final response must identify what actually runs, exact commands and results, verified/unverified/blocked counts, compatibility limitations, independent-review status, production-readiness verdict, and real artifact paths or working download links. Preserve incomplete deliverables as an honestly labeled checkpoint rather than discarding them.

Start by inspecting the supplied files, validating the baseline, and executing M0 and the M1 foundation proof. Then continue implementing the dependency-ready backlog. The requested output is the implemented platform and its evidence—not a proposal to implement it later.
