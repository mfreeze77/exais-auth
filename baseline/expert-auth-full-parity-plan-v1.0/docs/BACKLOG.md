# Delivery backlog and dependency graph

All work is planned. Responsible roles are responsibilities, not commitments to hire a particular staffing level. Milestones are ordered delivery gates, not time estimates. Basic security, deployment, UI and SDK scaffolding start in M1/M2; later milestones close full coverage rather than postpone fundamentals.

## M0 — Freeze scope and legal reuse boundary

Depends on: none. Families: BAS.

**Gate:** All sources, versions, schema captures, licensing decisions and requirement mappings recorded. Unknown contracts and unlicensed artifacts block foundation approval.

### WP-001 — Freeze documentation and operation contracts

Owner role: Platform engineering. Dependencies: none.

Deliverables: versioned feature/SDK/plugin/configuration matrix; 205 schema-complete operation records; documentation change log.

Acceptance: Every researched item maps to a requirement; every relevant contract field is captured or explicitly blocked.

### WP-002 — Audit licenses and reproducible dependency closure

Owner role: Engineering + licensing review. Dependencies: WP-001.

Deliverables: source/license/SBOM register; restricted-content exclusion list; dependency fetch/build egress allowlist.

Acceptance: No unapproved code or runtime dependency required for the selected unrestricted build.

### WP-003 — Create reference environments and behavioral fixtures

Owner role: Platform engineering. Dependencies: WP-001, WP-002.

Deliverables: owned synthetic reference deployment; permitted advanced-feature evidence; golden request/response/state fixtures.

Acceptance: Reference credentials/data are synthetic and authorized; unavailable commercial reference behavior stays marked unverified.

## M1 — Prove foundation and canonical identity/session boundaries

Depends on: M0. Families: IDN, CFG.

**Gate:** Pass identity collision/sharing, linking, embedded authentication, refresh concurrency and API adapter spikes. Select one authority through ADR-001; publish owned data and contract boundaries.

### WP-004 — Run foundation feasibility spike

Owner role: Platform engineering. Dependencies: WP-003.

Deliverables: Keycloak mapping proof; OSS SuperTokens reuse comparison if required; ADR-001 engine selection.

Acceptance: Critical tenant/link/session/embedded-SDK examples pass without insecure password-grant shortcuts or two credential authorities.

### WP-005 — Implement canonical tenancy and identity mapping

Owner role: Platform engineering. Dependencies: WP-004.

Deliverables: invariant-enforced schema; membership and linking transaction boundaries; storage partition routing.

Acceptance: Parallel same-email and shared-user tests preserve distinct app/tenant contexts.

### WP-006 — Establish security envelope and build/deployment skeleton

Owner role: Platform engineering. Dependencies: WP-004.

Deliverables: private engine/data network; secret rotation/bootstrap; CI scaffolding and local launch; threat model v1.

Acceptance: Unauthenticated private API access fails; secrets never enter browser bundles; production rejects ephemeral persistence.

### WP-007 — Establish adapters and configuration contract

Owner role: Platform engineering. Dependencies: WP-005, WP-006.

Deliverables: private provider interfaces; FDI/CDI translation skeleton; base-path/tenant routing validation.

Acceptance: All auth calls resolve explicit app/tenant context; unknown versions fail explicitly.

## M2 — Complete authentication and session vertical slices

Depends on: M1. Families: PWD, PLS, SOC, VER, DEL, SES.

**Gate:** Every required password/passwordless/social/verification/session behavior passes positive, negative and concurrency tests; local delivery harness and an application integration work.

### WP-008 — Build session authority and transports

Owner role: Platform engineering. Dependencies: WP-007.

Deliverables: access/refresh lifecycle; cookie/header/CSRF middleware; revocation modes and race tests.

Acceptance: Concurrent refresh/response-loss/replay/rotation tests pass without blanket grace periods.

### WP-009 — Build password and email verification flows

Owner role: Platform engineering. Dependencies: WP-008.

Deliverables: password/username/phone configuration; reset/verification flows; hash import fixtures.

Acceptance: One-time actions consume atomically; disabled/banned/wrong-tenant users cannot obtain sessions.

### WP-010 — Build message outbox and delivery adapters

Owner role: Platform engineering. Dependencies: WP-007.

Deliverables: SMTP/custom mail; Twilio/custom SMS; templates and local message sink.

Acceptance: Delivery outage/retry tests do not leak secrets or duplicate authentication effects.

### WP-011 — Build passwordless and invitation flows

Owner role: Platform engineering. Dependencies: WP-008, WP-010.

Deliverables: email/SMS OTP; magic links and combined mode; invitations/allowlists.

Acceptance: Resend, replay, brute-force and mail-preview tests pass.

### WP-012 — Complete social provider adapters

Owner role: Platform engineering. Dependencies: WP-008, WP-009.

Deliverables: baseline provider catalog; custom providers; Apple callback and multiple-client profiles.

Acceptance: Each baseline provider has a passing permitted live test or a clearly blocked live qualification; mocks alone do not certify provider interoperability.

## M3 — Complete linking, membership and permissions

Depends on: M2. Families: LNK, RBC.

**Gate:** Same-email, cross-tenant, verified/unverified link, unlink, role scope and access-propagation tests pass without inherited access escalation.

### WP-013 — Implement transactional linking and ID mapping

Owner role: Platform engineering. Dependencies: WP-005, WP-009, WP-011, WP-012.

Deliverables: primary/method identities; manual/automatic linking; unlink/conflict recovery.

Acceptance: Same-email and verified-domain shortcuts cannot take over another identity.

### WP-014 — Implement app roles and tenant-scoped assignments

Owner role: Platform engineering. Dependencies: WP-013.

Deliverables: role/permission APIs; backend/frontend guards; authorization freshness profiles.

Acceptance: Negative resource-ownership and stale-privilege tests pass.

## M4 — Complete factors, passkeys and recovery

Depends on: M3. Families: MFA, WBA.

**Gate:** Enrollment, step-up, recovery, factor removal, WebAuthn origin and replay tests pass with recent-authentication policy.

### WP-015 — Implement MFA factors and recovery

Owner role: Platform engineering. Dependencies: WP-013, WP-014.

Deliverables: TOTP/email/SMS factor orchestration; recovery codes; per-user/tenant step-up policy.

Acceptance: Factors cannot enroll/remove/recover without the configured evidence and replay controls.

### WP-016 — Implement WebAuthn/passkey lifecycle

Owner role: Platform engineering. Dependencies: WP-015.

Deliverables: registration/authentication/recovery; credential administration; virtual-authenticator tests.

Acceptance: Wrong origin/RP/challenge and replay attempts fail; physical-platform qualification is separately recorded.

## M5 — Complete enterprise, unified login and machine/agent auth

Depends on: M4. Families: ENT, OAU, M2M, MCP.

**Gate:** OIDC/SAML interoperability, multi-app logout, client lifecycle, resource audiences and MCP tool authorization pass under the frozen protocol profiles.

### WP-017 — Implement enterprise discovery and SAML

Owner role: Platform engineering. Dependencies: WP-014, WP-016.

Deliverables: tenant discovery/domain verification; SAML and external OIDC configurations; certificate rollover.

Acceptance: Signed assertion issuer/audience/recipient/replay and administrator ownership tests pass.

### WP-018 — Implement OAuth/OIDC provider and unified login

Owner role: Platform engineering. Dependencies: WP-017.

Deliverables: clients/scopes/consent; authorization-code PKCE; tokens/introspection/revocation/logout.

Acceptance: No ROPC shortcut; issuer/client/redirect/token audience conformance and multi-app logout tests pass.

### WP-019 — Implement machine-to-machine lifecycle

Owner role: Platform engineering. Dependencies: WP-018.

Deliverables: client credential provisioning; secret rotation; audience-scoped service permissions.

Acceptance: User tokens cannot silently become machine credentials; wrong-audience credentials fail.

### WP-020 — Implement MCP authorization

Owner role: Platform engineering. Dependencies: WP-018, WP-019.

Deliverables: versioned protected-resource metadata; discovery/resource indicators; tool-level authorization adapter.

Acceptance: Wrong-resource tokens and authorized-user/unauthorized-tool calls fail; unsupported protocol revision is explicit.

## M6 — Complete local attack protection and CAPTCHA

Depends on: M2, M4, M5. Families: RSK, CAP.

**Gate:** All documented signal classes execute locally with quality/false-positive evidence, clear unknown states and enforcement tests; optional providers remain opt-in.

### WP-021 — Build local risk signal acquisition

Owner role: Security engineering + data evaluation. Dependencies: WP-008, WP-015, WP-020.

Deliverables: eight signal families; licensed local datasets; retention/confidence metadata.

Acceptance: Missing data is unknown rather than a fabricated safe verdict.

### WP-022 — Build risk policies, actions and evaluation

Owner role: Security engineering + independent reviewer. Dependencies: WP-021.

Deliverables: allow/challenge/step-up/deny engine; explainable audit; quality test corpus and false-positive report.

Acceptance: All actions enforce policy, quality targets are declared before measurement, and failures remain visible.

### WP-023 — Build local and optional CAPTCHA adapters

Owner role: Platform engineering. Dependencies: WP-022.

Deliverables: local challenge; reCAPTCHA v2/v3 and Turnstile adapters; accessible flow integration.

Acceptance: No vendor key is required for the local default; challenge replay or flow substitution fails.

## M7 — Complete customer/admin UI and plugins

Depends on: M3, M4, M5, M6. Families: USR, ADM, UIX, PLG.

**Gate:** All admin/profile/tenant/ban/plugin/UI flows pass role-boundary and accessibility tests. No platform function requires a vendor-hosted dashboard or paid seat.

### WP-024 — Build user lifecycle and self-service profile

Owner role: Platform engineering. Dependencies: WP-013, WP-014, WP-016.

Deliverables: profile/metadata/search/counts; ban/deletion workflows; progressive profiling.

Acceptance: Protected-field mass assignment and profile-gate bypass tests fail safely.

### WP-025 — Build authentication UI and extension contracts

Owner role: Platform engineering. Dependencies: WP-016, WP-017, WP-023.

Deliverables: prebuilt/headless/embedded forms; translations/themes/overrides; accessibility tests.

Acceptance: Every error/loading/recovery state has a tested UI; server enforcement survives bypassing UI.

### WP-026 — Build admin/customer console

Owner role: Platform engineering. Dependencies: WP-022, WP-024, WP-025.

Deliverables: admin MFA/session management; delegated tenant/provider admin; audited sensitive actions.

Acceptance: Tenant administrators cannot obtain platform scope or view another tenant’s credentials/configuration.

### WP-027 — Close fourteen-plugin parity

Owner role: Platform engineering. Dependencies: WP-023, WP-024, WP-025, WP-026.

Deliverables: plugin ports/adapters; plugin API/version matrix; self-hosted OpenTelemetry export.

Acceptance: Both server and frontend plugin halves pass lifecycle and customization tests.

## M8 — Complete SDKs, integrations and migration

Depends on: M2, M3, M4, M5, M7. Families: SDK, INT, MIG.

**Gate:** All original SDK/platform profiles build and pass qualification; integration examples and full migration/reconciliation/rollback evidence exist.

### WP-028 — Complete Node/Python/Go backend SDK profiles

Owner role: Platform engineering. Dependencies: WP-027.

Deliverables: three backend distributions; middleware/framework bindings; recipe-specific support matrix.

Acceptance: Each baseline SDK profile builds and passes contracts; unsupported upstream features are not invented as prior parity.

### WP-029 — Complete web, React and mobile frontend profiles

Owner role: Web + mobile engineering. Dependencies: WP-028.

Deliverables: five frontend distributions; refresh/storage/deep-link tests; unmodified/forked compatibility labels.

Acceptance: Browser/native lifecycle tests and selected OS/SDK build evidence exist.

### WP-030 — Complete framework/platform integration samples

Owner role: Platform engineering. Dependencies: WP-028, WP-029.

Deliverables: all original integration profiles; CI fixtures; operator setup documentation.

Acceptance: Each example is runnable and tested; paid hosting is never the only deployable option.

### WP-031 — Build migration/import/reconciliation/rollback

Owner role: Platform engineering. Dependencies: WP-013, WP-016, WP-028.

Deliverables: bulk/lazy/Rownd migration tools; session bridge; identity/factor/membership reconciliation.

Acceptance: No unexplained data delta; nonportable sessions/passkeys are declared, not silently lost.

## M9 — Qualify production operations and disaster recovery

Depends on: M6, M7, M8. Families: OPS.

**Gate:** Reproducible deployments, multiple replicas, load/failure tests, recovery, upgrades, redaction and no-auth-vendor-egress qualification pass.

### WP-032 — Qualify clustering, performance and dependency failure

Owner role: Platform operations. Dependencies: WP-027, WP-030, WP-031.

Deliverables: multi-replica topology; capacity report; failure/load/concurrency runs.

Acceptance: Chosen measured latency/capacity targets hold; dependency outages follow declared fail-open/closed policy.

### WP-033 — Qualify backup, restore, key lifecycle and upgrades

Owner role: Platform operations. Dependencies: WP-032.

Deliverables: restore evidence; signing/secret rotation; upgrade and rollback runbooks.

Acceptance: An independent clean deployment restores correctly without resurrecting revoked credentials or relying on lost encryption keys.

### WP-034 — Qualify sovereignty and no-fee execution

Owner role: Platform engineering. Dependencies: WP-033.

Deliverables: deny-by-default auth-vendor egress run; SBOM/build validation; local risk and challenge run.

Acceptance: Full local feature profile runs without entitlement servers, vendor dashboard login or trial expiry.

## M10 — Close full parity and independently review release

Depends on: M0, M1, M2, M3, M4, M5, M6, M7, M8, M9. Families: CMP, TST.

**Gate:** All required functional rows have implementation, tests and reviewed evidence; all 205 operations accounted; supported compatibility profiles explicit; exploitable critical/high findings remediated.

### WP-035 — Close all operation/SDK compatibility contracts

Owner role: Platform engineering. Dependencies: WP-028, WP-029, WP-034.

Deliverables: 205-operation final dispositions; schema and differential reports; versioned compatibility exceptions.

Acceptance: No missing business behavior or undocumented claimed compatibility; no success stubs.

### WP-036 — Independent security assessment and release decision

Owner role: Independent security reviewer + product owner. Dependencies: WP-035.

Deliverables: review findings/remediation evidence; 265-row acceptance report; production release decision.

Acceptance: All required rows verified with evidence; critical/high exploitable issues resolved; quality/operations limits disclosed.
