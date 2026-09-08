# ExpertAuth — full SuperTokens parity implementation plan

**Version:** 1.0 · **Research baseline:** September 8, 2026 · **State:** specification and backlog; no implementation certified.

## 1. Product commitment

Build and operate an independently hosted authentication platform with the entire researched SuperTokens functional surface, including capabilities that the vendor sells as add-ons. No mandatory authentication subscription, per-user charge, MFA/SSO unlock, dashboard seat license, proprietary activation service, or vendor-hosted administration dependency may be required.

This is not a plan to stop after installing Keycloak, styling a login page, or connecting one application. Those are intermediate demonstrations. Full delivery includes identity and tenant semantics, sessions, all original SDK platforms, plugins, enterprise login, unified login, M2M, MCP authorization, risk controls, administration, migration, and production operations.

The source research [DR] and current references [S01–S12] are the functional benchmark. This package expands that benchmark into **265 required implementation and qualification requirements, organized into 29 families, 36 work packages, and 11 milestones**. These are our planning counts, not a claim that SuperTokens officially defines 265 features. A separate register accounts for **49 FDI and 156 CDI operation entries** [S02, S03], including deprecated, diagnostic, administrative, and license-related operations. An operation count is not a feature-completeness score.

### Five separate acceptance dimensions

| Dimension | Required outcome | What must not be claimed without evidence |
|---|---|---|
| Functional parity | Every required customer/developer workflow and documented supported configuration has an implementation and acceptance evidence. | A similarly named button or endpoint is not completion. |
| Behavioral parity | Identity, linking, tenant scope, token lifecycle, errors, hooks, and side effects match the frozen supported profile. | Matching happy-path JSON does not prove transactional or security behavior. |
| API/SDK compatibility | Explicit versioned FDI/CDI contracts and original SDK/platform profiles are qualified; legacy routes are accounted for. | A Keycloak token endpoint is not automatically compatible with a SuperTokens SDK. |
| Security effectiveness | Security invariants, adversarial tests, risk detection, false positives, and independent review have evidence. | Public docs cannot establish identical proprietary models, feeds, or detection quality. |
| Operational independence | Build, deploy, restore, upgrade, and operate without an authentication-vendor service or entitlement. | Self-hosting does not mean zero server, delivery, maintenance, or recovery cost. |

All required functionality is mandatory. Milestones sequence implementation; they do not convert difficult requirements into optional items. Unsupported or unverified behavior remains visibly blocked. Vendor-specific license bookkeeping is an explicitly declared non-equivalence, not missing MFA/SSO functionality and not a fabricated commercial entitlement.

## 2. Foundation decision: preserve requirements, then select the engine

**Recommended starting position:** test the Apache-licensed Keycloak community engine with supported extensions against the hardest parity cases before committing the product to it. Keycloak supplies a substantial identity/protocol platform and documented extension interfaces [S17–S20]. That establishes it as a candidate, not proof of full SuperTokens equivalence.

The previous recommendation to use Keycloak should not be mistaken for a conclusion that its organization, credential, or session model already reproduces the reference system. The reference permits tenant-specific identities with the same email, explicitly shared users across eligible tenants, app-level role definitions with tenant-specific assignments, app-level metadata, and tenant-specific sessions [S04]. Those must survive any engine choice.

**M1 makes a binding architecture decision.** It must execute the following proof cases through real APIs and a representative client, not merely show configuration screenshots:

| Proof case | Pass criterion |
|---|---|
| Identity collision | The same email/provider identity can remain distinct across two tenants and two apps as configured. |
| Explicit sharing | One app identity can be explicitly shared across eligible same-storage tenants without sharing sessions or permissions. |
| Link/unlink | Primary and method-specific identities remain stable through verified linking, conflicts, unlinking, and concurrent requests. |
| Embedded authentication | Required headless/embedded flows, pre-authentication states, MFA challenges, and hook behavior work through the adapter. |
| Session behavior | Rotation, concurrent refresh, response loss, replay classification, cookies/headers, and revocation profiles pass. |
| Developer contract | A representative Node/React and Python application executes the selected protocol profile, with errors and state changes characterized. |
| Unrestricted operation | No restricted binary, activation key, trial entitlement, or vendor service is required. |

Do not route an embedded password form through OAuth Resource Owner Password Credentials as a shortcut: RFC 9700 prohibits that grant [S24]. A legitimate first-party authentication extension or existing appropriate authentication API must implement the workflow.

If the Keycloak mapping fails these gates or requires duplicating most of the credential/session engine, select the **license-audited Apache portions of SuperTokens Core and SDKs as the alternative foundation**, then independently implement missing unrestricted components. The alternative must pass the same proof cases and license/dependency gate [S14, S15]. This is not a direction to patch enterprise checks or reuse restricted implementation code.

**One credential/session authority is selected.** Do not run Keycloak, SuperTokens, and another authentication framework as competing sources of truth. ADR-001 must record the selected engine, mappings, source pins, custom code boundaries, data owners, and rejected alternatives. Scope does not shrink when an engine is rejected.

## 3. Proposed architecture and ownership

| Component | Responsibility | Ownership constraint |
|---|---|---|
| Authentication client packages | Browser/native interaction, UI state, refresh coordination, hook contracts. | Never contain server credentials or treat client-side guards as authorization. |
| Application backend adapters | FDI routes, framework integration, request context, server guards, provider orchestration where required. | Preserve the client → application backend → private engine trust boundary. |
| Private identity engine | Credential verification, authoritative identity linkage, session/refresh state, factor state and signing operations as selected in ADR-001. | A single write authority owns each security-critical state machine. |
| Compatibility layer | Version negotiation, route/schema/error/cookie translations and method-to-primary ID mapping. | It must not create an independent refresh-token store or bypass engine policy. |
| Control plane | App/tenant provisioning, branding, policy configuration, delegated administration, audit and migration jobs. | Provision through engine interfaces; do not write directly into upstream-owned tables. |
| Local risk/challenge service | Local signal computation, approved datasets, policy decisions, CAPTCHA challenge verification. | No mandatory paid reputation endpoint; uncertainty and unavailable data are explicit. |
| Delivery service | SMTP/custom email, SMS adapters, templates, retries and outbox processing. | Transport is operator-configured; side effects are idempotent and secrets are redacted. |
| Operations layer | Build provenance, deployment, monitoring, backup/restore, upgrades and security response. | No required vendor console or licensing callback. |

A TypeScript control plane/dashboard and JavaScript client packages fit the web surfaces; Python and Go SDKs remain first-class required deliverables. Engine-specific Java code is retained where Keycloak or SuperTokens reuse makes it appropriate. PostgreSQL is the proposed durable store, with separate upstream-owned and product-owned schemas/databases. An optional shared cache may support rate limiting and revocation acceleration, but must not become an unreviewed second refresh authority.

Start with a small number of deployable services, not one microservice per feature. Containers, reverse proxy, engine, PostgreSQL, control plane, and a background worker are sufficient initial boundaries; risk and delivery modules can be separately isolated when measured load or security boundaries justify it. Runtime versions remain unset until the M0 compatibility/security freeze.

### Intended implementation repository

This is the proposed future source layout. The delivered package is the plan and registries, not these implementations.

```text
expert-auth/
  apps/control-plane/         apps/admin-console/
  packages/contracts/         packages/compatibility/
  packages/identity-mapping/  packages/risk-policy/
  packages/delivery/          packages/plugins/
  engine-extensions/         sdk/node/    sdk/python/   sdk/go/
  sdk/web/                   sdk/react/   sdk/react-native/
  sdk/ios/                   sdk/android/
  examples/                  migrations/
  deploy/                    tests/contracts/
  tests/security/            tests/concurrency/  tests/migration/
  evidence/                  docs/adr/
```

## 4. Full functional scope

Every group below is required. The detailed matrix in `docs/FEATURE_MATRIX.md` has individually numbered acceptance criteria and milestone assignments.

| Area | Required scope | Primary implementation approach |
|---|---|---|
| Password login | Email/password; configured username/password and phone/password; custom forms; reset; registration controls; password hashes and rehash; password managers. | Reuse audited credential primitives; implement reference behavior and UI integration. |
| Passwordless | Email/SMS OTP, magic links, combined flows, resend/expiry, code management, invitations, allowlists, custom delivery. | Reuse where exact behavior exists; implement atomic challenge lifecycle and adapters. |
| Social providers | Full baseline provider catalog, custom providers, multiple clients, Apple callback behavior, invites, hooks. | Reuse audited protocol/provider adapters and test each actual provider. |
| Tenant/app identity | Isolated and explicitly shared identity modes, tenant login configuration, app/tenant lifecycle, database partitions, routing, membership. | Canonical mapping plus engine extension, proven by M1. |
| Enterprise login | SAML, legacy interoperability, tenant/domain discovery, per-tenant providers, common-domain/subdomain workflows, certificate rotation. | Reuse proven federation implementations; build tenancy/self-service orchestration. |
| Unified login | OIDC/OAuth provider, multiple frontends/backends, clients, scopes, claims, consent, tokens, logout, desktop/mobile login reuse. | One provider authority, not ad hoc JWT endpoints. |
| M2M and MCP | Client lifecycle and credentials; audience/scopes; legacy transition; versioned MCP discovery/resource binding/tool authorization. | Protocol-backed machine identities and resource guards. |
| Passkeys | Registration/authentication, credential inventory/deletion, recovery, customization, RP/origin handling. | Audited WebAuthn machinery with complete lifecycle/UI tests. |
| Sessions | Access/refresh, cookie/header modes, local/online verification, CSRF, rotation/reuse, claims/data, SSR, WebSockets, subdomains, anonymous sessions, impersonation, iframe handling, blacklist, multiple endpoints. | Security-critical engine authority plus client/backend compatibility. |
| MFA and verification | TOTP, email/SMS OTP, passkey factors, recovery codes, step-up, user/tenant policy, enrollment/removal, verification state/actions. | Reuse factors; implement complete policy and recovery orchestration. |
| Risk and CAPTCHA | All eight documented signal classes, local decisions, challenge/step-up/deny, configurable local and external CAPTCHA adapters. | Local policy engine, approved open data, measured quality; not an always-allow stub. |
| Roles/permissions | App role definitions, tenant assignments, grants/revocations, backend/frontend guards, freshness, application resource examples. | Reuse compatible engine role machinery; enforce resource ownership in applications. |
| Users/profiles | Search/list/count, metadata, profile updates, deduplication, bans, deletion, progressive profiling. | Engine APIs and custom self-service/admin workflows. |
| Account linking | Primary/method identity model, manual/automatic linking, link-possibility checks, add password/social methods, unlink and session effects. | Atomic identity transactions and proof-of-control rules. |
| Administration | User/admin sessions, unlimited software-licensed administrator count, delegated tenancy, providers, configuration, audits, risk/migration remediation. | Self-hosted branded console with server authorization. |
| UI/extensions | Prebuilt/headless/embedded UI, styling, localization, hooks, function/API overrides, user context and network interceptors. | Audit/reuse licensed UI and define versioned extension contracts. |
| Plugins | Every one of the fourteen original package surfaces, including paired frontend/backend plugins. | Audit/adapt each package or supply equivalent owned package. |
| SDKs/integrations | All original three backend and five frontend SDK profiles, framework examples and host integrations. | Reuse compatible SDK code or maintain clearly labeled forks/adapters. |
| Migration | Bulk/direct/lazy import, hash/no-hash accounts, mappings, verification, roles, metadata, factors, sessions, Rownd, historical database transition, reconciliation/rollback. | Owned migration tools, realistic fixtures, explicit nonportable data decisions. |
| Configuration/operations | Routing, API keys, IP rules, TLS, pools, signing keys, secrets, observability, rate limits, HA, backup/restore, upgrades and CLI. | Versioned deployment/configuration system and tested operational runbooks. |

The provider names and original package/platform lists derive from [DR]. Do not infer that every source SDK supports every feature identically. The compatibility matrix must preserve the capability level of each original version; adding new support is a separately labeled extension, not evidence that it already existed.

## 5. SDK, plugin and integration closure

The required backend families are **Node.js, Python and Go**. The required frontend families are **vanilla JavaScript, React, React Native, iOS and Android** [DR]. A release with only Next.js/FastAPI integration is not full SDK parity.

For each profile record package version, runtime/OS version, supported recipes, request/cookie/header behavior, storage/security behavior, customization interfaces, exact supported APIs and known restrictions. Compile all delivered packages; run real native/browser tests in supported environments. An iOS source file that was never compiled is not a qualified SDK.

The fourteen plugin surfaces are CAPTCHA Node/React; OpenTelemetry Node; profile-base React; profile-details Node/React; progressive-profiling Node/React; tenant-discovery Node/React; tenants Node/React; and user-banning Node/React [DR, S12]. Server and UI halves are separate compatibility responsibilities.

Integration closure includes Next.js App Router and Pages Router, NestJS, GraphQL, Hasura, Supabase, AWS Lambda, AWS AppSync, Netlify and Vercel [DR]. Those host services are optional deployment targets, not mandatory purchases. Local executable examples must exist. Live provider qualification that needs a third-party account remains visibly pending until the permitted test is run; mocks cannot silently substitute for it.

## 6. Protocol contract and API compatibility

M0 must record exact method/path, recipe ID, protocol version, headers, query/body schemas, defaults, missing-versus-null behavior, success/error shapes, cookies, token claims, pagination, side effects, tenant scope, idempotency and deprecation status for every operation. SDK and Core specifications must match a selected compatible release, not arbitrary moving `master` branches [S02, S03, S21, S22].

This package captures operation names/methods, not their complete schemas. The JSON fields are deliberately null until captured. This is honest planned work, not a claim to have produced an executable OpenAPI server contract already.

The FDI adapter must preserve application-facing behavior. The CDI adapter stays private and must enforce server authentication, tenant scope and least privilege. Deprecated business operations within the chosen baseline remain required. A new endpoint with a similar name is not a drop-in substitute.

The license/enterprise-entitlement/vendor-telemetry entries are accounted for but cannot truthfully behave as vendor commercial services. Supply clearly owned capabilities/diagnostics and documented non-equivalence; do not fabricate a vendor license or advertise untouched vendor compatibility for those workflows. Every advanced business capability remains mandatory despite this distinction.

Test licensed unmodified upstream SDKs where possible; use explicitly named maintained forks where adapting a vendor-specific control path is necessary. Keep separate compatibility reports for each combination. There is no single blanket “all versions compatible” claim.

## 7. Data and session invariants

The conceptual schema is an implementation contract, not a claim that upstream tables have these literal names. `docs/CONFIGURATION_AND_DATA_MODEL.md` expands it.

App ID, tenant ID, method identity, primary identity and external ID are distinct concepts. A user’s stable app identity may be associated with multiple permitted tenants; the session and role assignment still carry their own tenant scope [S04]. Account linking must not transfer privileges merely because an email matches.

Refresh state is authoritative, durable, atomic and testable. Current and previous token verifiers, revocation, expiration and rotation decisions must survive concurrent replicas and crash/retry scenarios. The adapter must not independently rotate a second copy of the same session.

Locally checked access JWTs and immediate revocation are different operating profiles. Revoking refresh state does not cause an offline verifier to discover that change. Define access-token expiry and, when immediate or bounded online revocation is required, use online session checks/invalidation infrastructure and measure propagation. Do not promise instantaneous global logout while relying only on offline JWT validation [DR, S05].

Credential changes, factor resets, bans, tenant removal and linking must all have explicit session/claim consequences. Deleting or disabling one login method must not leave an orphaned session or accidentally lock a user out of all methods without a controlled recovery path.

## 8. Risk effectiveness and no-vendor operation

The published attack suite names brute force, breached passwords, impossible travel, bots, suspicious IPs, new devices, device count and requester detection [S09]. Our system must implement each corresponding signal and policy action, rather than expose placeholder settings.

Use approved locally stored feeds/data where feasible, retained signal provenance, privacy-conscious device evidence, uncertainty flags and versioned decisions. An optional externally purchased feed is allowed only as an operator-selected enhancement; the baseline must not require it. Licensing and availability of each selected dataset are M0 requirements. A CAPTCHA building block such as ALTCHA does not alone replace the full risk engine [S25].

Define evaluation targets before measuring. Test malicious and legitimate cases, proxies/VPNs, shared networks, device resets, accessibility and missing data. Record false positives, missed attacks, latency and coverage. Do not claim identical proprietary detection accuracy without comparative evidence. Unavailable lawful reference tests remain a stated validation limit; they do not justify dropping a feature.

No-fee qualification blocks authentication-vendor egress while exercising local login, sessions, factors, administration, risk and local CAPTCHA. Social IdPs and configured mail/SMS transports are separately declared external dependencies. Reproducing an SMTP/SMS adapter does not mean providing free carrier or mail-delivery infrastructure. Compliance badges and vendor support SLAs are not inherited from source code.

## 9. Delivery milestones

| Milestone | Required result | Release consequence |
|---|---|---|
| M0 | Versioned feature/contract/license baseline and lawful reference evidence. | No foundation commitment on unknown licenses or missing critical contracts. |
| M1 | Foundation proof, single-authority ADR, identity/config schema and security envelope. | Reject inadequate engine mappings rather than reduce scope. |
| M2 | Password, passwordless, social, verification, delivery and full sessions. | Useful first application slice; not full parity. |
| M3 | Linking, role scope, membership and resource authorization integration. | No unverified same-email linking or cross-tenant privilege transfer. |
| M4 | MFA, step-up, passkeys and complete recovery. | Recovery cannot be weaker than the declared account policy. |
| M5 | Enterprise, unified login, M2M and MCP. | Protocol/issuer/audience/interoperability gates must pass. |
| M6 | All local risk signal/action classes and CAPTCHA. | Quality evidence, not a feature flag, closes the milestone. |
| M7 | Complete user/admin UI, customization and fourteen-plugin surface. | Customer administrators remain isolated from platform authority. |
| M8 | All SDK profiles, framework integrations, migrations and rollback. | Native source-only deliverables and unexplained migration gaps block completion. |
| M9 | Production performance, multiple replicas, failure recovery and sovereignty. | No production approval based only on a single-container demo. |
| M10 | All acceptance evidence, API/SDK closure and independent security review. | Publish full parity only when required gates actually pass. |

The machine-readable backlog supplies 36 work packages with dependencies and outputs. Basic testing, secrets, deployment and observability begin in M1; M9 is their production qualification, not their first implementation. Minimal UI and SDK slices start early; M7/M8 close the entire surface.

## 10. Test and release gates

Every requirement needs implementation paths, positive and negative tests, a concrete test-run artifact, environment/version records and reviewer disposition. A placeholder test name or `200 OK` stub cannot count as passed.

Run property and concurrency tests for one-time tokens and linking; differential API/SDK tests against permitted reference deployments; browser/native lifecycle tests; standards-oriented OAuth/SAML/WebAuthn checks; tenant/resource negative tests; migration reconciliation; replica/crash/network failure tests; no-vendor-egress tests; and independent review of custom security-critical code and deployed configuration.

Use synthetic identities and owned or explicitly authorized systems. Do not bypass vendor trial/enterprise controls to obtain behavioral evidence. Public specifications and lawful existing evidence can define implementation requirements; behaviors that have not been tested remain marked accordingly.

Before production, set explicit supported load, latency, revocation, recovery-point and recovery-time objectives and prove them in the target environment. This plan does not invent benchmark measurements. Production qualification requires remediation of exploitable critical/high issues; versioned limitations for other findings must be reviewed rather than hidden.

## 11. Final definition of done

Full delivery means every required functional item is verified, every operation is accounted for with supported compatibility clearly specified, all original SDK profiles are qualified, all advanced feature paths operate without mandatory auth entitlements, recovery/upgrades are demonstrated, and security effectiveness is supported by evidence.

No required feature may disappear through wording such as “future enhancement,” “enterprise later,” “not necessary for the MVP,” or “the engine does not support it.” Intermediate releases may be useful and honestly labeled partial. They are not the requested final product.

### Current evidence state

This deliverable is the **plan, requirements, operation accounting, backlog and plan-integrity tooling**. It is not a compiled engine, a completed source harvest, a schema-complete API spec, a proven architecture spike, an independent security audit, or a running service. Source commit pins and exact API fields remain deliberately unfilled first-milestone work. The validator checks the consistency of this package only; it does not certify authentication behavior.

Source references such as [S04] resolve in `docs/SOURCES.md` and `registry/sources.json`. [DR] identifies the original research report retrieved from your Library. Public source facts and proposed implementation decisions are intentionally distinguished throughout.
