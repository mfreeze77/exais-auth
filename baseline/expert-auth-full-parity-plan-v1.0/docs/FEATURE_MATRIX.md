# Complete implementation requirement matrix

All rows are **required and planned**, not implemented. These are independently written implementation requirements derived from the original research baseline (DR), with selected current primary-source checks. Additional security/operations conditions make the features usable in a self-hosted system. Counts are not percentage-complete estimates. A row may contain several inseparable behaviors; schema/field-level expansion happens in M0.

## BAS — Baseline, licensing, and sovereignty

Milestone: **M0**. Strategy: **audit**. Sources: DR, S14, S15, S19.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| BAS-001 | Frozen public feature baseline | Every research-report feature, SDK, plugin, configuration family and operation has a stable identifier and source; new documentation changes create a reviewed delta rather than silently changing scope. |
| BAS-002 | Commit and artifact provenance | Each reused source or binary has a selected release, full commit or immutable digest, origin, license, notices and dependency list; unset pins block implementation qualification. |
| BAS-003 | No paid authentication entitlement | Start and exercise every built-in capability without an authentication-vendor account, subscription, activation key, usage meter or license-validation service. |
| BAS-004 | Restricted material exclusion | Dependency and artifact scans find no unapproved enterprise source, enterprise binary or runtime download; proprietary code is neither copied nor used to manufacture fake entitlements. |
| BAS-005 | Reproducible source build | Build the chosen OSS components and our changes from the recorded sources in a clean environment; compare declared artifact hashes and SBOM contents. |
| BAS-006 | No hidden outbound dependency | With auth-vendor domains blocked, first-party login, refresh, MFA, administration and local risk evaluation pass; explicitly configured social/mail/SMS traffic is separately allowlisted. |
| BAS-007 | Owned configuration and data export | Export application, tenant, user, roles, provider references, policy and audit data without a vendor service, then restore into an independently deployed instance. |
| BAS-008 | Bounded compatibility claims | Publish exact supported core/API/SDK/plugin versions and distinguish functional parity, wire parity, security quality and deployment evidence. |

## IDN — Application, tenant, and identity foundation

Milestone: **M1**. Strategy: **custom-or-extend**. Sources: DR, S04, S06.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| IDN-001 | Application isolation | The same external email can identify unrelated users in two applications, and tokens/data cannot cross the app boundary. |
| IDN-002 | Default app and tenant | A fresh installation creates the documented default logical application and tenant, and omitted addressing resolves only to those defaults. |
| IDN-003 | Tenant-specific identity namespaces | The same email, phone or provider account in two tenants may create distinct identities without an application-global uniqueness constraint accidentally merging them. |
| IDN-004 | Explicit user sharing | Within an allowed shared storage boundary, explicitly associate one app-scoped identity with two tenants while retaining separate tenant sessions and role assignments. |
| IDN-005 | Primary and method-specific identities | Preserve stable primary IDs and method/recipe IDs, with explicit mappings rather than treating a provider account as the complete application user. |
| IDN-006 | Tenant membership lifecycle | Add and remove memberships with authorization checks; removal prevents new tenant sessions and invalidates access according to the declared revocation profile. |
| IDN-007 | App-level roles and tenant assignments | Define a role once per application and assign it differently for the same user in different tenants; verify both positive and forbidden access. |
| IDN-008 | App-level user metadata | Shared tenant membership does not duplicate or leak the app-scoped metadata record across applications. |
| IDN-009 | Separate persistence domains | Place selected applications or tenants on separate database deployments and reject identity-sharing operations that cross an unsupported physical boundary. |
| IDN-010 | Host and routing resolution | Resolve app/tenant from validated host, route and caller configuration; substituting a host header or tenant parameter cannot select another customer's identity context. |
| IDN-011 | Provisioning lifecycle | Create, configure, list, suspend and delete apps/tenants using idempotent jobs, explicit destructive-operation policy and audit records. |
| IDN-012 | Concurrency and uniqueness | Simultaneous sign-up, membership change and linking tests preserve all uniqueness and foreign-key invariants without orphaned credentials. |

## PWD — Password authentication

Milestone: **M2**. Strategy: **reuse-plus-adapt**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| PWD-001 | Email and password registration/login | Correct credentials create/resolve the expected tenant identity; wrong credentials and disabled accounts cannot create authenticated sessions. |
| PWD-002 | Username and password | Configured username login uses a tenant-scoped normalized identifier without leaking identity existence across tenants. |
| PWD-003 | Phone and password | Support the documented customized phone/password use case with phone normalization and independent verification state. |
| PWD-004 | Custom sign-up/sign-in fields | Validate added fields on the server and in UI, return stable field errors and prevent client-side-only policy bypass. |
| PWD-005 | Password hashing and rehash | Verify supported imported hash fixtures and rehash after successful authentication under a configured modern policy; never expose the hash to clients. |
| PWD-006 | Password reset lifecycle | Issue, expire and atomically consume a reset token; replay, wrong-tenant and concurrent consumption attempts fail. |
| PWD-007 | Registration control | Disable open registration while preserving administrator or explicitly invited registration paths. |
| PWD-008 | Password-manager behavior | Browser autocomplete, generated-password and paste flows work in supported browsers; accessible field labels remain intact. |
| PWD-009 | Authentication hooks and overrides | Pre/post hooks, API overrides and function overrides receive documented context and cannot implicitly bypass shared authorization invariants. |
| PWD-010 | Password change security | Require appropriate recent authentication, notify according to policy and apply the declared session-revocation policy after a change. |

## PLS — Passwordless OTP and magic links

Milestone: **M2**. Strategy: **extend**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| PLS-001 | Email OTP | Start, deliver, consume and expire email codes; enforce attempt limits, tenant binding and one-time use. |
| PLS-002 | SMS OTP | Run the same lifecycle through a configurable SMS adapter without an auth-vendor delivery dependency. |
| PLS-003 | Magic links | Support link creation and consumption with allowed redirects, expiration and replay protection. |
| PLS-004 | Combined OTP and link flows | Where configured, code and link refer to one controlled pre-authentication flow and cannot produce conflicting identities through concurrent consumption. |
| PLS-005 | Resend and throttling | A resend observes configured cooldowns and attempt policy; overlapping delivery does not reset brute-force protection or extend validity unexpectedly. |
| PLS-006 | Code administration | Check, list and revoke one or all active challenges under authorized backend operations without exposing raw secrets to users or logs. |
| PLS-007 | Invitation-based sign-up | Invitations bind intended app/tenant, recipient and expiration; reuse or recipient substitution is rejected. |
| PLS-008 | Allow-list sign-up | Apply tenant-specific allow-list rules before creating a user; disallowed recipients receive a non-enumerating error profile. |
| PLS-009 | Customization and providers | Customize OTP/link templates, verification behavior and hooks; provider failure leaves challenge and delivery state reconcilable. |
| PLS-010 | Link-preview safety | Mail scanners/prefetch do not silently authenticate or consume high-impact actions; a documented confirmation mechanism preserves supported link flows. |

## SOC — Social and custom identity providers

Milestone: **M2**. Strategy: **reuse-plus-adapt**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| SOC-001 | Built-in provider catalog | Supply integration/configuration paths for Google, Google Workspaces, Apple, Discord, Facebook, GitHub, GitLab, Twitter, LinkedIn, Okta and Active Directory; SAML is tracked under enterprise federation. |
| SOC-002 | Custom OAuth/OIDC provider | Register a custom provider with validated issuer/endpoints, claim mapping and callback behavior; reject mismatched issuer or audience. |
| SOC-003 | Provider client variants | Select distinct client configurations by tenant/platform while preventing secret/configuration crossover. |
| SOC-004 | Authorization callback integrity | Validate state and the applicable nonce/PKCE/issuer binding; duplicate or swapped authorization callbacks do not sign in a different session. |
| SOC-005 | Apple callback handling | Exercise Apple's documented callback representation and state preservation rather than assuming every provider uses an identical redirect query flow. |
| SOC-006 | Claims and email trust | Treat provider subject and issuer as identity evidence; an unverified email claim alone never causes privileged linking. |
| SOC-007 | Provider invitations and hooks | Run invitation, allow-list and customization policies consistently on third-party sign-in and sign-up. |
| SOC-008 | Secret and credential rotation | Rotate provider secrets/certificates without exposing them to browser bundles or losing tenant configuration rollback. |

## ENT — Enterprise federation and discovery

Milestone: **M5**. Strategy: **reuse-plus-extend**. Sources: DR, S04.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| ENT-001 | Per-tenant login configuration | Configure enabled password, passwordless and enterprise providers separately per tenant and return only allowed login methods. |
| ENT-002 | Common-domain tenant discovery | Discover/select a tenant through a configured shared login domain without unauthenticated disclosure of sensitive tenant membership. |
| ENT-003 | Subdomain login | Resolve a tenant from an allowlisted subdomain and prevent host-header or suffix-matching spoofing. |
| ENT-004 | Domain ownership and onboarding | Verify ownership before granting domain-directed routing, and handle ownership expiry, conflicts and transfer with audit records. |
| ENT-005 | SAML service-provider flow | Validate signed assertions, issuer, audience, destination, request correlation and validity; reject replay and malformed XML fixtures. |
| ENT-006 | SAML metadata and certificate lifecycle | Import/export metadata, support planned certificate rotation and reject untrusted endpoint/configuration updates. |
| ENT-007 | Legacy SAML migration | Convert documented legacy configuration and mapping behavior or supply an explicit tested adapter; do not label an untested metadata import compatible. |
| ENT-008 | Tenant provider administration | Tenant-authorized administrators can configure their own connections but cannot read another tenant's secrets or edit platform-level providers. |
| ENT-009 | Federation mapping and logout | Map identities and memberships predictably and document/test the extent of SAML/OIDC logout and local-session invalidation. |

## OAU — Unified login and OAuth/OIDC provider

Milestone: **M5**. Strategy: **reuse-plus-adapt**. Sources: DR, S24.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| OAU-001 | Authorization code with PKCE | Public and confidential clients complete the applicable secure authorization-code flow; code reuse, wrong verifier and redirect substitution fail. |
| OAU-002 | Issuer discovery and keys | Publish correct issuer metadata and JWKS, with exact issuer/audience verification and key-rotation overlap tests. |
| OAU-003 | Client registration and administration | Create, list, update, disable and remove OAuth clients; validate redirects, grants and authentication methods per client. |
| OAU-004 | Login and consent interactions | Expose accept/reject login, consent and logout decisions with one-time request binding and least-privilege scope approval. |
| OAU-005 | Shared-backend multi-domain SSO | Two frontend domains sharing one backend authenticate via top-level redirects and keep domain/session boundaries intact. |
| OAU-006 | Separate-backend multi-domain SSO | Two independently configured backend applications reuse central login without sharing raw application refresh tokens or collapsing app identity namespaces. |
| OAU-007 | Desktop and native login reuse | Use external-browser authorization and validated callback/deep-link handling for desktop and mobile clients. |
| OAU-008 | Scopes and custom claims | Issue only approved scopes/claims; reserved claims cannot be overridden and unauthorized application roles do not propagate. |
| OAU-009 | Userinfo, introspection and revocation | Implement authorized userinfo/introspection and token/client revocation with defined propagation and audience restrictions. |
| OAU-010 | Logout and session inventory | Support local app logout, OAuth-session logout and central SSO logout as separate explicit operations with tested effects. |
| OAU-011 | Token lifecycle and consent records | Persist grants/consents and apply expiry, rotation and revocation independently from application cookie sessions. |
| OAU-012 | Legacy provider behavior | Identify required legacy documented token/client behavior and test a migration adapter without enabling prohibited password-grant shortcuts for new clients. |

## M2M — Machine-to-machine authentication

Milestone: **M5**. Strategy: **reuse-plus-adapt**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| M2M-001 | Client-credentials grant | An authorized service obtains an audience- and scope-restricted token; an end-user credential cannot impersonate a machine client. |
| M2M-002 | Service credential management | Create, rotate, expire and revoke machine credentials with audit and overlap policy. |
| M2M-003 | Service authorization | Enforce service-specific permissions and tenant restrictions on every protected operation. |
| M2M-004 | Machine token validation | Validate issuer, audience, time and scopes on service requests and distinguish service principals from human sessions. |
| M2M-005 | Legacy M2M transition | Import/migrate documented legacy machine configuration with controlled overlap and removal of old credentials. |
| M2M-006 | No volume licensing | Issue and validate machine tokens without per-token billing logic or vendor quota enforcement in the software. |

## MCP — MCP authentication and authorization

Milestone: **M5**. Strategy: **custom-adapter**. Sources: DR, S10, S23.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| MCP-001 | Protected resource metadata | The protected MCP endpoint publishes version-pinned OAuth protected-resource metadata and an authorization-server discovery path. |
| MCP-002 | Client authorization flow | Run browser authorization and PKCE for supported MCP clients; client metadata/registration requirements are explicitly profiled to the selected protocol version. |
| MCP-003 | Resource and audience binding | Requests include the required target resource and the MCP server rejects tokens issued for another server or API. |
| MCP-004 | Tool-level scope checks | Tool invocation receives authenticated identity/context and checks the required scope and application/tenant permission. |
| MCP-005 | Authentication errors and challenges | Produce the correct authentication challenge and insufficient-scope behavior; no raw bearer token is reflected in errors. |
| MCP-006 | No token passthrough | Do not forward an inbound bearer token to an unrelated downstream service; obtain an explicitly scoped credential through a supported delegation path. |
| MCP-007 | Compatibility sample | Ship an independently self-hosted MCP sample that authenticates, invokes an allowed tool, rejects a forbidden tool and handles logout/token expiry. |

## WBA — Passkeys and WebAuthn

Milestone: **M4**. Strategy: **reuse-plus-adapt**. Sources: DR, S08.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| WBA-001 | Registration options and credentials | Generate challenge/options and verify credential registration with configured RP ID, origin, user-verification and algorithm policy. |
| WBA-002 | Passkey sign-up and sign-in | Support the documented creation and existing-user authentication flows, including invalid credential and user-not-found outcomes. |
| WBA-003 | Credential inventory | List, name where supported, and remove credentials without exposing private material or another identity's credential metadata. |
| WBA-004 | Challenge lifecycle | Expire/remove options and reject duplicate, wrong-origin, wrong-RP and wrong-tenant responses. |
| WBA-005 | Account recovery | Issue/consume recovery credentials with a strong approved recovery policy, notifications and session revalidation. |
| WBA-006 | Passkeys as an MFA factor | A verified passkey can satisfy the configured factor/assurance policy without counting one ceremony twice as independent factors. |
| WBA-007 | Browser and device coverage | Test supported browsers plus real native/device scenarios; virtual authenticators alone do not qualify device compatibility. |
| WBA-008 | Migration constraints | Preserve RP ID and origin-compatible credentials where possible, otherwise mark required re-enrollment explicitly rather than claiming portable passkeys. |

## SES — Session lifecycle and runtime behavior

Milestone: **M2**. Strategy: **reuse-or-custom-critical**. Sources: DR, S05.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| SES-001 | Session creation | Issue an app/tenant-scoped handle, access token and refresh credential only after required authentication policy succeeds. |
| SES-002 | Local JWT verification | Normal protected requests verify cached signing material and claims locally; invalid issuer, audience, algorithm or expired token is rejected. |
| SES-003 | Stateful refresh rotation | Atomically compare and rotate server-side refresh verifiers; concurrent refresh and response-loss cases follow a documented tested state machine. |
| SES-004 | Refresh reuse detection | Distinguish allowed race/retry behavior from stale-token replay under a versioned policy, and revoke the intended token family on confirmed compromise. |
| SES-005 | Logout and session invalidation | Revoke one or all authorized sessions; subsequent refresh fails while existing access-token behavior matches the declared revocation mode. |
| SES-006 | Online revocation mode | An explicit denylist/version check enforces a measured bounded revocation window; dependency failure follows a documented security policy. |
| SES-007 | Cookie and header transfer | Support both transport modes with correct secure storage, CSRF protections, headers and cookie path/domain flags. |
| SES-008 | Subdomain session sharing | Share sessions only across explicitly configured trusted subdomains in the same allowed identity context; tenant switching requires a distinct tenant session. |
| SES-009 | SSR protection | Server rendering validates sessions without accidentally refreshing from a browser-only context or leaking tokens into rendered HTML. |
| SES-010 | WebSocket verification | Verify initial upgrade and enforce expiration/revocation policy during a long-lived socket; reconnect and reauthentication are tested. |
| SES-011 | Claims and session data | Read/update server-side session data and JWT claims with stable regeneration semantics and protection of reserved claims. |
| SES-012 | Signing key modes | Support configured static/dynamic signing-key behavior, versioned key rotation and old-token overlap; retired keys expire from acceptance. |
| SES-013 | Anonymous sessions | Create limited anonymous sessions and upgrade them without session fixation or unintended role inheritance. |
| SES-014 | Impersonation | Require privileged recent authentication, record actor and subject, enforce bounded duration and exclude prohibited actions. |
| SES-015 | Multiple API endpoints | Multiple configured resource APIs use the right token audience and shared refresh policy without duplicate refresh storms. |
| SES-016 | Interceptors and explicit mode | Fetch/XHR/client integrations support refresh coordination and an opt-out/manual mode with no silently unprotected requests. |
| SES-017 | Error contract | Preserve refresh, expired-session, invalid-claim, forbidden and network-failure distinctions expected by supported SDKs. |
| SES-018 | Iframe behavior | Document and test behavior with supported third-party-cookie/storage policies; use a supported fallback rather than claiming to bypass browser restrictions. |
| SES-019 | Path and domain migration | Changing auth base path/domain has a tested transition policy for cookie scope and old sessions, including safe forced reauthentication when necessary. |
| SES-020 | Server outage behavior | Unexpired offline-verifiable access can continue under its profile; new login/refresh and state-dependent checks fail according to documented boundaries. |

## MFA — Multifactor and assurance policy

Milestone: **M4**. Strategy: **reuse-plus-extend**. Sources: DR, S07.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| MFA-001 | TOTP device enrollment | Create, verify, name, list, remove and import TOTP devices; protect secrets at rest and do not activate unverified enrollment. |
| MFA-002 | TOTP verification controls | Enforce accepted skew/period, failed-attempt policy and replay prevention for relevant operations. |
| MFA-003 | Email and SMS second factors | Deliver and verify independently scoped OTP challenges with expiry, cooldown, retry policy and tenant binding. |
| MFA-004 | Per-user and tenant-wide requirements | Require factors for everyone or selected users according to tenant/app policy; removing a factor cannot silently clear mandatory MFA. |
| MFA-005 | Factor discovery | Return available, enrolled and required factors consistently to backend and frontend clients. |
| MFA-006 | Step-up authentication | Require appropriate factor class and recent authentication for a sensitive action; a stale MFA claim alone does not satisfy freshness. |
| MFA-007 | Recovery codes | Generate, display once, hash, rotate and consume recovery codes atomically; reuse is rejected across replicas. |
| MFA-008 | Factor independence | Passwordless email plus another email challenge is not misrepresented as two independent factors; policies state the achieved assurance. |
| MFA-009 | Route and UI enforcement | Backend guards enforce verification status regardless of hidden UI controls; prebuilt/custom UI represents enrollment and challenge states. |
| MFA-010 | Recovery and factor replacement | Require a documented recovery proof, notify the user and re-evaluate active sessions when factors are reset or replaced. |

## VER — Email verification

Milestone: **M2**. Strategy: **reuse-plus-adapt**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| VER-001 | Verification status | Query verification status for the correct identity/email and distinguish account-level from current-email state. |
| VER-002 | Send and consume verification | Send, expire, remove and consume single-use verification tokens with wrong-tenant and replay rejection. |
| VER-003 | Manual administrative actions | Mark verified/unverified through privileged audited actions; applications cannot forge the result through profile updates. |
| VER-004 | Protected-route behavior | Enforce verification claims on API and UI routes, with bounded stale-claim handling after state changes. |
| VER-005 | Custom and embedded UI | Support embedded verification state, resend actions, text/styling and redirect customization. |
| VER-006 | Email change handling | Updating an email invalidates or re-evaluates old proof and linking policy without granting trust to the replacement address. |

## RSK — Attack protection and risk assessment

Milestone: **M6**. Strategy: **custom-plus-open-data**. Sources: DR, S09.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| RSK-001 | Brute-force detection | Rate and behavior rules cover login, reset, verification and challenge endpoints, including distributed attempts and tenant/account lockout abuse. |
| RSK-002 | Breached-password detection | Check against an approved locally available dataset or optional adapter without logging plaintext or transmitting full password hashes. |
| RSK-003 | Impossible-travel signal | Evaluate time/location uncertainty and VPN/proxy effects; uncertain geography yields an explicit unknown signal, not certain fraud. |
| RSK-004 | Bot and credential-stuffing signal | Combine request/challenge/velocity evidence; test both scripted attacks and legitimate automation/accessibility cases. |
| RSK-005 | Suspicious IP signal | Support approved local IP/ASN/Tor/proxy/reputation feeds with version, age and license metadata; no proprietary intelligence endpoint is required. |
| RSK-006 | New-device detection | Track a scoped, privacy-conscious device recognition signal with reset, loss and cookie-blocking scenarios. |
| RSK-007 | Device-count tracking | Count observed devices using defined retention and confidence, without treating every cookie reset as a confirmed new human/device. |
| RSK-008 | Requester correlation | Correlate available requester signals with explicit confidence/limitations; do not promise identification of arbitrarily disguised devices. |
| RSK-009 | Risk policy and action contract | Return allow, challenge, step-up or deny plus reason codes and policy version; challenge completion is bound to the original transaction. |
| RSK-010 | Unknown and outage state | Missing or stale signals remain unknown; define minimum local protections and fail-open/fail-closed behavior by action and severity. |
| RSK-011 | Risk administration and audit | Explain decisions, configure tenant policy, review outcomes and redact sensitive inputs from telemetry. |
| RSK-012 | Detection quality evaluation | Measure detection and false-positive rates on a documented corpus and lawful available reference tests; never equate an API-shaped stub with comparable protection quality. |

## CAP — CAPTCHA and challenges

Milestone: **M6**. Strategy: **reuse-plus-adapters**. Sources: DR, S11, S25.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| CAP-001 | Self-hosted challenge default | Generate and verify local challenges without vendor keys and reject expired/replayed/wrong-site responses. |
| CAP-002 | reCAPTCHA v2/v3 adapters | Implement documented provider adapters with site/action/hostname validation; use only when operator-configured credentials permit. |
| CAP-003 | Turnstile adapter | Implement server-side validation and equivalent error mapping without making the service mandatory for core operation. |
| CAP-004 | Conditional flow enforcement | Apply challenge rules to configured sign-in, sign-up, reset and passwordless flows with consistent server enforcement. |
| CAP-005 | UI, accessibility and degraded clients | Support suitable accessible challenge/fallback behavior and measure impact on constrained devices; proof-of-work alone is not labeled a complete bot detector. |

## RBC — Roles, permissions and application authorization

Milestone: **M3**. Strategy: **reuse-plus-extend**. Sources: DR, S04.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| RBC-001 | Role and permission lifecycle | Create, update, list and delete roles; grant/revoke permissions with stable app scope. |
| RBC-002 | Tenant-specific assignments | Assign/remove roles to users in a tenant and query users by role and roles by permission without cross-tenant leakage. |
| RBC-003 | Backend guards | Require authenticated context and enforce role/permission claims at each protected API operation. |
| RBC-004 | Frontend guards | Provide route/component helpers while documenting that server authorization remains mandatory. |
| RBC-005 | Authorization change propagation | Removing privileges affects access within the selected online/offline claim freshness contract and refresh regeneration behavior. |
| RBC-006 | Resource isolation integration | Sample document/database/search endpoints enforce tenant/resource ownership even when the user has a valid platform token. |

## USR — User lifecycle, metadata and profiles

Milestone: **M7**. Strategy: **reuse-plus-custom**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| USR-001 | Search and user inventory | List, filter, search and paginate users with stable cursor behavior and authorized tenant/application scope. |
| USR-002 | Counts and activity | Produce total/active-user counts and administrative statistics using documented definitions without fee enforcement. |
| USR-003 | Profile updates | Let users update permitted fields with validation, recent-authentication checks where required and protected fields unavailable to mass assignment. |
| USR-004 | User metadata | Get, merge/update and remove app-scoped metadata with size limits, version control and safe reserved namespaces. |
| USR-005 | Deduplication | Identify potential duplicates and resolve them through the explicit verified linking workflow, not blind same-email merges. |
| USR-006 | User banning | Enforce app/tenant-scoped bans on login, refresh and applicable active sessions; unban behavior is audited. |
| USR-007 | Progressive profiling | Require configured fields at defined stages while keeping incomplete profiles from accidentally receiving privileged access. |
| USR-008 | Deletion and retention | Delete users and dependent state using explicit retention/legal policy; restore/deletion reconciliation does not resurrect removed access. |

## LNK — Account linking and method composition

Milestone: **M3**. Strategy: **custom-or-extend**. Sources: DR, S06.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| LNK-001 | Primary-user creation checks | Determine whether a method identity can become primary without conflicting with another primary identity in the applicable namespace. |
| LNK-002 | Link-possibility checks | Return deterministic conflict outcomes for already-linked identities and account information conflicts. |
| LNK-003 | Manual linking | Require proofs of control for the accounts involved and a recent-authentication policy before transactionally linking. |
| LNK-004 | Automatic linking policy | Enable only for explicit verified/trusted evidence rules; an equal unverified email or broad domain match is insufficient. |
| LNK-005 | Add social or password method | Attach additional login methods to the intended primary user without changing ownership or bypassing verification requirements. |
| LNK-006 | Unlink semantics | Preserve valid remaining login paths and defined method-identity lifecycle; prevent accidental last-method lockout. |
| LNK-007 | Merge/split transaction integrity | Concurrent linking/unlinking preserves unique ownership, tenant membership and credential invariants. |
| LNK-008 | Session and authorization consequences | Resolve subject/recipe IDs consistently after link/unlink and revoke or regenerate affected sessions without transferring unintended roles. |

## ADM — Administration and customer dashboard

Milestone: **M7**. Strategy: **reuse-plus-custom**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| ADM-001 | Self-hosted dashboard | Serve all dashboard assets and APIs locally with your own branding and no required vendor login. |
| ADM-002 | Unlimited licensed administrator count | Create, update, list, disable and delete administrators without software seat entitlements; normal capacity and security limits still apply. |
| ADM-003 | Administrator authentication and sessions | Enforce administrator MFA, list/revoke administrator sessions and separate dashboard credentials/authorization from ordinary users. |
| ADM-004 | User operations dashboard | Search/edit/delete/ban users, inspect metadata/roles and revoke sessions with authorization, confirmation and audit. |
| ADM-005 | Tenant/application management | Create/configure apps and tenants, manage membership and login methods, and inspect isolated user pools. |
| ADM-006 | Enterprise provider management | Configure provider metadata, secrets/certificates and domain ownership with masked secret fields and audited changes. |
| ADM-007 | Delegated administration | A tenant administrator can manage only delegated resources; platform administrator functions remain inaccessible. |
| ADM-008 | Configuration and diagnostics | Expose authorized configuration/status/stats with secrets redacted; liveness and database readiness are visibly distinct. |
| ADM-009 | Risk and lifecycle workflows | Present factor reset, linking conflicts, failed imports and risk events with safe remedial actions. |

## DEL — Email and SMS delivery

Milestone: **M2**. Strategy: **custom-adapters**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| DEL-001 | Operator-controlled SMTP | Verification, reset, invite and email OTP deliver through configured SMTP with no auth-vendor sender service. |
| DEL-002 | Custom email adapter | Support a typed delivery interface with template data, locale, recipient, idempotency and categorized errors. |
| DEL-003 | SMS/Twilio/custom adapter | Support the documented Twilio-style integration and a generic SMS interface without a required provider purchase or claim of cost-free SMS transport. |
| DEL-004 | Templates and localization | Customize sender, subject, HTML/text, links, language and branding safely; untrusted fields cannot inject headers or unsafe markup. |
| DEL-005 | Durable outbox and retries | Persist messages atomically with challenge intent, retry bounded failures and prevent uncontrolled duplicate sends or reissuance. |
| DEL-006 | Delivery operational controls | Apply abuse budgets, monitor bounces/errors where available, protect credentials and never log OTPs, raw links or recovery secrets. |

## MIG — Migration, import and rollback

Milestone: **M8**. Strategy: **custom-tooling**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| MIG-001 | Bulk import staging | Add/list/count/delete staged imports with idempotent batches, schema validation and per-record error reports. |
| MIG-002 | Direct and hash-preserving import | Import individual accounts and supported hash types using fixtures proving authentication succeeds and unsupported types are reported. |
| MIG-003 | No-hash and lazy migration | Provide explicitly secured first-login or password-reset flows for accounts without portable hashes; no fabricated password credential is introduced. |
| MIG-004 | External user-ID mapping | Create/read/update/remove external ID mappings without breaking stable application IDs or linking ownership. |
| MIG-005 | Verification, metadata and roles | Reconcile verification state, app metadata, tenant memberships and role/permission assignments with zero unexplained differences. |
| MIG-006 | MFA and passkey migration | Import transferable TOTP state and eligible passkeys; mark nonportable factor/credential material for re-enrollment. |
| MIG-007 | Session migration bridge | Validate old sessions through an owned authorized bridge and issue new bounded sessions; never assume unrelated token formats are interchangeable. |
| MIG-008 | Rownd transition | Provide a tested mapping/configuration path for the research report's Rownd migration use case, with explicit source credential/data prerequisites. |
| MIG-009 | Historical MySQL to PostgreSQL | Supply a supported conversion/reconciliation path for relevant historical schema snapshots; do not add MySQL as a new production dependency by accident. |
| MIG-010 | Cutover and rollback | Dry-run migration, canary traffic and rehearse rollback; new writes/factors after cutover have a defined reconciliation policy rather than destructive blind downgrade. |

## CFG — Configuration and platform controls

Milestone: **M1**. Strategy: **reuse-plus-custom**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| CFG-001 | Domains and paths | Support appName, websiteDomain, apiDomain, websiteBasePath, apiBasePath and gateway-prefix equivalents with validated combinations. |
| CFG-002 | Origin and CORS handling | Support static/dynamic allowed-origin resolution without wildcard credentialed CORS or untrusted reflected origins. |
| CFG-003 | Recipe selection and configuration | Enable/disable authentication modules with typed validation; disabled modules do not leave accidentally accessible API routes. |
| CFG-004 | Private service authentication | Authenticate backend-to-core operations with rotatable scoped keys and private networking; public clients never receive control-plane credentials. |
| CFG-005 | Core IP filtering | Implement allow/deny caller policies with normalized addresses and trusted proxy handling; forged forwarding headers do not bypass them. |
| CFG-006 | TLS and proxy deployment | Document/run external TLS termination and internal secure transport appropriate to the network boundary. |
| CFG-007 | PostgreSQL configuration | Support DSN/discrete settings, schema/table namespace equivalents and tested database connection-pool controls. |
| CFG-008 | Session and signing configuration | Expose access/refresh lifetimes, signing-key mode/rotation and CSRF/cookie options with safe defaults and explicit migration impact. |
| CFG-009 | CLI and environment configuration | Bootstrap, validate, inspect version/configuration, migrate and export through documented commands without printing secrets. |
| CFG-010 | Secret custody and rotation | Use encrypted secret storage/external file or vault adapters; test provider, service, DB and signing-key rotation and recovery access. |

## OPS — Production deployment and operations

Milestone: **M9**. Strategy: **custom-operations**. Sources: DR, S20.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| OPS-001 | Single-host deployment | Supply production-mode containers, private networks, persistent volumes, TLS, health checks and explicit backup instructions; this profile is not described as highly available. |
| OPS-002 | High-availability deployment | Support redundant auth nodes and an independently resilient data tier, with exercised node/AZ failure and no single proxy/database masquerading as HA. |
| OPS-003 | Gateway and application limits | Enforce request, payload and rate limits at appropriate public boundaries and handle retry-after/backoff safely. |
| OPS-004 | Readiness and liveness | Liveness proves process health; readiness verifies required persistence/dependencies and removes a failed node from traffic. |
| OPS-005 | Metrics, traces and logging | Export self-hosted observability signals and redact passwords, hashes, OTPs, tokens, provider secrets and sensitive profile data. |
| OPS-006 | Backup and recovery | Encrypt and restore databases, key material and configuration in a fresh environment; record measured recovery results. |
| OPS-007 | Upgrade and compatibility | Perform schema-compatible rolling upgrades with old/new SDK fixtures, tested rollback boundaries and pinned images. |
| OPS-008 | Security update ownership | Track upstream advisories, prioritize relevant fixes and run tests on patched dependencies before publication. |
| OPS-009 | Load and capacity evidence | Publish benchmark hardware, data size, request mix, failure rates and latency distributions; do not claim unlimited throughput from unlimited licensing. |
| OPS-010 | Audit and privacy operations | Export security/admin history with access control and retention; enforce deletion and privacy choices in logs, backups and local risk datasets. |
| OPS-011 | Dependency outage controls | Exercise database, cache, SMTP, provider, DNS and signing-key fetch failures with explicitly documented safe behavior. |
| OPS-012 | No certification inheritance | Provide audit-evidence artifacts and control mapping; do not label a fork SOC 2 certified or promise a contractual vendor SLA from code alone. |

## SDK — Backend, web and native SDKs

Milestone: **M8**. Strategy: **reuse-plus-adapt**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| SDK-001 | Node.js SDK | Ship recipe APIs, request adapters, verification, errors, hooks and override behavior for the selected Node versions/frameworks. |
| SDK-002 | Python SDK | Ship and test FastAPI/ASGI and other frozen-baseline adapters, async lifecycle, verification, errors and configuration without Node-only hidden requirements. |
| SDK-003 | Go SDK | Ship and test middleware/context/request/response integrations and the selected baseline recipe surface. |
| SDK-004 | Vanilla JavaScript SDK | Provide framework-independent authentication/session APIs, refresh coordination and explicit network-client integration modes. |
| SDK-005 | React SDK | Provide UI and state/route helpers, hooks, overrides, theme/localization and recipe-composition behavior. |
| SDK-006 | React Native SDK | Verify header-token storage/refresh, deep links, concurrent networking and lifecycle/resume behavior in supported native environments. |
| SDK-007 | iOS SDK | Build and test native integration, secure credential storage, refresh coordination and browser authentication callback behavior. |
| SDK-008 | Android SDK | Build and test native integration, secure credential storage, refresh coordination and browser authentication callback behavior. |
| SDK-009 | Versioned feature matrix | Record feature-by-language/platform support rather than assuming every upstream SDK implements every recipe; no required original platform is dropped. |
| SDK-010 | Consistent error and context contract | SDKs expose normalized documented result types, request context and cancellation/retry semantics while preserving per-version compatibility where promised. |

## UIX — Authentication UI and extensibility

Milestone: **M7**. Strategy: **reuse-plus-custom**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| UIX-001 | Prebuilt and custom authentication UI | Provide complete login, sign-up, reset, verification, OTP, MFA, passkey and recovery states plus headless APIs. |
| UIX-002 | Embedding and component overrides | Embed forms within an application and replace documented components without forking the entire UI. |
| UIX-003 | Theme and CSS | Customize colors/styles, support the documented shadow-DOM choices and preserve accessible focus/validation behavior. |
| UIX-004 | Localization and legal links | Configure translations, tenant branding and terms/privacy links without requiring a vendor-hosted asset. |
| UIX-005 | Post-login redirects | Support application-controlled redirects with server-side allowlisting and consistent continuation after MFA/verification. |
| UIX-006 | Function/API hooks and plugin ordering | Define before/after/error contracts, asynchronous behavior, ordering, exception propagation and context isolation. |
| UIX-007 | Network interceptor extension | Intercept the documented request boundaries safely while redacting credentials and preventing hook-caused infinite refresh loops. |
| UIX-008 | Cross-version extension tests | Compile and execute representative customizations on each supported SDK release so an override signature match is not mistaken for semantic compatibility. |

## PLG — Fourteen documented plugin packages

Milestone: **M7**. Strategy: **audit-and-adapt**. Sources: DR, S12, S13.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| PLG-001 | CAPTCHA Node and React packages | Supply both server and UI counterparts with equivalent configuration and hooks, including a fully local default provider. |
| PLG-002 | OpenTelemetry Node package | Provide equivalent lifecycle tracing/redaction behavior and allow a self-hosted collector. |
| PLG-003 | Profile-base React package | Supply the profile container/composition entry points required by dependent profile plugins. |
| PLG-004 | Profile-details Node and React packages | Enforce server-side field policies and corresponding editable/read-only UI behavior. |
| PLG-005 | Progressive-profiling Node and React packages | Preserve enrollment/completion gating and server/UI consistency through authentication changes. |
| PLG-006 | Tenant-discovery Node and React packages | Resolve tenant candidates and user choice with enumeration controls and correct app context. |
| PLG-007 | Tenants Node and React packages | Support authorized tenant management APIs and corresponding customer-facing UI flows. |
| PLG-008 | User-banning Node and React packages | Apply ban/unban decisions and UI state consistently, including active-session policy. |
| PLG-009 | Plugin package provenance | Verify each package license, dependencies, version and extension signatures rather than assuming the monorepo root makes every runtime dependency reusable. |

## INT — Framework and platform integrations

Milestone: **M8**. Strategy: **adapters-and-samples**. Sources: DR.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| INT-001 | Next.js App Router | Test auth routes, frontend guards, route handlers, proxy/middleware equivalents and server-component/SSR behavior on the frozen Next.js version. |
| INT-002 | Next.js Pages Router | Test API routes, frontend guards and server-side session validation in the Pages Router profile. |
| INT-003 | NestJS | Supply middleware/guard/decorator integration and error propagation examples backed by tests. |
| INT-004 | GraphQL | Supply context authentication, resolver authorization and subscription/session-expiry handling. |
| INT-005 | Hasura | Supply claim/JWT or webhook integration with row/tenant permission fixtures; valid authentication never replaces row authorization. |
| INT-006 | Supabase | Supply the documented interoperability path with issuer/claim validation and RLS fixtures rather than asserting generic JWT interchangeability. |
| INT-007 | AWS Lambda | Test stateless handler startup, request/response cookies, key caching and session verification under concurrency. |
| INT-008 | AWS AppSync | Provide an authorizer/session example with explicit identity propagation and unauthorized subscription tests. |
| INT-009 | Netlify and Vercel | Provide deployment examples with supported runtime constraints, proxy paths, headers and cookie behavior; these hosts are integrations, not mandatory hosting choices. |
| INT-010 | Reproducible local examples | Every integration has a local/test harness plus clearly identified external credentials/prerequisites for live qualification. |

## CMP — API and behavioral compatibility

Milestone: **M10**. Strategy: **contract-adapters**. Sources: DR, S02, S03, S21, S22.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| CMP-001 | FDI operation coverage | Implement and test all 49 frozen reference operation entries, including documented legacy variants, with exact method/path/header/cookie/error behavior for the declared profile. |
| CMP-002 | CDI operation accounting | Account for all 156 entries; implement business/admin equivalents and explicitly classify licensing/telemetry differences without fake vendor-license success. |
| CMP-003 | Schema and field behavior | Capture request/response schemas, missing/null fields, defaults, error variants and pagination; unknown schema fields remain qualification blockers. |
| CMP-004 | Negotiated versions and recipe IDs | Enforce supported protocol ranges, recipe identifiers and default app/tenant addressing; unsupported combinations fail clearly. |
| CMP-005 | SDK differential corpus | Execute representative unmodified upstream SDKs where licensed/compatible and maintained forks otherwise; compare observable state, errors, cookies and hooks. |
| CMP-006 | No success stubs | A route returning the expected JSON shape without required state changes, audit and security behavior fails parity acceptance. |
| CMP-007 | Compatibility exceptions | Every deviation is versioned and visible; unapproved functional reductions block full parity, while nonfunctional vendor-license differences are never advertised as exact wire equivalence. |

## TST — Qualification, security and release evidence

Milestone: **M10**. Strategy: **test-and-audit**. Sources: DR, S24.

| ID | Required capability | Acceptance criterion |
|---|---|---|
| TST-001 | Requirement traceability | Every requirement links to implementation paths, positive/negative tests, a run artifact and reviewer sign-off before it can become verified. |
| TST-002 | Cross-tenant adversarial corpus | Test identity collision, session substitution, provider configuration theft, dashboard privilege escape and resource-data leakage across at least two apps and tenants. |
| TST-003 | Concurrency and crash corpus | Test refresh, OTP/reset/recovery consumption, linking, credential updates and key rotation across concurrent replicas and injected crashes. |
| TST-004 | Protocol security corpus | Validate OAuth/SAML/WebAuthn/CSRF/CORS protections and malformed or replayed inputs using maintained test tooling where suitable. |
| TST-005 | Migration evidence | Run realistic data fixtures, reconciliation and rollback; unexplained missing memberships/factors/sessions block migration acceptance. |
| TST-006 | Independent security review | Review custom security-critical code and deployed configuration independently from its author; remediate exploitable critical/high findings before production approval. |
| TST-007 | Accessibility and usability evidence | Verify keyboard/screen-reader/error/translation workflows and account-recovery usability across supported interfaces. |
| TST-008 | No-fee runtime qualification | Block authentication-vendor egress and prove local capability operation; separate genuine external provider transport prerequisites from auth licensing. |
| TST-009 | Final parity publication | Publish functional, protocol, SDK, security-quality and operations scorecards separately; skipped or unknown requirements are not counted as passed. |
