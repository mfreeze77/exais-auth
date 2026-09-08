# Configuration contract and conceptual data model

**Proposed design, not extracted production SQL.** Baseline semantics: [DR], [S04–S08]. ADR-001 selects the actual engine/schema mapping. Upstream-owned tables must be changed through the upstream implementation or a reviewed engine extension, not uncontrolled control-plane SQL.

## Required logical records

| Record | Minimum conceptual fields | Invariant / authority |
|---|---|---|
| Application | app ID, name, default tenant, storage partition, config version | App-scoped identity namespace; control plane provisions through authoritative engine interface. |
| Tenant | app ID, tenant ID, enabled methods, policies, provider references, state | Tenant belongs to one app; accepted routing never establishes caller authorization by itself. |
| Primary identity | app ID, primary ID, lifecycle, creation time | Stable user concept independent of a particular login method. |
| Method identity | app ID, method ID, method type, primary link, normalized identifiers | A method identity has unambiguous ownership; its tenant associations determine identifier scope. |
| Membership | app ID, tenant ID, primary/method association as required, status | Explicit sharing; no cross-app implicit membership. |
| Credential | authority ID, method owner, type, protected verifier/reference, parameters, status | One engine write authority; password verifier is not exposed through management APIs. |
| Factor | owner, type, enrollment state, protected secret/public credential, timestamps | Enrollment and removal require policy-approved evidence. |
| External mapping | app ID, external namespace/ID, internal identity | Mapping uniqueness and stable migration resolution. |
| Session | app ID, tenant ID, handle, subject/method IDs, expiry, auth level, claims/data, revocation | One authoritative session state machine; tenant cannot be swapped after login. |
| Refresh family/state | session reference, current/previous verifier, rotation metadata, state | Atomic compare/rotate/revoke; previous-token behavior is explicit and versioned. |
| One-time challenge | app/tenant, purpose, owner/flow, verifier, expiry, attempts, consumed state | A challenge cannot be repurposed or consumed twice. |
| Role definition | app ID, role ID, permission set | App-level role definition; tenant-level assignments. |
| Role assignment | app ID, tenant ID, user ID, role ID | Membership and authorization context required. |
| User metadata | app ID, primary ID, versioned JSON | App-scoped; protected/reserved keys excluded from untrusted mass assignment. |
| Federation configuration | app/tenant, provider ID/type, trusted issuer/domain, secret references, certificates | Ownership validated; untrusted metadata cannot select arbitrary internal URLs. |
| OAuth client/consent | client ID, allowed redirects/grants/scopes/resources, credential refs, consent | Client/resource-specific validation and secret lifecycle. |
| Signing/encryption keys | key ID, algorithm, purpose, status, validity, encrypted material/reference | Rotation overlap and recovery custody are explicit; never export raw secrets to frontend. |
| Risk evidence/decision | scoped subject/request, features/confidence, policy/data version, action, reason | Unknown data stays unknown; retention/privacy policies apply. |
| Audit/outbox | event ID, actor, subject, app/tenant, action, time, correlation/idempotency key | Redacted, access controlled, durable; outbox delivery cannot rewrite identity ownership. |
| Import job/staged row | source ID, schema version, checksum, status, errors, reconciliation | Idempotent batches and explicit blocked records. |

The same external identifier may be distinct across tenant namespaces. Do not introduce a global unique-email constraint. Explicit sharing across eligible tenants and the same database boundary must be represented rather than inferred from an email match. Separate database tenant partitions cannot silently share one identity record [S04].

Browser SSO between relying applications is a separate federation/consent relationship; it does not erase the baseline distinction between isolated Core applications.

## Configuration mapping checklist

Names below reflect the original research catalog where applicable [DR]. Their exact spelling/default/type is frozen per supported SDK/version in M0; engine-native configuration may differ and must be mapped explicitly.

| Reference family | Items to capture and map | Required qualification |
|---|---|---|
| Application info | appName, websiteDomain, apiDomain, websiteBasePath, apiBasePath, apiGatewayPath, backend origin | Test proxy prefixes, dynamic origins and explicit allowlists; preserve path-sensitive refresh behavior. |
| Engine connection | connectionURI, apiKey | Private authenticated route; secret rotation with deliberate overlap. |
| Recipe composition | recipeList, per-recipe settings | Disabled methods cannot remain reachable through stale UI or direct API calls. |
| Extension contracts | function overrides, API overrides, hooks, user context, network interceptor | Ordering, errors, async behavior and cross-request context isolation. |
| Storage | PostgreSQL URI or discrete host/port/database/user/password, schema and prefix | Production disallows accidental in-memory persistence; credentials are secret references. |
| Engine networking | API_KEYS, IP_ALLOW_REGEX, IP_DENY_REGEX, host/port | Fail closed on invalid policy; validate proxy/IP parsing rather than trust spoofable headers. |
| Pools | server pool, DB pool, minimum idle, idle timeout | Load tests and bounded backpressure; do not copy defaults without measured sizing. |
| Access/session | access lifetime, refresh/session lifetime, session data, JWT claims | Document offline/online verification and actual revocation window. |
| Signing | static/dynamic access key option, rotation interval | Key overlap and stale-cache cases; explicit algorithm/issuer/audience validation. |
| CSRF | NONE, VIA_CUSTOM_HEADER, VIA_TOKEN profiles where supported | Test deployment-specific CSRF risks; compatibility support does not make every mode safe in every deployment. |
| Cookies | cookieSameSite, cookieSecure, path/domain, transfer mode | Browser tests for same-site/cross-site/iframe; no claims to bypass browser restrictions. |
| Email | SMTP/custom provider, sender, templates, locale | Retries, abuse limits, link allowlists and protected delivery payloads. |
| SMS | Twilio/custom provider, sender, templates | Adapter semantics are free of mandatory auth entitlements; transport cost remains separate. |
| Tenant methods/policies | enabled login methods, discovery, MFA, provider clients, risk rules | Versioned policy rollout with positive/negative tenant tests. |
| Deployment | image/version/digest, TLS proxy, readiness/liveness, CLI | Exact pins and source provenance; readiness must verify actual dependency health. |
| Commercial control | vendor license key and feature entitlement | No required counterpart; declare non-equivalence rather than emulate a valid vendor license. |

## Required state machines

Specify legal transitions and atomic transaction boundaries for: sign-up/verification; OTP and magic links; password reset; factor enrollment/recovery/removal; WebAuthn challenge/credential lifecycle; link/unlink; session create/refresh/revoke; tenant suspension/deletion; OAuth authorization/consent/token exchange; SAML assertion consumption; and migration cutover/rollback.

Each transition must define authorization preconditions, state version/locking, side effects, retry/idempotency behavior, audit record, interruption recovery and expiry. Traces and events must not contain passwords, OTPs, raw recovery links, refresh tokens or sensitive provider credentials.
