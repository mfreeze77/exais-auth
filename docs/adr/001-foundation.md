# ADR-001: Foundation decision

Date: 2026-09-08; decided 2026-09-30. Status: **decided by the product owner:
selected_engine = ExpertAuth Engine (independently authored).**

## 2026-09-30 decision (product owner)

ExpertAuth is its own authentication engine. SuperTokens is the **functional and API
reference only**: the benchmark for behavior, the FDI/CDI wire contracts and SDK
compatibility. **No SuperTokens source code is included in the product**, whether
Core, the plugin interface, the PostgreSQL plugin or `ee/`. This supersedes the
baseline's fallback of "Apache portions of SuperTokens Core as the foundation" and the
Keycloak starting recommendation. Neither was the owner's intent. Consequences:

- The engine lives in `engine/` (TypeScript on Node.js with PostgreSQL), written
  independently from the published API contracts (`contracts/`) and the baseline data
  model. It owns credentials, identity linkage, tenancy, sessions/refresh state and
  signing as one write authority.
- Multi-tenancy, account linking, MFA and every other capability the reference sells
  as an add-on are ordinary ExpertAuth features. There is no license gate to patch
  because no vendor code is used. The product never emulates, forges or calls a vendor
  license service.
- Earlier SuperTokens-Core and Keycloak labs (`engine-extensions/`, `evidence/`) become
  reference-behavior evidence and differential-test oracles. They are not product
  code and never ship. Their findings (refresh races, reset atomicity, hash bounds,
  rehash) are carried forward as requirements and tests for the ExpertAuth engine.
- All 265 requirements, 205 API IDs and every profile/review gate remain binding.
- **Retention (owner instruction, 2026-09-30):** keep the reference labs and their SuperTokens-
  derived material (`engine-extensions/`, the reference-lab `tools/`/`tests/`, `evidence/`)
  until the engine no longer needs them as a reference. Retire them only by an explicit
  owner decision, never as incidental cleanup. Reference material never ships in the product.

## History (evaluation before the decision)

The sole production identity/session engine will be selected only after the binding
foundation cases pass. Candidate labs share no application state and are not a
dual-engine product architecture.

Keycloak community26.7.3, source `6d238b6558037085cc25c915893c3d301a80243e`,
image `quay.io/keycloak/keycloak@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54`:
real PKCE login and isolated realm identities work. The initial client-per-tenant
experiment was insufficient: equal SSO `sid` does not disprove distinct client
sessions, and setting organizationsEnabled alone does not install a hard membership
gate. Explicit organization membership/scopes, `requiresUserMembership` and client
refresh revocation pass12 supported organization cases. JSON password/TOTP Authenticator
SPIs pass16 narrow cases, retaining the engine's credential/factor state. Real owned
OIDC broker tests pass17 cases and fail2 concurrency cases: duplicate provider ownership
and removal of all login methods. The corrective implementation turn was rejected by
automatic review; no identity-provider override or schema change exists. Those failures
block engine selection. The PostgreSQL two-replica session proof passes7 and fails3
checks under `revokeRefreshToken=true,refreshTokenMaxReuse=0`: stale parent denial
invalidates a legitimate child, concurrent winner refresh is unusable, and lost
committed response retry fails. This rejects the tested strict configuration; it
does not prove every possible policy fails or approve weaker replay protection.
Client proofs cannot waive the failed identity/session checks.

Audited-source alternative: SuperTokens Core12.2.0 at
`b2219c4aa019a501e4dfea76cf06ef802ca93fc0`, plugin interface10.0.0 at
`2550750188069110753decd06265a59fadefb427`, PostgreSQL plugin9.8.0 at
`0b68fd14ca10baee2d0e3c31466984fccfb36c8a` compile and run without `ee.jar`.
Basic real authentication, session and two-replica cases work; unactivated required
app/tenant/link operations return402. No license checks were patched. CDI5.3's
two-phase refresh branch and CDI5.6's strict rotation differ materially; zero grace
at5.6 revokes legitimate concurrent refresh. These are gate failures/limits requiring
resolution, not permission to omit tenancy/linking/concurrency requirements.

Current evidence paths: `evidence/foundation/keycloak`, `keycloak-organizations`,
`keycloak-headless`, `keycloak-identity`, and `oss-core` as those runs are completed.
Missing paths or an unfinished agent report are not passing evidence.

Ownership constraint remains binding: the selected engine owns credentials, factor
state, identity linkage, signing and refresh transitions. Adapters may validate and
translate contracts; they must not keep a duplicate refresh store or write into
upstream tables. Offline access verification is a separate profile from online
session revocation. No product authority is committed by these experiments.

2026-09-09 evidence addition: the separate `OSS-CDI56-GRACE5-V1` candidate passes
12 direct Core cases and an explicitly adapted installed Node/React flow. The
five-second window recovers lost responses and converges concurrent responses
on one successor; stale replay revokes the intended family. The real browser
coordinates32 protected requests across four tabs. This does not approve the
upstream Node5.4/Python/native profiles, every client ordering, effective-policy
readiness or the missing tenant/link/factor mapping. Original strict-profile
failures stay preserved, and `selected_engine` remains null. Exact evidence and
historical image pins are in `docs/session-refresh-grace.md`.

Later 2026-09-09 addition: the current Core/Node candidate exposes and verifies
effective grace/reuse settings. Real zero-grace, alternate-reuse and transport
failure cases are refused; concurrent refusals and same-session recovery pass.
Installed reset/grace/browser regressions and actual Core upgrade/rollback pass.
The per-request preflight does not prove atomic policy consistency across
heterogeneous replicas or a configuration change before the operation. All other
foundation, configured namespace/link/factor, SDK/native/provider, licensing and
independent-review gates remain binding. `selected_engine` stays null. Current
pins, source and exact evidence are in `docs/session-policy-readiness.md`.

Subsequent 2026-09-09 addition: guarded private Core refresh/verify routes now
carry an explicit policy argument into the existing Core operations. Real
healthy-preflight/mismatched-operation cases fail closed, including concurrency;
an actual pre-guard replica returns 404 for the new routes. The original API
classes and behavior remain unchanged. Installed Node routes these operations
without fallback; reset, grace, browser and local upgrade/rollback regressions
pass. This does not close the required namespace/linking, runtime distribution,
other auth/configuration ordering, SDK/native/provider or independent-review
gates. Engine selection remains pending. Current evidence and pins are in
`docs/guarded-session-operations.md`.
