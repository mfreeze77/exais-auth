# ADR-001: Foundation decision gate (pending)

Date: 2026-09-08. Status: **evaluation in progress; selected_engine=null**.

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
current image pins are in `docs/session-refresh-grace.md`.
