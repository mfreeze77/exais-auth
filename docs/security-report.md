# Security checkpoint — not independent approval

Foundation remains unapproved. Tests use isolated private containers and synthetic
identities. No production, remote publication, spend, external account messages or
license-enforcement changes were performed.

Material unresolved findings:

- Keycloak26.7.3 broker linking can persist one provider subject on two primary
  accounts under concurrent supported flows. Parallel self-service unlink can
  remove all login methods. Fresh realms and an independent persistence read
  confirmed the failures. The corrective agent turn was automatically rejected;
  no identity override was implemented. See the identity handoff and exact source.
- Unmodified OSS Core requires entitlements for native required app/tenant/link
  operations. No-fee full parity is unproved. CDI5.6 zero-grace concurrent refresh
  invalidates the legitimate session; that behavior is not accepted as complete.
- The actual Node24.0.3 SDK negotiates CDI5.4 and revokes through Core after
  legacy `TOKEN_THEFT_DETECTED`. A raw client racing and subsequently using both
  candidate branches loses the selected session. This remains a failed
  availability observation. The Core's legacy theft response alone does not
  revoke; SDK crash/failure between classification and revocation is untested.
  A committed promotion survived a SIGKILL/restart of the temporary second Core,
  and three request/response transport faults recovered through the real SDK.
  These are bounded tests, not transaction-internal failure or database HA proof.
- Original Node graph included Nodemailer advisory GHSA-p6gq-j5cr-w38f. Scoped
 9.1.1 override passed9 isolated transport/security checks using unchanged SDK
  delivery recipes. The original affected graph and current graph audits are
  retained separately; this is not a claim that all dependencies are risk-free.

Positive evidence includes private authenticated Core access, actual password and
session behavior, bounded payloads, origin checks, CSRF, issuer/audience rejection,
online logout revocation, organization membership revocation, PKCE, TOTP and state
tamper checks. Their reports state narrower scope than baseline acceptance rows.
Offline JWT verification intentionally retains its bounded post-logout validity.

The Python cookie-client correction was reviewed against the diagnostic's actual
ordered response headers: the engine expires cookies and denies revoked sessions;
Python CookieJar's batched same-name processing caused the original failed HTTP
assertion. Applying headers in wire order is a test-client correction. Actual
Python browser behavior remains unqualified; Node's browser evidence does not
substitute for it.

Independent human security and licensing review, production TLS/proxy controls,
all migration/key/backup/load/HA cases, native and live-provider qualification,
complete threat-model coverage and final dependency redistribution remain open.
An AI assessment, advisory scan or passing evidence gate is not independent review.
