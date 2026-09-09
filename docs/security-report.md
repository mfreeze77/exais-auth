# Security checkpoint — not independent approval

The installed native Core profile checks library integrity and its actual load
path before service startup. Seven startup cases and real native password/reset/
concurrency regressions pass. Docker-privileged replacement, other JVM loader
paths, live tampering, rehash, full platform/provider/maintenance coverage and
independent review remain open. Read [the exact scope](installed-native-argon2.md).
This is source-native packaging; it does not change the authoritative engine or
entitlement checks. Current Core is `e8c460664ac5`; Node is `2a02e08d5fcb`.

Foundation remains unapproved. Tests use isolated private containers and synthetic
identities. No production, remote publication, spend, external account messages or
license-enforcement changes were performed.

Material unresolved findings:

- The explicit five-second CDI5.6 session candidate now passes direct Core
  transaction-abort/retry and stale-family revocation cases, plus installed
  Node transport faults and actual four-tab browser coordination. An old
  response delivered after logout fails server-side use. Arbitrary concurrent
  credential installation, all SDK/tenant/factor profiles, revocation crash
  boundaries, effective grace-configuration readiness and full independent
  review remain open. Historical zero-grace/legacy failures remain recorded.
  See `docs/session-refresh-grace.md` and its source-specific reuse report.
- The locked npm downloader now passes actual wrong-SRI response, concurrent
  writer, corrupt/link/oversize/unknown-cache and wrong-origin rejection cases,
  plus fresh registry and disconnected installation/compilation. Crash-safe
  stale-lock/partial-file recovery and actual HTTP timeout/redirect/oversized or
  truncated response faults remain unqualified. Deprecated/maintenance warnings
  for three pinned transitive packages remain unresolved. No all-dependencies-
  maintained, full distribution or independent-review claim follows. See
  `docs/node-package-bootstrap.md`.
- Updated Node image `e02ab9bcd78e` passes 34 installed atomic-profile behavior
  checks without app overlays. A real new-Core/old-plugin mismatch fails readiness
  and sign-in without issuing tokens/cookies or adding a session; healthy-writer
  retry succeeds. Original archive bytes and source bindings were checked before
  promotion, and the old image was removed. Core image `03b4458c532f` now installs
  the JAR pair and passes 16 Core and 34 Node cases without healthy-path overlays.
  Fourteen local upgrade/rollback cases preserve sessions, password access and
  the original identity/schema state. Foundation, rolling-upgrade failure paths
  and complete distribution remain unqualified. New
  deadline-expiry, daemon-outage and promotion/rollback faults are unexecuted.
  See `docs/atomic-node-installation.md` for exact evidence and failed-run history.
- Password reset succeeds through verified authenticated TLS SMTP and rejects
  replay/concurrent losing consumers. The default upstream profile still uses
  separate reset and revocation calls with a crash gap. The explicit atomic
  adaptation joins reset and revocation in one engine transaction and rechecks
  password/session creation under the same user lock. Actual race ordering and
  database-abort/retry tests pass for that profile; other SDKs and legacy writers
  remain unqualified. Equal
  known/unknown-email response bodies do not eliminate transport timing leakage.
  Configured cross-tenant/link cases and durable outbox/retries remain open.
  The real exit73 worker-cleanup proof removes its one owned account; fallback
  timeout/daemon outage are not qualified. See `docs/password-reset.md`.
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

The Python readiness correction was tested against a real stopped PostgreSQL
container. The old route and Core protocol advertisement incorrectly remained200;
the corrected route returned503 in3.011 seconds, with generic error text and
`Cache-Control: no-store`, while process liveness remained200. Storage access is
authenticated and uses exact CDI5.4 count rather than an approximate cached value.
Its4-second total budget and3-second HTTP timeout bound an individual check.
This does not establish readiness load capacity, traffic removal, all dependency
failure classes or database HA. The database was restored using its original
container and volume; a prior private dump was retained but not restore-tested.
No credentials, tokens or upstream exception details are included in the reports.
Current-image regression passes19 HTTP checks with its two synthetic users removed;
the outage probe removes its single synthetic user. See the exact image-02 and
run-03 reports under `evidence/operations/python-readiness`. The current probe's
normal19 checks are in image-06. A separate real dropped-connection test confirms
its `finally` cleanup removes the one created user while preserving52 existing
identities; the aborted child records seven unexecuted checks and exits1. The
four outer assertions qualify harness cleanup only.

Independent human security and licensing review, production TLS/proxy controls,
all migration/key/backup/load/HA cases, native and live-provider qualification,
complete threat-model coverage and final dependency redistribution remain open.
An AI assessment, advisory scan or passing evidence gate is not independent review.
