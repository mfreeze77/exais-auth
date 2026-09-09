# Evidence-preserving test corrections

## Node session residual window, 2026-09-08

`evidence/runs/node-live-01` retained a 9/10 result. The residual-window assertion reused
the access token returned immediately by refresh and ignored the new access token
returned by the following protected request. SuperTokens Node 24.0.3
`lib/build/recipe/session/sessionFunctions.js` only takes the offline path when
`parentRefreshTokenHash1` is absent. A token awaiting that handshake still calls Core.
The first correction consumed returned headers but still failed: CDI 5.6 retains the
parent marker and does not return a settled token from verification. Evidence is
`evidence/runs/node-live-02`. Thus the unmodified SDK's default verifier cannot be
advertised as wholly offline for this token lifecycle. The example now labels that
route `sdk-hybrid` and implements a separate, explicit offline profile with maintained
`jose` signature, issuer, audience, algorithm, expiration and tenant checks. Issuer and
audience are set by a server-controlled SDK override; Core remains the sole signer.
The original security assertions remain: online access and refresh denied after
logout, offline token still accepted before expiration. Independent review is pending.

## Keycloak session and membership characterization

The initial probe treated equal realm `sid` values as a tenant-session failure and
tested bare clients without organization scopes. Review found these were insufficient
to reject a supported organization/client mapping. Prior output is retained under
`evidence/foundation/keycloak/attempts`. Current bare-client cases are observations;
real organization membership and scope tests are separate. No engine has passed M1.
# Browser and release evidence corrections

The initial Node UI build used a removed `EmailPasswordPreBuiltUI.SignInAndUp`
component, producing a blank page. The app now uses the exported SDK routing
component. Real browser checks then caught a viewport-width card overflowing its
padded320px parent; a supported style override confines the card to its parent.
Both implementation failures and the final4 passing browser checks are retained.
Test-only fixes selected the actual Sign Up link and waited for the new form before
typing, preventing input into a form being replaced. No failed behavior assertion
was removed. Screenshots were visually inspected.

Source evidence now excludes ignored local runtime secrets, `.env` files and
generated archive output; `.env.example` remains part of source verification.
An adversarial evidence test checks those boundaries. `.gitattributes` disables
newline conversion so immutable baseline and evidence hashes survive Git checkout.

## Windows report-write correction

The hygiene review found a separate Python text-write issue: `run_evidence.py`
hashed LF output before Windows stored CRLF bytes, and the extracted-ZIP wrapper
did the same for its report pointer. Git preservation did not cause this issue.
Future output logs/reports are now written as exact UTF-8 bytes. The extracted
report file is unchanged and its `latest.json` pointer now uses the actual file
digest, as recorded in `evidence/extracted-checkpoint/README.md`.

`evidence/integrity/command-log-newline-audit-20260908T225555Z.json` records33
historical CRLF digest mismatches,2 new exact-digest records and0 unexplained
mismatches. It hashes the untouched original records and output files. Those
historical mismatched records are not eligible as exact-digest release evidence;
the forensic correction index does not rerun or certify their tests. Candidate
execution observations remain limited to their recorded cases. All baseline
acceptance rows remain unverified. Subsequent evidence must use the corrected
writer and actual file hashes.

## Notice packaging and maintenance preflight

The first notice-tree test counted88 filename candidates, including Bouncy Castle's
compiled `org/bouncycastle/LICENSE.class`. That2,001-byte executable class is not
notice text. The assembler already correctly excluded it; the test now requires87
actual archive notice texts and separately verifies5 supplemental notices. Original
failure evidence remains in `evidence/runs/runtime-notice-package-tests-01`.

The first local notice-image replacement stopped before any mutation because the
Gradle base had added an inherited anonymous volume. The preflight now accepts only
the exact owned read-only configuration mount plus that specific Gradle destination;
unrelated mounts still fail. New Core containers use bounded tmpfs for the unused
cache. Two nonempty old volumes were retained and measured at385,398 bytes combined.
The successful run verified identical87 JARs and storage readiness before/after;
it did not test rollback failure behavior, migrations or complete authentication.

## Session browser probe resource diagnosis

The first new multi-tab probe timed out before signup; unlike the existing browser
test it filled fields immediately after selecting the signup tab. Waiting for the
actual SIGN UP form fixed that harness ordering. Run01 and its exact input
snapshots remain failed historical evidence.

Runs02–04 reached real expiry but failed browser fetch. The bounded diagnostic
recorded all32 outcomes:12 successes and20 `net::ERR_INSUFFICIENT_RESOURCES`,
after a successful refresh. The browser's128MiB memory-backed `/tmp` was too small
for this burst:run05 used the same images and32-request workload with a bounded
512MiB tmpfs and passed, measuring175,648,768 bytes in use after concurrency.
No browser security feature was disabled, authentication assertion relaxed, or
request count reduced. Run05 includes all three browser checks passing and22
synthetic-user removals. Temporary resources were removed with zero Docker delta.

The raw-header concurrency failure is a separate observed client-policy issue
and remains failed. The runner returns1 for it. New test results do not rewrite
the original CDI5.3 capture, CDI5.6 zero-grace or Keycloak strict-profile failures.
The policy review explains why one engine/profile's expectations cannot be
silently applied to another; it does not waive any baseline acceptance.
