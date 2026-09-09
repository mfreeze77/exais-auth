# Maintained SDK session characterization

This is a **PARTIAL foundation proof**, not final engine selection or a completed
baseline requirement. The versioned candidate policy is
`contracts/session-policy-oss-node-cdi54-v1.json`; the immutable capture remains
CDI5.3, and all original requirements/API/profile IDs remain required.

The current full run is **`run-05`**:10 SDK checks and3 browser checks passed;
the uncoordinated raw-header availability case failed. Two passing rows are
cleanup checks, not authentication behavior. The32 four-tab requests all
returned200 after one refresh; all four tabs returned401 after logout. Every
created synthetic user was removed (21 SDK and1 browser). Current source inputs
and physical log/artifact hashes are recorded; the suite correctly exits1.

The test runs the unchanged `examples/node-react/server.js` from the retained
Node24.0.3 application image. A transport proxy sends its actual SDK requests to
two source-built Core replicas sharing PostgreSQL. It records negotiated CDI5.4,
paths, replica identity and status only. It does not issue authentication
responses, forge tokens, alter Core enforcement or own refresh/session state.
Runtime image IDs, source/application hashes and configuration digest accompany
every run. The existing Core-a and database retain their IDs and start times.

The complete SDK path exercises candidate mint/promotion, three transport-loss
points, stale-token detection and default SDK family revocation, unrelated-session
survival, twelve concurrent logout/refresh rounds, and committed promotion across
SIGKILL/restart of only the temporary Core B. The before-forward fault happens
before Core receives the request; it is not a database-transaction failure. The
other proxy faults occur after receiving a complete real Core response, including
one case delivering only eight bytes downstream. They are not internal commit hooks.

**The uncoordinated raw-header availability case remains failed.** Both initial
refreshes can mint candidates in one legacy family. After one is promoted,
presenting the sibling invokes the maintained SDK theft handler, revoking that
family and invalidating the selected child. Passing the theft-enforcement check
does not make this availability failure pass. The full runner therefore returns
exit1. SDK crash/failure between Core theft response and revocation is untested.

The browser case uses the actual React/Session fetch interceptor, four tabs in
one Chromium context, an actual access-token expiry, and32 concurrent requests.
It keeps errors, unsuccessful requests and resource failures in evidence. No
native/Safari/multi-device/application-HA or complete SDK profile is inferred.

## Historical runs and source preservation

- `run-01`:10 SDK checks passed, including21 synthetic-user removals; the raw-header
  availability case failed. The browser stalled before signup, so neither browser
  behavior nor browser cleanup was passed. The original input snapshots remain
  under `inputs/` and match the run's recorded SHA values.
- `run-02`:10 SDK checks passed and the availability case failed. Waiting for the
  actual signup form fixed the first harness sequence, but concurrent browser
  fetch failed after real expiry. Its own created user was removed. Exact inputs
  are retained; no old report was rewritten.
- `run-03-browser`:browser-only diagnostic exposed a native `Failed to fetch`
  error. The worker's single passing row is zero-user cleanup, not an auth test.
- `run-04-browser-network`:browser-only diagnostic collected all32 outcomes:
  12 HTTP200 and20 Chromium `net::ERR_INSUFFICIENT_RESOURCES`, after one successful
  refresh. All32 initial expired-access requests returned401. Exact inputs and
  network failure records are retained. The original128MiB browser `/tmp` was
  memory-backed, not persistent disk.
- `run-05`:with the same application/Core/browser images and bounded512MiB
  browser tmpfs, all32 concurrent requests passed. Measured `/tmp` use after the
  burst was175,648,768 bytes (about167.5MiB), exceeding the old128MiB limit. This
  supports temporary-memory exhaustion as the cause of the earlier Chromium
  resource errors. No browser security limit was disabled and concurrency was
  not reduced. Cross-tab logout passed; the SDK raw-header failure remains.

The current runner records temporary-memory capacity/usage and uses a bounded
512MiB browser `/tmp`,128MiB SDK `/tmp`,256MiB browser shared memory and16MiB
temporary Core Gradle cache. Resource usage is measured separately from auth
acceptance. Check the newest run's actual results before calling this qualified.

## Reproduce

Prerequisites are the existing private Core-a/PostgreSQL lab, reconstructed pinned
Core sources, retained Node application image and pinned Playwright image, and
`tests/browser/node_modules` installed from its exact package lock. This runner
refuses missing cached images: it never builds or downloads an image. See the
repository README for the source build and representative example READMEs for
their dependency builds. A fresh archive excludes `node_modules` and private data.

```powershell
python tools/run_sdk_session_faults.py --name NEW_UNIQUE_RUN
python tools/run_sdk_session_faults.py --name NEW_BROWSER_RUN --browser-only
python tools/verify_checkpoint_hygiene.py
```

Use a new evidence name; reports are never overwritten. `--browser-only` omits
SDK fault/crash execution and must not be counted as those tests. The full run's
known availability failure is retained and produces nonzero status. Browser
failure independently produces nonzero status too. Neither mode can mark the
foundation passed.

Only three temporary containers are used, with unique names and ownership labels.
One-off processes use `--rm`; exact Docker-created IDs and both labels gate service
cleanup. CID/credential files live in a private temporary directory until cleanup
has captured ownership. No new image, network or persistent volume is created.
All created synthetic users are tracked and removed through Core. Reports retain
resource deltas and preserved-service checks; no global prune is used.

## File-specific reuse

| File | Reuse and boundary |
| --- | --- |
| `tools/run_sdk_session_faults.py` | Original orchestration; Python standard library and installed Docker CLI. Existing exact images only; no added dependency. |
| `tests/foundation/sdk_session_faults.mjs` | Original transport/failure tests using Node built-ins. Runs existing Apache-licensed SuperTokens Node24.0.3 middleware unchanged. SDK version/querier/session-handler file hashes are captured from the running image. |
| `tests/browser/session-coordination.mjs` | Original browser tests using pinned Playwright1.62.1 and the existing React/Session application. Existing package locks and license audits remain authoritative. No new UI/auth library or copied vendor source. |
| `contracts/session-policy-oss-node-cdi54-v1.json` | Independently authored candidate policy derived from the pinned Apache Core/SDK implementation and actual observations. It adds no waiver or identity authority. |

All previous licensing, native/provider, independent-review, identity/link and
full-distribution blockers remain. An agent's evidence review is not the required
independent human security review.
