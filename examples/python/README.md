# Python SDK representative integration

This FastAPI application uses **unmodified `supertokens-python` 0.31.3** with the real self-hosted Core. Password credentials, identities, signing, and refresh state are owned by that Core. The application stores no parallel identity or session state. The pinned SDK requires **CDI 5.4** and advertises FDI support through 4.2. This example uses the default application and public tenant.

The current image passed **19 live tests**, covering header/cookie signup, password sign-in, wrong-password and duplicate-signup rejection, malformed/absent tokens, online-verified protected access, refresh, logout, online revocation, cookie clearing, and the custom-header CSRF requirement. Current app/probe/image bindings are in `evidence/operations/python-readiness/image-06`; its original build is image-02. Reset generation and reset consumption endpoints are intentionally disabled until a local transport is integrated. The example's supplied delivery service raises an error if invoked; it never falls back to vendor-hosted email. Telemetry is disabled through the supported SDK option.

The public API listens on container port **8300**. `/protected` uses `verify_session(check_database=True)`, including real session existence checks; this differs from offline JWT-only verification. `/protected/action` also requires the SDK's CSRF policy. `/live` reports process liveness. `/ready` checks CDI5.4 support and an authenticated exact storage query through the private Core, with a four-second total budget and three-second HTTP timeout. It returns503 for dependency failures and uses `Cache-Control: no-store` on success and failure. Its response contains no count, credentials or upstream exception details.

## Build and run locally

Build from the repository root. The base Python image is pinned by digest and every installed wheel is pinned by version and SHA-256 for **Linux x86_64 / CPython 3.12**. Other architectures/platforms require a separately generated and qualified lock.

```powershell
docker build --pull=false --label org.expertauth.project=expert-auth --label org.expertauth.purpose=python-foundation -t expertauth-python-app:0.1.0 examples/python
```

The first build may need network access for pinned dependencies. Do not rebuild an unchanged image or retain obsolete component tags. `.dockerignore` admits only the Dockerfile, lock and app source. For an existing component image, the bounded refresh helper below uses cached dependency layers with build networking disabled; it rejects changed dependency/base layers. It is not a dependency-upgrade tool.

The local parent lab must already provide the internal `expertauth-oss-proof` network, running `core-a:3567` and PostgreSQL. Its ignored `.runtime/oss-core/runtime.env` must contain `EXPERTAUTH_CORE_API_KEY` matching the Core. Never put that key in the repository. Run the current-image HTTP regression and resource cleanup with a new evidence name:

```powershell
python tools/refresh_python_image.py --test-existing --name NEW_UNIQUE_IMAGE_NAME
```

With `--test-existing`, the helper inspects the retained image without building, checks installed app/lock hashes, starts a temporary application without a source overlay, executes all19 HTTP checks, and retires its own containers in `finally`. This is the appropriate mode after harness-only changes. It checks exact container IDs and both project/purpose labels before cleanup. The example runs as UID/GID65532, with a read-only root, bounded temporary memory and no published ports. Tests use a private HTTP origin; production TLS Secure-cookie behavior remains unqualified.

The build mode is currently blocked by a recorded legacy Docker cache-restoration error on this host. Image-04's unsuccessful offline install left one intermediate container, which was identified by exact ID, command, time and lock hash, then removed. Its original build output was discarded by the old wrapper and cannot be recovered from the daemon's logging driver. Image-05 preserves the exact subsequent cache-restoration error and has zero resource delta. Current build mode preserves failure output, specifies the retained image as a cache source and forces intermediate removal. Do not repeat the unchanged cache failure or rebuild dependencies merely to test a probe change. A fresh full build or another builder needs separate qualification.

The image helper checks source stability and container cleanup before retiring the prior image. A separate real trial with a distinct image configuration and identical filesystem layers passed19 HTTP checks, then correctly rejected an isolated source change, restored the prior tag and removed the trial image. Its21 lifecycle assertions qualify that rollback path only; they do not close the full source-build failure. See `evidence/operations/python-image-lifecycle`.

The probe generates synthetic `example.invalid` identities, retains no passwords/tokens in evidence, and revokes its sessions. The helper passes `--cleanup-created-users`, deleting only the two users it created through the authenticated Core API in `finally`; a failed cleanup fails the run. An actual dropped auxiliary signout connection proved that its one created user is removed even when a transport exception aborts the remaining checks. That child exits1 and records seven unexecuted checks; its four passing outer cleanup assertions are not authentication acceptance. See `evidence/operations/python-probe-cleanup-fault`. Older historical probes left synthetic users behind. The probe refuses to overwrite an existing report. A failed prerequisite yields an incomplete/failed report, never skipped success. `probe-report.json` lists every test and the exact app/lock/probe hashes. The Core is never mocked.

To reproduce readiness behavior, use the separate controlled outage lab:

```powershell
python tools/run_python_readiness.py --name NEW_UNIQUE_OUTAGE_NAME
python tools/verify_checkpoint_hygiene.py
```

This deliberately stops and restores the exact owned private PostgreSQL container, after a small private dump and isolation/identity checks. It refuses other network consumers. It compares the historical Git-pinned app against current source on the same dependency image; no obsolete image is retained. The six passing checks include one cleanup row. They demonstrate the old false200, current503 with liveness200, same-volume recovery and existing-session continuity. Reports under `evidence/operations/python-readiness/run-03` preserve exact timings and resource deltas. Traffic removal, readiness load, other dependency classes, database HA and dump restore remain unqualified. Do not repeat an unchanged passing proof just to refresh timestamps.

The proof network is Docker `Internal=true`. Actual outbound attempts to `supertokens.com:443` and an external IP failed while the local tests passed. This demonstrates vendor independence for **this password/session integration only**, not the remaining required MFA, administration, risk, or provider surfaces.

## Source and dependency provenance

The candidate comes from `reuse/profiles.json` SDKP-02 and audited commit `b498da1a6d09ca84ca204ac881df76900df19175`. The downloaded wheel's **418 Python source files match that immutable source manifest byte-for-byte**. No SDK fork, patch, or monkeypatch is used. The application uses documented recipe/API overrides to disable unavailable delivery routes. `dependency-audit.json` records all 49 installed dependencies, source-wheel hashes, installed notice hashes, and declared licenses. Exact-version OSV queries returned zero matches; this does not replace independent security review or establish an exhaustive vulnerability absence claim.

The recorded audit used public OSV over the normal build/research network. Its observation time is historical; the readiness change adds no dependency and preserves all dependency/base layers. Runtime authentication operates on the private network. `lock_dependencies.py` is an explicit update tool; do not regenerate the lock during normal builds. Dependencies added by upstream extras are not implicitly enabled: the example requests only its four direct packages. Upstream includes optional transport libraries transitively; no Twilio/mail service is configured or invoked.

## Preserved test correction and qualification limits

The first probe passed 18/19 checks. After refresh, a real SDK signout response first refreshed the access cookie and then expired it in the same response. Python's `http.cookiejar` batches same-name cookie processing and retained the refreshed cookie despite the following expiry. The probe now applies response `Set-Cookie` headers in their wire order with `OrderedCookieClient`. This changes only the test HTTP client's cookie handling; server/SDK code and the strict cookie-clearing assertion are unchanged. The original failed report remains `probe-report-first-failure.json`. A real browser qualification is still required; this HTTP probe is not browser evidence.

No claim is made for the complete Python feature matrix, additional frameworks, live providers, password reset delivery, production TLS, advanced authentication features, migrations, concurrency acceptance, or independent review. These remain separate obligations. The example is a working, tested representative integration and not full SDK or platform parity.
