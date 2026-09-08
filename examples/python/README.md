# Python SDK representative integration

This FastAPI application uses **unmodified `supertokens-python` 0.31.3** with the real self-hosted Core. Password credentials, identities, signing, and refresh state are owned by that Core. The application stores no parallel identity or session state. The pinned SDK requires **CDI 5.4** and advertises FDI support through 4.2. This example uses the default application and public tenant.

The running proof passed **19 live tests**, covering header/cookie signup, password sign-in, wrong-password and duplicate-signup rejection, malformed/absent tokens, online-verified protected access, refresh, logout, online revocation, cookie clearing, and the custom-header CSRF requirement. Reset generation and reset consumption endpoints are intentionally disabled until a local transport is integrated. The example's supplied delivery service raises an error if invoked; it never falls back to vendor-hosted email. Telemetry is disabled through the supported SDK option.

The public API listens on container port **8300**. `/protected` uses `verify_session(check_database=True)`, including real session existence checks; this differs from offline JWT-only verification. `/protected/action` also requires the SDK's CSRF policy. `/live` reports process liveness. `/ready` checks the private Core and required CDI version. It returns 503 when that prerequisite is absent.

## Build and run locally

Build from the repository root. The base Python image is pinned by digest and every installed wheel is pinned by version and SHA-256 for **Linux x86_64 / CPython 3.12**. Other architectures/platforms require a separately generated and qualified lock.

```powershell
docker build -t expertauth-python-app:0.1.0 examples/python
docker run -d --name expertauth-python-app --network expertauth-oss-proof --network-alias python-app --env-file .runtime/oss-core/runtime.env --env PYTHON_API_DOMAIN=http://localhost:8300 --env WEBSITE_DOMAIN=http://localhost:8300 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m expertauth-python-app:0.1.0
```

The environment file must contain `EXPERTAUTH_CORE_API_KEY` (or `SUPERTOKENS_API_KEY`) matching the Core. Do not put a real key in `.env.example` or the repository. The parent deployment creates the private `expertauth-oss-proof` network and `core-a:3567`; no public Core port is required. The example container runs as UID/GID 65532 with a read-only root filesystem and no published host ports. The tested API/website origin is `http://localhost:8300`; TLS Secure-cookie behavior is a separate unqualified profile.

Run the real HTTP probe from the built image, granting write access only to its evidence directory:

```powershell
$pythonProofRoot = (Get-Location).Path
docker run --rm --network expertauth-oss-proof --mount "type=bind,source=$pythonProofRoot,target=/work,readonly" --mount "type=bind,source=$pythonProofRoot\evidence\clients\python,target=/work/evidence/clients/python" -w /work expertauth-python-app:0.1.0 python tests/clients/python_probe.py --url http://python-app:8300
```

The probe generates synthetic `example.invalid` identities, retains no passwords/tokens in evidence, and revokes its sessions. Synthetic users remain in the isolated proof database. A failed prerequisite yields an incomplete/failed report, never skipped success. The Core is never mocked. `probe-report.json` lists every test result and exact app/lock/probe hashes.

The proof network is Docker `Internal=true`. Actual outbound attempts to `supertokens.com:443` and an external IP failed while the local tests passed. This demonstrates vendor independence for **this password/session integration only**, not the remaining required MFA, administration, risk, or provider surfaces.

## Source and dependency provenance

The candidate comes from `reuse/profiles.json` SDKP-02 and audited commit `b498da1a6d09ca84ca204ac881df76900df19175`. The downloaded wheel's **418 Python source files match that immutable source manifest byte-for-byte**. No SDK fork, patch, or monkeypatch is used. The application uses documented recipe/API overrides to disable unavailable delivery routes. `dependency-audit.json` records all 49 installed dependencies, source-wheel hashes, installed notice hashes, and declared licenses. Exact-version OSV queries returned zero matches; this does not replace independent security review or establish an exhaustive vulnerability absence claim.

```powershell
docker run --rm --mount "type=bind,source=$pythonProofRoot,target=/work,readonly" --mount "type=bind,source=$pythonProofRoot\evidence\clients\python,target=/work/evidence/clients/python" -w /work expertauth-python-app:0.1.0 python examples/python/audit_dependencies.py
```

The audit uses public OSV over the normal build/research network. Runtime authentication operates on the private network. `lock_dependencies.py` is an explicit update tool; do not regenerate the lock during normal builds. Dependencies added by upstream extras are not implicitly enabled: the example requests only its four direct packages. Upstream includes optional transport libraries transitively; no Twilio/mail service is configured or invoked.

## Preserved test correction and qualification limits

The first probe passed 18/19 checks. After refresh, a real SDK signout response first refreshed the access cookie and then expired it in the same response. Python's `http.cookiejar` batches same-name cookie processing and retained the refreshed cookie despite the following expiry. The probe now applies response `Set-Cookie` headers in their wire order with `OrderedCookieClient`. This changes only the test HTTP client's cookie handling; server/SDK code and the strict cookie-clearing assertion are unchanged. The original failed report remains `probe-report-first-failure.json`. A real browser qualification is still required; this HTTP probe is not browser evidence.

No claim is made for the complete Python feature matrix, additional frameworks, live providers, password reset delivery, production TLS, advanced authentication features, migrations, concurrency acceptance, or independent review. These remain separate obligations. The example is a working, tested representative integration and not full SDK or platform parity.
