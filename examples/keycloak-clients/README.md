# Keycloak candidate Node, React and Python clients

This executable proof uses a private Keycloak 26.7.3 engine and the separately audited JSON Authenticator SPI. The React UI and Python client call the Node application backend. Only that backend calls Keycloak. Password verification, TOTP replay protection, identity membership, OAuth authorization sessions, issued sessions and refresh-token revocation remain owned by Keycloak.

This is a **partial candidate integration**, not an ExpertAuth SDK release or a claim of full FDI/CDI compatibility. No original requirement is closed by installing or compiling this example. Read the actual `evidence/foundation/keycloak-clients/*-results.json` outcomes and source hashes. Earlier timestamped failing runs are retained.

## Contract and boundaries

`GET /candidate/csrf` issues a stateless CSRF token bound to an opaque browser correlation cookie. `POST /candidate/start` accepts only `{ "tenant": "alpha" }`. It returns an opaque transaction ID and action token, with the `password` challenge. `POST /candidate/step` accepts that pair and the current step's credential fields; password success returns `totp`, and TOTP success returns a sanitized identity. Engine action URLs, OAuth state, nonce, verifier, cookies and callback URLs stay in the backend-held, 180-second transaction. The backend allows only the configured engine's exact authentication action path and intercepts its final registered callback privately.

The backend consumes each application action token before the upstream call. Concurrent and replayed actions fail closed. A backend restart expires the transient preauthentication transaction and requires starting again. There is no application database of users, authenticated sessions, refresh families, OTPs or revocation state.

Keycloak-issued access and refresh tokens are transported as separate HttpOnly, SameSite=Strict cookies. The UI never puts them in JavaScript storage. Successful authentication and logout rotate browser correlation and CSRF values. Cookie writes and refresh/logout require an exact application Origin, JSON content type and CSRF token. No cross-origin browser API is enabled. The Node API validates RS256, issuer, audience, expiry, subject, authorized client and the signed organization string-array containing `alpha`. It requires the configured built-in mapper's array-of-strings shape. All other requested tenant contexts are rejected. Keycloak must attach the supported built-in `basic` default client scope so access tokens contain `sub`; missing subjects are rejected.

`GET /candidate/resource?tenant=alpha` verifies access JWTs offline. `POST /candidate/refresh` submits the held engine refresh cookie to Keycloak; `POST /candidate/logout` revokes it with RFC 7009 and clears browser tokens. **Previously copied access JWTs may remain valid until expiry.** This example does not claim immediate global offline logout, durable preauth recovery, refresh response-loss recovery, replica coordination, broad hooks, SDK family coverage or production qualification.

The demonstration uses a public OAuth client with S256 PKCE and no password grant. The private backend enforces the browser boundary; public-client registration does not mean a client secret is embedded in React. For production, TLS, network deployment, confidential-client authentication policy, limits, monitoring, recovery and independent security review still require qualification.

## Reproduce

Commands below run from the repository root in PowerShell. First build the sibling `engine-extensions/keycloak-headless` image and prepare its private fixtures exactly as its README describes. This client proof copies that private realm into its own disposable engine/database and attaches the candidate client's built-in `basic` default scope. It retains the `organization` optional scope, resource audience and real alpha memberships. The sibling server remains untouched. Its private `.runtime/fixtures.json` contains synthetic test secrets; never publish or package it.

```powershell
python examples/keycloak-clients/prepare-client-lab.py
docker network create --internal expertauth-kc-clients-proof
docker run -d --name expertauth-kc-clients-engine --network expertauth-kc-clients-proof --network-alias kc-headless.example.test --mount "type=bind,source=${PWD}/examples/keycloak-clients/.runtime/realm-import.json,target=/opt/keycloak/data/import/realm-import.json,readonly" expertauth-kc-headless:0.1.0
docker build -t expertauth-kc-clients-node:0.0.1 examples/keycloak-clients
docker run -d --name expertauth-kc-clients-node --network expertauth-kc-clients-proof --network-alias expertauth-kc-clients-node -e EXPERTAUTH_LOCAL_PROOF=true expertauth-kc-clients-node:0.0.1
docker run --rm -v "${PWD}/examples/keycloak-clients:/work" -w /work node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 npm ci --ignore-scripts --no-audit --no-fund
docker run --rm -v "${PWD}/examples/keycloak-clients:/work" -w /work python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python -m pip download --require-hashes -r requirements-test.txt --no-deps -d .runtime/wheels
docker run --rm -v "${PWD}/examples/keycloak-clients:/work" -w /work python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python -m pip install --no-index --find-links .runtime/wheels --require-hashes -r requirements-test.txt --target .runtime/testdeps
docker run --rm --network expertauth-kc-clients-proof -v "${PWD}:/workspace" -w /workspace -e PYTHONPATH=/workspace/examples/keycloak-clients/.runtime/testdeps python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tests/foundation/keycloak_clients.py
docker run --rm --network expertauth-kc-clients-proof -v "${PWD}:/workspace" -w /workspace/examples/keycloak-clients mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e node browser-probe.mjs
```

After setup, `python examples/keycloak-clients/run-proof.py` rebuilds and replaces only `expertauth-kc-clients-node`, then captures exact commands, logs, running image IDs, source hashes and real test outcomes in `commands.json`. The qualified engine image ID is recorded there; a newly rebuilt engine must be requalified. Existing private imports are reused, never silently overwritten. The current fixture engine uses disposable H2/dev mode; this candidate proof does not qualify PostgreSQL deployment or engine replica behavior.

The local proof containers publish no host ports. TLS bypass requires the explicit local-only environment flag; normal startup requires HTTPS and a supplied CSRF secret. Do not run the fixtures against production. Do not repeat successful OTP use in the same 30-second window; Keycloak rejects reused codes. Intentional wrong-password/OTP checks may temporarily lock synthetic users under the real engine policy; resolve that cause or wait for the configured cooldown instead of weakening it.

Reproduce dependency notices, file inventory, CycloneDX SBOM and current NPM advisory scan:

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace/examples/keycloak-clients node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 node audit-dependencies.mjs
python examples/keycloak-clients/audit-python.py
```

Dependencies are used unmodified; NPM tarball integrity and every installed package file hash are recorded in `npm-reuse-files.json`. Matching upstream grants are retained in `THIRD_PARTY_NOTICES.txt`; test-only PyOTP has its own wheel/file report and MIT notice. An NPM advisory scan is neither a review of this integration nor proof that the container has no vulnerabilities. Repository-owned code has not been assigned a distribution license by this example; package metadata is private/UNLICENSED pending the repository owner's licensing decision.

Relevant primary references: [openid-client](https://github.com/panva/openid-client), [jose](https://github.com/panva/jose), [Keycloak client scopes](https://www.keycloak.org/docs/latest/server_admin/#_client_scopes), [pinned Keycloak organization claim mapper](https://github.com/keycloak/keycloak/blob/6d238b6558037085cc25c915893c3d301a80243e/services/src/main/java/org/keycloak/organization/protocol/mappers/oidc/OrganizationMembershipMapper.java), [PyOTP](https://pyauth.github.io/pyotp/). Exact installed versions and source hashes, not moving documentation URLs, define this proof's dependency boundary.
