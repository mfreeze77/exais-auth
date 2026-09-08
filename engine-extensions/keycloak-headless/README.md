# Keycloak JSON password and TOTP challenge proof

This is a working **candidate** Authenticator extension for Keycloak **26.7.3**, source commit `6d238b6558037085cc25c915893c3d301a80243e`. It returns first-party JSON password and intermediate TOTP challenges directly from Keycloak's authentication flow. It does not scrape HTML or implement the password grant. Successful authentication completes the normal authorization-code flow with S256 PKCE.

`JsonPasswordAuthenticator` subclasses the upstream `UsernamePasswordForm`; `JsonOtpAuthenticator` subclasses `OTPFormAuthenticator`. Their action, credential-validation, brute-force, and OTP behavior is inherited unchanged. Only challenge rendering is overridden. `JsonChallenge` obtains the action URI and access code from `AuthenticationFlowContext`; Keycloak owns authentication sessions, credentials, password hashing, OTP replay state, final sessions, and signing. No parallel credential/session database is present.

The required flow is password → pre-enrolled TOTP. The synthetic realm uses `otpPolicyCodeReusable=false`, which activates the engine's `SingleUseObjectProvider` replay protection. Conditional passkeys, factor enrollment, other required actions, providers, and every other baseline capability remain separate requirements.

## JSON contract

Begin at the normal realm OIDC authorization endpoint with a registered redirect URI, `response_type=code`, `scope=openid`, state, nonce, and S256 PKCE challenge. Keep the engine authentication cookies in the same transaction's private cookie jar.

```json
{
  "status": "CHALLENGE",
  "step": "password",
  "authenticated": false,
  "action": "<engine-generated action URL with session_code/execution/tab_id/client_id>",
  "method": "POST",
  "contentType": "application/x-www-form-urlencoded",
  "fields": ["username", "password"]
}
```

Submit form-encoded values only to the held, engine-generated action. A valid password returns the same JSON structure with `step=totp` and `fields=["otp"]`. Invalid credentials return JSON HTTP 401 with generic `error=AUTHENTICATION_FAILED`. Challenges are `no-store` and never claim an authenticated final session. A valid final OTP produces Keycloak's 302 redirect to the registered callback, containing the authorization code and original OAuth state; the client exchanges it using its private PKCE verifier.

A backend integrating this profile must hold the action URI/cookies/state/verifier, enforce the expected engine origin/realm path, and never trust an arbitrary action URI submitted by a browser. Action errors outside the authenticator retain engine behavior: a missing session code re-renders the password challenge without processing submitted credentials; tampered codes/tab IDs/cross-browser substitution produce engine recovery redirects without a code; missing authentication cookies return an engine HTML 400 error. The probe never parses that HTML. This is **not** a completed SuperTokens FDI compatibility layer or a uniformly JSON error protocol.

## Build and run the isolated lab

From the repository root:

```powershell
docker build -t expertauth-kc-headless:0.1.0 engine-extensions/keycloak-headless
python engine-extensions/keycloak-headless/prepare_lab.py
docker network create --internal expertauth-kc-headless-proof
docker run -d --name expertauth-kc-headless-server --network expertauth-kc-headless-proof --network-alias kc-headless.example.test --mount "type=bind,source=$((Get-Location).Path)\engine-extensions\keycloak-headless\.runtime\realm-import.json,target=/opt/keycloak/data/import/realm-import.json,readonly" expertauth-kc-headless:0.1.0
```

The container has no published host ports. This bounded lab deliberately uses H2/dev mode; it is not production deployment or multi-replica operational proof. `.runtime/` contains generated synthetic passwords/OTP secrets and must not be committed or archived. The fixture generator refuses accidental replacement; its explicit `--replace-generated-fixtures` option is only for recreating this isolated lab. Do not regenerate fixtures while another client test uses the server.

The Gradle 8.13/Java 21 build image and Keycloak image are pinned by digest. Six compile-only Maven artifacts have exact versions in `build.gradle`, a dependency lock, and SHA-256 verification metadata. Strict verification is used in the Docker build. The JAR contains only this extension's own classes, not shaded Keycloak or dependency binaries. Archives disable timestamps, use deterministic ordering and normalize file/directory permissions. `BUILD_DEPENDENCY_REPORT.json` verifies each artifact and retains the Jakarta API license/notice alongside the Keycloak license.

`python tests/foundation/keycloak_headless_build.py` performs two strict clean builds and compares them to all three live lab JARs. The deterministic archive SHA-256 is `540ddf249b1020a4c1ee9adabaa61b8ddff7de389de2a1dcf38b460a9e779366`. It matches both PostgreSQL replicas byte for byte. The original H2 lab archive SHA-256 is `fa6e2ef790f068364241a126912b39073e54c26b968fe30eadad87e2c0af4591`: it differs only in ZIP permission metadata, with every class/resource/manifest entry identical. `evidence/foundation/keycloak-headless/build-report.json` records the exact runtime image IDs and comparison; the original mismatch evidence is retained. No H2 runtime restart was used to conceal that difference.

Run the real probe using the separately built Python example image (its dependencies are independently pinned):

```powershell
$keycloakProofRoot = (Get-Location).Path
docker run --rm --network expertauth-kc-headless-proof --mount "type=bind,source=$keycloakProofRoot,target=/work,readonly" --mount "type=bind,source=$keycloakProofRoot\evidence\foundation\keycloak-headless,target=/work/evidence/foundation/keycloak-headless" -w /work expertauth-python-app:0.1.0 python tests/foundation/keycloak_headless_probe.py
```

The **16 actual tests** cover JSON challenges; correct/incorrect password; invalid/missing TOTP; absence of final session/token before the factor; final code/state; signature/issuer/audience/nonce verification after PKCE exchange; code replay; cross-session TOTP replay; missing/tampered action codes and tabs; cross-browser action substitution; missing cookies; and the inherited brute-force lockout. There are no mocked Keycloak responses and no skipped-test success. Repeating against already-used fixtures can encounter the intentional OTP replay window or 60-second lockout; use a fresh isolated server or wait for these declared policies rather than weakening the tests.

The fixture also provisions a separate `expertauth-node-candidate` client for the candidate Node/React/Python lane, with callback `http://expertauth-kc-clients-node:3000/candidate/callback`, resource audience `expertauth-candidate-api`, default `basic` scope and optional `organization` scope. Its three client-test users are real imported members of organization `alpha`. The separate organization probe verifies the signed membership, issuer, audience, and authorized party using an independent synthetic audit user. Claims are produced by the built-in organization membership mapper from the engine's membership state; they are not hardcoded.

The initial organization-only fixture lacked default `basic` because explicitly configured optional scopes suppress implicit default assignment. The original narrow organization report proves only its stated membership/audience/issuer/authorized-party checks; it did not require a subject claim. The candidate clients rejected its access token for missing signed `sub`. The generator now includes the engine's supported `basic` scope. The client lane uses its own isolated corrected fixture and retains separate evidence; it does not weaken signed-subject validation.

For the separate PostgreSQL session lab, see `evidence/foundation/keycloak-sessions/README.md`. It uses this same extension with two engine replicas, records three strict-rotation recovery failures, and does not qualify the full foundation.

## Provenance and remaining gates

`SOURCE_REUSE_REPORT.json` records immutable source paths, hashes, licenses, inherited boundaries, original extension files, and evidence links. `LICENSES/keycloak-LICENSE.txt` retains the source license. `audit_sources.py` recreates that bounded audit from primary sources. Existing upstream source files were not copied or modified.

Keycloak logs this Authenticator SPI as **internal and subject to change without notice**. Upgrades need version-specific compilation and behavior qualification. Ordinary password/OTP errors are JSON, but duplicate-user federation errors and unrelated required-action/engine error rendering are not claimed qualified. The H2 lab, zero custom-store design, or passing checks do not select Keycloak as the final engine. All other foundation cases, full SDK/FDI contracts, production clustering/recovery, advanced features, and independent security review remain required. The candidate and overall foundation gate stay unselected/unpassed.
