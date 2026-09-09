# Node and React candidate integration

Working default-application/public-tenant password and session slice against the
audited OSS Core. This is a foundation candidate, not the final ExpertAuth SDK.
Core exclusively owns passwords, identities, signing and refresh state.

Pinned Node22.23.2, Express5.2.1, React19.2.8, SuperTokens Node24.0.3 and React0.51.3
are in `package-lock.json`. The Node dependency graph deliberately overrides
Nodemailer to9.1.1 after a real advisory and isolated delivery qualification; the
upstream graph is retained in `evidence/reuse`. `jose`6.2.12 verifies offline JWTs.

The backend has same-origin enforcement, bounded JSON, private Core authentication,
online session/resource guards and explicit offline JWT verification. The offline
route validates signature, issuer, audience, expiry and required claims but cannot
promise immediate logout revocation. `/api/session` is SDK hybrid verification;
`/api/session/online` performs the online check. Password reset now uses optional
authenticated SMTP with verified implicit TLS; without SMTP both reset endpoints
are disabled. See [password reset evidence and setup](../../docs/password-reset.md).
Its full offline image and installed reset lab pass. Exact package/app byte
correspondence and the remaining fresh-bootstrap gaps are described in
[the build report](../../docs/node-offline-build.md).

From the repository root after starting the private OSS lab:

```powershell
python -B tools/build_node_runtime.py --name NEW_NODE_IMAGE_BUILD
docker run -d --name expertauth-node-react --label org.expertauth.purpose=oss-foundation --network expertauth-oss-proof --network-alias node-app.example.test --env-file .runtime/oss-core/runtime.env -e EXPERTAUTH_PUBLIC_ORIGIN=http://node-app.example.test:3000 -e EXPERTAUTH_LOCAL_PROBE=true --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges expertauth-node-react:0.0.5
```

The tested lab publishes no ports. Commands do not silently replace existing
containers. HTTPS, production proxy configuration and host browser deployment need
separate qualification. The actual Chromium proof ran within the private network.

Twelve live HTTP tests pass in `evidence/runs/node-live-03`. Four real browser checks
pass in `evidence/browser/oss-password-05`; screenshots were visually reviewed at
1280px and320px. Initial failed UI/import/layout tests are preserved. The current
component uses the SDK's exported routing component and responsive style override.
This does not qualify all accessibility criteria, browsers or the full React profile.

Browser reproduction (install test dependencies from the lock in the pinned Node
image first; no install-time scripts or browser downloads are needed):

```powershell
docker run --rm -v "${PWD}/tests/browser:/app" -w /app -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 npm ci --ignore-scripts
docker run --rm --network expertauth-oss-proof --ipc=host -e EVIDENCE_DIR=/repo/evidence/browser/NEW_RUN -v "${PWD}:/repo" -w /repo/tests/browser mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e node oss-password.mjs
```
