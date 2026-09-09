# Guarded Core session operations

Current Core packaging is now `e8c460664ac5`, with unchanged `guarded-01` JARs.
Read [installed native Argon2](installed-native-argon2.md) for current image build
commands and startup/native qualification. The earlier Core pin below is historical.

Status: PARTIAL; no foundation selected and no full baseline row qualified.

The five-second session profile now uses private Core routes
`POST /expertauth/session/refresh` and `/expertauth/session/verify`. They retain the
original API-key/IP checks, token parsing, cryptography, session transaction and
error behavior, and require CDI 5.6. They pass the fixed expected policy
`OSS-CDI56-GRACE5-V1` into the existing Core methods. A pre-guard Core does not
recognize these routes and returns 404 before performing a session operation.
The Node adapter has no fallback to the original refresh/verify routes.

Core resolves the actual tenant from the verified token. The guard requires the
default public tenant, grace of five seconds and `TOKEN_THEFT`. Refresh checks
the same `CoreConfig` object that the existing SQL transaction uses for its
grace/reuse decisions. Recursive transaction retries retain the expected-policy
argument. There is no ThreadLocal context, policy database, adapter token store
or alternate signing/refresh algorithm. Guarded refresh refuses unqualified
non-SQL storage. Original API routes and method signatures retain their original
behavior by passing no expected-policy constraint.

Node readiness and its preflight still check the authenticated effective settings
and now require advertisement of guarded operations. A mismatch at preflight is
503. If preflight reaches a healthy replica but the actual refresh/verify reaches
a mismatched replica, Core returns 503 `SESSION_POLICY_MISMATCH`. The unchanged
SDK's Core-service failure handling produces a fixed application 500 with no
credentials. Returning the same session to a healthy replica succeeds. This is
a declared service/configuration failure, not an invalid-credential or theft
response. No SDK source or protocol-support declaration was changed.

Other auth operations, including sign-up, password-session creation and reset,
still depend on consistent configuration across their preflight and operation.
This work does not qualify their configuration-change races. The explicitly
offline JWT profile also remains separate. Full configured-tenant, live config
reload, rolling deployment, all SDK/native/provider versions, security ordering,
migration, distribution and independent human-review gates remain open.

## Reuse and evidence

`tools/patch_session_policy.py` transforms exact audited Apache-2.0 source bytes.
`Session.java` receives backward-compatible overloads and an explicit policy
argument. Private API derivatives retain the original Apache headers and have
visible modification notices. Original `RefreshSessionAPI` and `VerifySessionAPI`
classes are unchanged. `Webserver.java` only registers the added private routes
alongside its existing atomic extensions. `SessionPolicy.java` is the small new
Core-owned constraint. The file-specific source/derivative mapping is in
`reuse/password-session-components.json`; original notices remain installed.
No licensing or entitlement check was removed or altered.

The offline `guarded-01` binary build passes. The PostgreSQL plugin is
byte-identical to its preceding version. Source JARs and all audited compiler
dependencies remain pinned. The initial transformation preflight failed because
a catch-clause substring also matched a nested catch; its exact generator and
diagnostic remain in `evidence/operations/session-policy-transform/anchors-01`.
Anchoring the full line resolved that build-time ambiguity; no runtime, image or
authentication operation was involved in the failed preflight.

Core image
`sha256:db1d29ba624484783b999d788762da27b3f94ad936e80e13f0c8b54c8996e9f7`
passes `evidence/operations/atomic-core-image/guarded-01`. Its new direct-engine
child is `evidence/foundation/refresh-grace/image-guarded-guarded-01`:

- Nine behavior/security checks plus one owned-user cleanup row pass against
  three actual configurations and one actual pre-guard Core replica sharing a
  disposable database. Each installed JAR is checked against its build manifest.
- Healthy preflight followed by a zero-grace or alternate-reuse operation returns
  503 without changing any tracked session column. Same-token retry on the
  healthy replica succeeds. Guarded invalid-token errors match the original APIs.
- Sixteen mixed concurrent requests produce eight healthy rotations and eight
  mismatch refusals, with exactly one authoritative successor. Downgrade to
  CDI 5.3/5.4 is refused. Unauthenticated guarded operations return 401.
- The actual older replica returns 404 for both new routes, leaves the session
  unchanged, and still refreshes successfully through its original route.
- All seven temporary containers and the owned identity are removed.

The same Core image also passes 16 atomic transaction cases, 34 installed Node/
SMTP/TLS/browser regressions, 12 direct refresh-policy cases, and 14 actual local
upgrade/rollback/re-upgrade phase cases. The previous Core image and JAR pair
are retired after qualification. The PostgreSQL process, original schema,
configuration and 52 original identities are preserved.

`evidence/foundation/refresh-grace/guarded-source-01` passes the actual Node source
profile: the existing seven policy checks, three new cross-replica checks and
one cleanup row. The proxy only routes real requests/responses between the real
Cores. Healthy preflight does not rescue a mismatched guarded operation. Mixed
concurrent requests produce two healthy refreshes and two refusal errors, with
one online-valid successor. All six temporary containers are removed.

Installed Node image
`sha256:2a02e08d5fcbdd573974bb21247e4784b23870e86d0de1ced65121b3a11da19a`
passes `evidence/operations/node-image-build/guarded-01`: 55 delivery unit tests,
8 package/parser checks, 34 reset behavior regressions, the installed grace/
browser profile and all 11 guarded policy rows. The installed children are
`installed-guarded-01` and `policy-guarded-01` under the refresh-grace evidence
directory. Both use installed Core/Node bytes without JAR or application overlays.
Four tabs complete 32 protected requests with one coordinated refresh and all
four are denied after logout. Real committed response loss and truncation recover
through the guarded route. Three private Core paths return 404 at the public app.

All 35 Node build/qualification containers are retired. The previous Node image
is removed only after qualification. Node build correspondence passes 303 checks;
guarded code/binary/log correspondence passes 878. Those are integrity checks,
not extra authentication cases or independent review. Hygiene verifies two
retained containers, six task image tags and no dangling project images.

## Resume

Use unique run names and run only when code or an unresolved case changes:

```powershell
python -B tools/run_refresh_grace_lab.py --name NEW_GUARDED_CORE --session-build guarded-01 --guarded-core
python -B tools/run_refresh_grace_lab.py --name NEW_GUARDED_NODE --session-build guarded-01 --with-node --policy-readiness --guarded-node
python -B tools/run_refresh_grace_lab.py --name NEW_INSTALLED_NODE --session-build guarded-01 --with-node --policy-readiness --guarded-node --installed-node-image sha256:2a02e08d5fcbdd573974bb21247e4784b23870e86d0de1ced65121b3a11da19a
python -B tools/build_node_runtime.py --name NEW_NODE_BUILD --session-build guarded-01 --qualify-refresh-grace
python -B tools/build_password_session.py --name NEW_BINARY --candidate-from guarded-01
python -B tools/build_atomic_core_runtime.py --name NEW_CORE_BUILD --session-build NEW_BINARY --native-argon2-build linux-03 --qualify-refresh-grace --qualify-guarded-sessions
python -B tools/retire_password_session_candidate.py --image-build NEW_CORE_BUILD
```

The optional `--legacy-core-image`/`--legacy-session-build` probe arguments and
Core builder `--legacy-session-build` are specifically for a retained pre-guard
candidate during qualification. Do not recreate retired images merely to repeat
passing evidence. The default guarded probe has eight behavior rows plus cleanup;
the optional pre-guard replica adds its actual unsupported-route compatibility
case. These are distinct declared profiles, not skipped required tests.

The Node builder requires both installed grace/browser and guarded cross-replica
policy checks before promotion. Source-only test changes use existing cached
images. Fresh-host bootstrap, all original API/profile acceptance and complete
licensing closure remain incomplete. Keep one current image per component, one
current adapted JAR pair after qualification, and at most three validated ZIPs.
