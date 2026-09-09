# Effective session-policy readiness

Status: PARTIAL. This package qualifies a default-public-tenant candidate. It does
not select a foundation or close any complete baseline requirement or profile.

The private authenticated `GET /public/expertauth/password/session` now returns
the Core's effective `refreshTokenRotationGracePeriodSeconds` and
`recentTokenReuseBehaviour` under `sessionPolicy`. These values come from the
request tenant's existing Core configuration. No credential, API key, connection
string or full configuration is returned. The existing capability fields remain
compatible. Unauthenticated requests return401.

With `EXPERTAUTH_SESSION_POLICY=core-cdi56-grace-v1` and
`EXPERTAUTH_RESET_POLICY=atomic-v1`, the Node app requires exactly5 seconds and
`TOKEN_THEFT`. Readiness still checks storage, advertisedCDI5.6 and the atomic
APIs. Authentication, hybrid and online-session routes additionally check the
effective policy before each request, without retaining a previous healthy
answer. A mismatch or transport failure returns503 with no tokens. Liveness
remains200. The explicitly offline JWT route keeps its signature/claim-only
behavior; it does not acquire an online revocation or policy-health guarantee.

This preflight is not atomic with a later Core operation. A load balancer that
routes the check and operation to differently configured replicas, or an operator
changing settings between them, remains unqualified. Every replica must use the
same policy. Full namespace configuration, all originalSDK/client profiles,
revocation crash/restart/failover/load orderings, complete migration/distribution
and independent human review remain open. The retained source lab's configuration
is still zero grace; it correctly fails this optional five-second profile.

## Code, binaries and real evidence

- `engine-extensions/core-reset/src/io/expertauth/core/AtomicPasswordSessionAPI.java`
  supplies the authenticated readout. `examples/node-react/server.js` consumes it.
- Core image `sha256:3e15c927a6625389e03bceb27d898d9a688bdf9d6431cb00b0668530ae56c97e`
  is built from `evidence/operations/password-session-build/policy-01`. Relative
  to compile-04, only `AtomicPasswordSessionAPI.class` changes; the PostgreSQL
  plugin remains byte-identical. Original token algorithms and entitlement checks
  are unchanged. File-specific mappings and Apache notices are in
  `reuse/password-session-components.json` and `reuse/session-grace-components.json`.
- `evidence/operations/atomic-core-image/policy-01` passes16 Core transaction
  cases,34 installed Node/SMTP/TLS/browser regressions,12 direct refresh-policy
  cases, and14 actual local upgrade/rollback/re-upgrade phase cases. Both zero
  grace and five-second effective settings are observed from the actual engine.
  The PostgreSQL process, schema, private configuration and52 original identities
  are preserved; only one Core is active during the replacement controller.
- `evidence/foundation/refresh-grace/policy-source-01` passes seven policy checks
  plus one owned-user cleanup row. Three actual Core configurations all advertise
  CDI5.6:5/TOKEN_THEFT,0/TOKEN_THEFT,5/UNAUTHORISED. The latter two are refused.
  Transport loss is also refused. Each negative profile issues zero auth business
  requests; eight concurrent rejected requests issue no credentials. Returning
  to the healthy Core allows the same session to refresh without restarting the
  app. All six temporary containers and the one synthetic identity are removed.

Installed Node image
`sha256:7964df6fe51e7ff9164326628144a72bab8d1f310b7db66044ddfe65445e2a6c`
passes the complete local builder qualification in
`evidence/operations/node-image-build/policy-02`:55 delivery unit tests,
8 package/parser checks,34 reset behavior regressions, the installed grace
SDK/browser profile, and the installed policy-refusal profile. The latter two
are `installed-policy-02` and `policy-policy-02` under
`evidence/foundation/refresh-grace`. The SDK has nine HTTP behavior rows plus
wire/cleanup; the browser has two behavior rows plus cleanup. Four tabs complete
32 protected requests and all receive401 after logout. The new private readout
and app guards use no JAR or app overlays in installed qualification.

All35 Node build/qualification containers are retired, with no downloads, new
networks, persistent volumes or public ports. The previous Node imagee02ab9bcd78e
is retired only after every child passes. Correspondence checks pass295 for the
Node build and724 for policy/source/binary/private-log mappings; those counts are
integrity checks, not extra authentication cases. Final hygiene passes10/10,
with two retained containers, six task image tags and no dangling project images.

## Preserved regression and correction

The first Node candidate in `evidence/operations/node-image-build/policy-01`
was not promoted. Its reset browser test failed after a200 sign-in response and
before the response-body check. The private failure capture shows navigation
already underway. The test waited for click/navigation completion before reading
the body, consistent with Chromium discarding that response. The original
exception was not classified, so that particular mechanism is an inference.

`tests/browser/password-reset.mjs` now starts parsing the actual200 response as
soon as it arrives, concurrently with the click. All original assertions remain.
It also records a fixed nonsecret failure category for future diagnoses. The
focused `policy-browser-01` disposable lab passes all nine real browser cases;
all eight parent/child containers are retired. No image build or download was
needed for that diagnostic. The failed candidate image is absent and its source,
build output, negative result and private capture hashes remain preserved.

## Bounded build and resume commands

`tools/build_password_session.py --candidate-from` preserves the previous exact
JAR pair while creating one immutable candidate directory. It refuses an existing
destination, unknown files, changed binary hashes, paths outside its cache, and a
third pair. Eight actual filesystem guard tests pass; these are tooling checks.
After installed qualification and upgrade/rollback, the exact retirement tool
checks hashes, every JAR member and all container bind mounts before removing
only the superseded pair. Its1,666,723 bytes were retired in
`evidence/operations/hygiene/password-session-retirement-policy-01.json`.

Use fresh evidence names only when code changes or a remaining case warrants it:

```powershell
python -B tools/run_refresh_grace_lab.py --name NEW_POLICY_RUN --session-build policy-01 --with-node --policy-readiness
python -B tools/run_refresh_grace_lab.py --name NEW_INSTALLED_RUN --session-build policy-01 --with-node --policy-readiness --installed-node-image sha256:7964df6fe51e7ff9164326628144a72bab8d1f310b7db66044ddfe65445e2a6c
python -B tools/run_refresh_grace_lab.py --name NEW_CORE_RUN --session-build policy-01
python -B tools/build_node_runtime.py --name NEW_NODE_BUILD --session-build policy-01 --qualify-refresh-grace
python -B tools/build_password_session.py --name NEW_BINARY --candidate-from policy-01
python -B tools/build_atomic_core_runtime.py --name NEW_CORE_BUILD --session-build NEW_BINARY --qualify-refresh-grace
python -B tools/retire_password_session_candidate.py --image-build NEW_CORE_BUILD
```

The Node builder now requires reset regression, installed grace/browser behavior
and effective-policy refusal before promotion. The source runner above mounts
`server.js`; add `--installed-node-image` with the current immutable pin for actual
installed qualification. The Core runner binds and checks both installed JARs
against the explicitly supplied binary build. Existing audited caches and the
private lab are prerequisites; fresh-host bootstrap remains incomplete.

No production changes, spending, publishing, pushing, global prune, volume prune
or Docker/WSL restart is authorized by these commands. Keep one current image per
component, one current JAR pair after qualification, and at most three validated
source checkpoints. Retain the original baseline and all failed evidence.
