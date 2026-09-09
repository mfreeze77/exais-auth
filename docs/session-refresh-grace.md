# Explicit CDI5.6 session candidate

Current images and effective-policy readiness are in
[session-policy-readiness.md](session-policy-readiness.md).
The following original checkpoint used Node `e02ab9bcd78e` and Core `03b4458c532f`;
both have been superseded and retired after qualification.
This is a tested default-public-tenant candidate, not foundation or full SDK approval.

The original SES-003/004 criteria require a tested race/retry state machine and
a distinction between allowed retry and stale replay. They do not require zero
grace. The original zero-grace and legacy uncoordinated-client failures remain
preserved. This profile adds evidence; it does not turn those failures into passes.

## Behavior and adaptation

`contracts/session-policy-oss-cdi56-grace-v1.json` declares a five-second window.
Core commits one current successor at refresh. Retrying the retired parent within
the window replaces that successor without extending the window or expiry.
Displaced access tokens fail online verification. Refreshing a displaced branch,
an expired-window parent or stale ancestor revokes the intended family server-side.
Other families remain usable. Clients must coordinate credential installation and
use; arbitrary simultaneous use of both returned branches is still unqualified.

The [pinned Node declaration](https://raw.githubusercontent.com/supertokens/supertokens-node/9b82aefb46da4c0f0a388d8f6656c39a62d7642c/lib/ts/version.ts)
advertises CDI5.4. ExpertAuth uses its existing network-interceptor extension to
adapt only private `POST /recipe/session/refresh` and `/recipe/session/verify`
requests to CDI5.6. Upstream SDK files and dependencies are unchanged. Atomic
password-session creation retains its separate tested CDI5.4 private route.
The adapter rejects unexpected namespace/origin/version contexts and keeps all
rotation, signing and revocation inside the existing Core engine.

Enable this explicit candidate with `EXPERTAUTH_SESSION_POLICY=core-cdi56-grace-v1`
and `EXPERTAUTH_RESET_POLICY=atomic-v1`, against Core configured with
`refresh_token_rotation_grace_period: 5` and `recent_token_reuse_behaviour: TOKEN_THEFT`.
The retained original lab configuration was not changed. Its zero-grace setting
must not be described as this profile. Readiness verifies storage, atomic APIs
and advertised CDI5.6 in this historical checkpoint; the later implementation
also checks the effective grace/reuse settings and refuses a mismatch.
No unmodified Node/Python/native CDI5.6 qualification is claimed.

## Actual evidence

- `evidence/foundation/refresh-grace/run-01`: 12 direct Core cases pass using
  two installed replicas and a disposable PostgreSQL database. Eight concurrent
  refresh responses converge on exactly one current successor. An AFTER UPDATE
  trigger blocks an owned transaction before commit; terminating that identified
  backend rolls back all rotation columns and permits same-token retry. The
  test-only trigger is removed, and the disposable database is retired.
- That Core run also verifies three replay classifications, bounded retry,
  real committed-response loss, eight-byte body truncation, a response delivered
  after logout, and an explicit 5.4/5.6 transition sequence. These are raw Core
  cases, not SDK or migration-program acceptance.
- `node-03` qualifies the source-mounted Node adaptation: nine HTTP behavior
  cases, one wire-correlation row and one owned-user cleanup row pass. The
  unchanged React interceptor passes four-tab refresh and cross-tab logout;
  its third row confirms cleanup. All 32 concurrent protected requests return200
  after real access expiry using one refresh request. All four return401 after logout.
- `installed-cdi56-grace-01` repeats those SDK/browser checks using the installed
  Node image without application mounts. Core also has no JAR mounts. Its wire
  trace contains135 actual requests; adapted calls use5.6 across both replicas,
  while password-session creation uses the atomic5.4 route. Eleven backend users
  and one browser user are removed; all six temporary containers retire.
- `evidence/operations/node-image-build/cdi56-grace-01` passes the offline build,
  55 delivery unit cases, eight actual package-parser cases, 34 installed
  password-reset/SMTP/TLS/browser regressions and the installed grace child.
  Dependencies and all7,629 audited original package members remain unchanged;
  all eight installed app files match. Only then is the previous Node image
  `9375a5bc093d` retired. The build and both children remove29 temporary containers.
- Correspondence validators pass288 Node-build and287 grace source/log checks.
  These are integrity checks, not extra authentication cases or independent review.
  Both grace browser screenshots were visually inspected.

The initial `node-01` and `node-02` runs failed before auth requests because the
lab omitted its local HTTP flag, then used a hostname without a valid suffix.
Both failures remain recorded and all five containers from each were retired.
A bounded offline startup diagnostic first exposed a Docker log-option error;
its corrected invocation captured the actual HTTPS guard. The runner now retains
private bounded app diagnostics and detects early app exit. It uses an internal
`.example.test` alias and the existing local-probe flag; production HTTPS checks
are unchanged. No image was downloaded or built for these diagnostics.

## Resume commands and remaining gates

Use unique evidence names and rerun only when inputs or an unresolved case change:

```powershell
python -B tools/run_refresh_grace_lab.py --name NEW_CORE_RUN --session-build policy-01
python -B tools/run_refresh_grace_lab.py --name NEW_NODE_RUN --session-build policy-01 --with-node --installed-node-image sha256:7964df6fe51e7ff9164326628144a72bab8d1f310b7db66044ddfe65445e2a6c
python -B tools/build_node_runtime.py --name NEW_BUILD --session-build policy-01 --qualify-refresh-grace
```

The build command requires existing audited caches and private lab; clean-host
bootstrap remains unqualified. The source-mounted runner is for changed app code;
omit `--installed-node-image` for that explicit mode. No new image is needed for
test-only changes. Keep one current image and at most three validated source ZIPs.

Still required: policy consistency across check/operation/replica changes; every supported SDK and
header/cookie/native coordination profile; late/reordered client credential
installation; transaction-internal revocation failures, restart/failover/load and
all orderings; bounded offline residual measurement; configured namespaces,
linking and factors; full API contracts/migration; complete native/OS distribution;
live-provider/native-platform tests and independent human security review.
ADR-001 remains pending. All265 requirements,205 APIs and original profiles remain
binding. See `reuse/session-grace-components.json` for nine file-specific sources.
