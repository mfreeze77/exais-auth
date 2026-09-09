# ExpertAuth execution checkpoint

Status: **PARTIAL, active implementation. No engine selected; M0/M1 not closed.**
All 265 required rows and 205 API IDs remain required. No baseline requirement is
verified as a complete acceptance row. Tests below prove narrower cases only.

Original extracted baseline: 20/20 manifest files verified by size and SHA-256;
265 requirements, 29 families, 36 packages, M0-M10, 49 FDI/156 CDI, 8 SDK,
14 plugin and 10 integration profiles preserved. Original ZIP was not supplied;
its expected checksum remains recorded. Research report is available and preserved.

Actual code and evidence:

- Fresh npm archive acquisition now passes 11 actual registry/concurrency/cache
  and disconnected install/compile checks. One temporary container retired; no
  image, volume, network or extra host cache was retained. The single archive
  cache remains 14,891,202 total bytes. Current Node image `4c03d7306e1e` fixes
  deterministic application/directory permissions, passes 55 unit and 30
  installed reset/SMTP/browser checks, and matches 7,629 original archive members.
  All 16 build/reset containers retired; the previous image `2c4ad0be07b8` was
  removed after promotion, with original 52 identities and persistent processes
  preserved. Hygiene `verification-20260909T064650Z.json` passes 10 checks: two
  retained containers, six current tags and no dangling project-labeled images.
  Read `docs/node-package-bootstrap.md` for exact evidence, maintained-dependency
  warnings and unqualified cache-crash/HTTP-fault/full-stack cases. No requirement
  or API status was promoted.
- The complete Node Dockerfile builds with networking disabled and a single
  14,580,488-byte archive cache. Earlier image `2c4ad0be07b8` has all8 application
  files verified and7,629 original archive members matched across143 packages.
  Its installed reset lab passes10 transport,11 HTTP/SMTP and9 browser checks;
  55 delivery unit checks and8 archive-parser boundary checks pass separately.
  The previous image and its6 untagged legacy parents were retired without
  parent pruning or force. All16 build/reset containers and a separate compiler
  container retired; original52 identities and persistent processes preserved.
  Hygiene `verification-20260909T055142Z.json` passes10 checks:2 containers,
  6 current tags, no dangling project-labeled images. Nodemailer9.1.1 original
  tarball correspondence is now established. Read `docs/node-offline-build.md`:
  native/base-image licensing, full fresh-stack deployment, lifecycle faults and full
  authentication acceptance remain open; no requirement status was promoted.
- Node/React password reset now uses real authenticated TLS SMTP and the engine's
  one-time token/password APIs. Combined run-16 passes10 transport,11 HTTP/SMTP
  and9 Chromium checks, including eight concurrent consumers with one winner.
  All12 temporary containers and11 synthetic identities were removed; the original
  52 identities and source processes/configuration are preserved. A separate
  exit73 worker fault proves fallback deletion of one owned identity and removal
  of all6 temporary containers. Read `docs/password-reset.md` for exact sources,
  prior failures and commands. PWD-006 remains implemented-unverified: configured
  tenant/link cases, atomic password-change/session-revocation, durable outbox,
  fresh deployment and independent review remain open. The newer installed-image
  proof above closes only the earlier image-build gap. No engine was selected.
- A real encrypted recovery drill now restores the candidate database, signing
  material and configuration into temporary PostgreSQL/Core instances.28 format
  tests and19 operational checks pass; one historical snapshot state is separately
  characterized. Two post-snapshot revoke/delete actions are replayed before the
  restored app starts, and unexpired old refresh tokens/deleted credentials stay
  denied. All9 temporary containers retire, source processes/mounts stay unchanged
  and its original52-identity set is restored. This is a two-action lab, not a
  general durable reconciliation journal, full OPS-006/WP-033 or final-engine
  acceptance. Read `docs/encrypted-recovery.md` for measured evidence and limits.
- Hygiene now checks untagged task images as well as the6 current component tags.
  Three unused legacy Python build/fixture image records were retired by exact
  ID with no force/parent prune. No dangling project-labeled image remains;
  persistent containers, shared parents, tags, networks and volumes are preserved.
  That earlier 10-check hygiene report is `verification-20260909T032659Z.json`.
- Python's full Dockerfile now builds offline through the existing BuildKit
  builder from49 hash-pinned wheels, retaining one20,367,857-byte cache. New image
  `5bffadb83aa3` passes3,349 wheel-file comparisons,63 notice checks,418 immutable
  SDK source comparisons, pip check and19 real HTTP checks. It replaced7a4bb6dcfd63
  after tests/cleanup; Core/PostgreSQL identity/start/mounts stayed unchanged.
  One empty-directory checker defect and its rejected candidate are preserved.
  Full Python/native/OS, fresh-stack and new lifecycle fault qualification remain
  open. See `evidence/operations/python-offline-build` and the Python README.
- Native source review now identifies all59 embedded native release members and
  adds pinned source/build/notice evidence for scrypt, Argon2, JNA and SQLite.
  The corrected notice assembler preserves JNA's two full short-named licenses
  and three scrypt header notices:89 archive notice texts,390 generated files.
  Ten package/source-request tests pass, plus an actual fetched-hash rejection
  with container cleanup. The corrected package is installed in Core image
  `5ec6ccc3fd5d`: all479 files match, including87 unchanged executable JARs.
  PostgreSQL kept its exact container/start time/mounts;19 Python HTTP checks
  passed after replacement and removed both test users. The previous Core
  container/image and all temporary inspection/readiness clients were removed.
  These remain narrow tooling/attribution and regression results. Native builds/platforms,
  unresolved grants and independent distribution review remain unqualified.
  See `docs/native-source-correspondence.md` for exact boundaries and reports.
- Immutable contract extraction: 205 IDs / 207 path variants; 29 contract-tool tests.
  Source facts/hashes retained; no copied unlicensed schemas or behavioral pass claim.
- Fail-closed ledger/release gate with adversarial tests; full completion correctly fails.
- Core12.2.0/plugin-interface10.0.0/PostgreSQL-plugin9.8.0 compile from pinned source.
  84 runtime JARs audited; no EE JAR. Two real replicas were tested on a private network
  with PostgreSQL17.11 and vendor egress blocked. Source-build and probe evidence under
  `evidence/build/oss-core` and `evidence/foundation/oss-core`.
- OSS Core probe: 12 narrow passes, 5 unavailable. Native app/tenant provisioning
  and linking return402 without entitlements. CDI5.6 with zero refresh grace kills
  a legitimate concurrent refresh session. No license enforcement was altered.
- Python/FastAPI: 19 real HTTP tests passed for default-app/public-tenant password
  and online sessions, cookie/header/CSRF/logout. Full Python profile remains open.
  These19 checks were rerun against image `7a4bb6dcfd63` after fixing readiness
  and again against Core image `5ec6ccc3fd5d` after its notice replacement.
  A real PostgreSQL outage leaves Core's protocol advertisement and the historical
  readiness implementation at200; the corrected app returns503 in3.011 seconds,
  keeps liveness200 and recovers after the same database restarts. Existing-session
  refresh/online access/logout still pass after recovery. Six operational checks
  include one synthetic-user cleanup row. See `evidence/operations/python-readiness`.
  No proxy traffic removal, backup restore, database HA or full OPS acceptance follows.
- Node/React:12 live HTTP checks and4 actual Chromium checks pass. Password signup,
  wrong-password rejection, signin, logout/cookie clearing and320px layout are tested.
  Explicit offline JWT issuer/audience verification is separate from online revocation.
  Earlier SDK offline assumptions, invalid React component and overflow failures remain.
- Keycloak26.7.3: organization proof12 passes; JSON password/TOTP proof16 passes.
  Real broker/linking characterization17 passes/2 failures: concurrent ownership and
  final-method unlink. Independent persistence reread confirmed both. No correction
  was implemented after automatic review rejected the agent's hardening turn.
- Keycloak PostgreSQL two-replica probe:7 passes/3 failures. Cross-replica login,
  serial rotation and client revocation work; strict reuse/concurrent refresh and
  lost-response retry fail. Cluster startup does not close those cases.
- Keycloak representative Node backend/React/Python clients:17 real HTTP and5
  Chromium checks pass with supported basic/organization scope configuration,
  PKCE/CSRF/state guards and engine-owned password/TOTP/session behavior. Full
  FDI/CDI/SDK coverage and preauthentication replica failover remain unqualified.
- Fresh isolated OSS build consumed strict checksum/lock verification and reproduced
  all87 JAR hashes. Source fetch reconstructed1300 permitted files with zero EE paths.
- The unchanged Node24.0.3 SDK actually negotiated CDI5.4 across two Core replicas.
  Latest session proof (`evidence/foundation/sdk-session-faults/run-05`) has10 SDK
  checks and3 Chromium checks passing, including two cleanup checks, with1 explicit
  raw-header concurrency availability failure. Three transport-loss cases recover;
  committed promotion survives SIGKILL/restart of only the temporary Core B. Both
  refresh-success and refresh-denial orderings occur in12 logout races, with no
  post-logout refresh resurrection. Four real browser tabs send32 successful
  requests after actual expiry through one refresh, then all deny after logout.
  This does not qualify transaction-internal precommit failures, database HA,
  SDK-crash-before-theft-revocation or full original platform/profile scope.
- Four original Unicode path ambiguities (FDI-026, CDI-099, CDI-104, CDI-116) now
  have independently authored Apache-source and runtime resolutions:9 actual checks
  passed. The original capture is unchanged. CDI-104's legacy identifier discrepancy
  is explicit; this does not close full schema or operation qualification.
- The exact `69c68e8b4994` source ZIP was freshly extracted, manifest-checked and its
  Node/React and Python images built from the extraction.12 Node HTTP,19 Python HTTP
  and4 Chromium checks passed. Existing Core/PostgreSQL were reused; this is not a
  fresh full-stack restore, migration or complete release qualification. See
  `evidence/extracted-checkpoint/README.md` for the exact ZIP and source bindings.

Disk/Docker hygiene:15 temporary task containers,8 stale image tags,4 networks and
463,715,868 bytes of duplicate scratch were removed. Only Core-a and PostgreSQL
remain as containers, with6 retained task image tags. Retired H2 databases and raw
proof logs were backed up and their hashes verified. No volumes were deleted;
unrelated projects/shared base images were outside scope. Candidate labs and example
servers are stopped/removed, not currently running. See `evidence/operations/hygiene`.
The updated archive runner retires its own resources and fails on cleanup errors;
its12 integrity/filesystem tests passed, but its revised full Docker flow has not
been rerun. `AGENTS.md` requires the same lifecycle for all further work.

Current hygiene verification `verification-20260909T050303Z.json` passes all10
checks: two persistent containers, six current task image tags and no dangling
project-labeled images. The reset slice added only one pinned17.16MB Mailpit
image; source/bundle and test changes reused cached dependency images. The oldest
generated checkpoint ZIP (12,715,973logical bytes) was retired after full
hash/CRC/member/ancestry verification; its sidecars/history and two newer ZIPs
were preserved before making the next checkpoint. A277,260-byte host compile
cache remains locally ignored because automatic review rejected its cleanup.

Historical notice packaging ran in Core image `60c7677d0a91`:474 installed files
were hash-verified, including87 unchanged executable JARs,87 embedded notice texts,
and5 supplemental scrypt/libffi notices mapped to release bytes. The83 available
Maven source archives are locked and verified offline in the existing43MB cache;
the one unavailable Guava source sibling corresponds to a metadata-only binary.
Eight archive/provenance/notice tests pass, including tamper rejection and identical
notice-tree reproduction. This is packaging evidence, not full license approval.

Core-a was replaced only after verifying all87 JARs equal the running old image.
Authenticated storage readiness passed before/after; PostgreSQL/config were preserved,
old Core logs retained privately, and the old container/image retired. This did not
rerun the historical full auth cases or exercise the replacement script's rollback
branch. Its initial preflight refused an inherited Gradle volume; the corrected path
recognizes that mount and uses16MiB tmpfs for the unused Gradle cache. Two old caches
were retained after a nonempty check; their combined file content is385,398 bytes.
Only Core-a/PostgreSQL remain as containers, with6 retained task image tags.

The recorded SDK/session run added no images, networks or volumes. All three
temporary containers and22 synthetic users were removed; Core-a/PostgreSQL IDs,
start times and config were unchanged during that run. Chromium needed more than the probe's
original128MiB `/tmp`:the successful run measured about167.5MiB of temporary use.
Its bounded512MiB tmpfs is memory-backed and disappears with the container. All
earlier browser failures and exact harness snapshots remain preserved.

The Python readiness build reused every dependency/base filesystem layer, with
network access disabled, and retired the obsolete Python image. Only the final
application layer changed. Both outage runs and the image regression removed all
temporary containers and their own synthetic users. Core-a stayed running; the
same private PostgreSQL container/volume was stopped and restored deliberately.
Two private pre-outage dumps total367,902 bytes and remain under `.runtime/`;
their hashes are recorded, but dump restore has not been tested. The baseline is
a tiny Git-pinned app overlay, so reproducing the bug needs no stale Docker image.
Final hygiene verification at `verification-20260909T010630Z.json` passed9/9.

The corrected probe now performs its own-user cleanup in `finally`. A real dropped
auxiliary signout connection produces an incomplete child report/exit1 and removes
the one created user, preserving52 existing identities. Four outer cleanup checks
pass; they do not qualify authentication. Current normal regression image-06
passes19/19 and removes two users using the retained image without a build.
An attempted rebuild exposed missing legacy dependency-cache metadata, followed
by an explicit Docker cached-image restoration error. Image-04's exact owned
stopped intermediate was identified and removed; image-05's failure added no
resources. Both failures and prior runner sources remain preserved. The current
image is intact. The full offline rebuild path remains blocked; no repeated
rebuild or new dependency download was used to run the current regression.
A distinct image-configuration trial with all eight filesystem layers unchanged
then proved source-drift rejection and tag rollback before old-image retirement.
The helper itself restored the prior image and removed the trial image/containers;
no outer fallback ran. Its21 lifecycle checks and nested19 HTTP checks qualify
that harness branch only. The full legacy source-build error remains open.

Full notices for other uncovered dependencies, native source/build/relink obligations,
container OS review and independent distribution approval remain open. Four native
bundles need further work: scrypt, Argon2, JNA and SQLite JDBC. See
`docs/runtime-distribution-review.md` and `evidence/runtime/oss-core-notices`.

Editable ledger currently maps23 requirements to partial implementation,10 to blockers,
7 to failed candidate checks and225 to planned work. All205 API rows remain blocked
for complete contract/runtime qualification. These are statuses, not a completion rate.

Read `BLOCKERS.md`, `docs/adr/001-foundation.md`, and the current evidence before
continuing. Candidate labs are experiments, never competing product authorities.
No publication, paid resource, production change or remote push is authorized.

Resume/check commands from this repository:

```powershell
git status --short --branch
python tools/ledger.py check
python tools/capture_contracts.py --validate
python tools/validate_release.py --output evidence/integrity/current-release-check.json
docker ps --filter label=org.expertauth.purpose=oss-foundation
```

The release validator is expected to exit1. Do not convert incomplete contracts,
provider/native tests, review or dependency gates into passes to make it exit0.

Current next work: finish M1 supported extension proofs; settle one authoritative
engine only after identity/link/session/headless/client gates converge. Continue
vertical slices and carry all requirements and original profiles through selection.
