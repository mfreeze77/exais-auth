# Installed atomic Core candidate and local rollback

This is the superseded installed-02 checkpoint. Current pins and commands are in
[guarded-session-operations.md](guarded-session-operations.md). Its old image and JAR
pair were retired after replacement qualification.

This checkpoint's `expertauth-oss-core:12.2.0-probe` image was
`sha256:03b4458c532f0d1f212012967f849420761dea14c2c1636ad32c8ed29ee2e97d`.
It contains the atomic password-reset/session Core and PostgreSQL JAR pair.
This Core qualification used Node image `9375a5bc093d`; the subsequent
[refresh-policy qualification](session-refresh-grace.md) installed its successor
`e02ab9bcd78e`. Healthy Core and Node flows
now run without application/JAR overlays. This is a qualified local candidate;
ADR-001 still has no selected production engine and no full requirement passes.

## Actual installed and migration behavior

`evidence/operations/atomic-core-image/installed-02` binds the image assembly,
source snapshots and the installed two-replica Core and Node child labs:

- 16 actual Core cases pass, including both password-reset/session insertion
  orderings, database transaction abort/retry, concurrent creation and mapping.
- 34 installed Node/SMTP/TLS/Chromium behavior cases pass. The mismatch cases
  deliberately mount original JARs; the healthy Core replicas have no JAR mounts.
  The new-Core/old-plugin combination remains not-ready and cannot issue a
  session. The healthy path records 38 successful private session calls, and the
  missing-writer path records one rejected call. The success screenshot was
  visually inspected. The disposable database and all its fixtures were retired.
- 14 actual upgrade/rollback cases pass on the preserved local database. A
  synthetic legacy session survives upgrade, rollback and re-upgrade, including
  refresh and password sign-in. A session created through the new API remains
  usable after rollback to the original Core. The original API availability is
  restored during rollback. The single synthetic identity is removed afterward.

The replacement preserves all 52 original identities and uses the same private
configuration, PostgreSQL container, volume and process. It stops and detaches
one Core before attaching the other; there is never a second active identity
authority for this database. This is a single-node transition with interruption,
not a rolling or highly available upgrade. Other SDK versions, factors, tenant
contexts, schema migrations, in-flight process failures and general post-cutover
reconciliation remain unqualified.

Before replacement, a 193,742-byte custom-format pg_dump and the original logs
were retained privately. The dump SHA-256 is
`6db55ad09f37af3fdc9909adfeea7d2b8d29afacc016added18a590c64191e2e`.
This particular dump was not restore-tested and does not pass OPS-006. Schema-only
dump contents match before/after after excluding pg_dump's generated psql
restriction nonce. Both raw outputs and the exact normalization remain recorded.
The backup and synthetic fixture credentials stay outside the source ZIP.

Only after continuity, rollback, final cleanup, schema and installed-file checks
passed did the controller promote the tag and retire the old Core container and
image `5ec6ccc3fd5d`. Current Core container:
`ab67dec1c0c1114e23b782b55460b76e5a8e214fdc506fe0ddc35be916b2d667`.

## Sources, distribution and cleanup

Compile-04 uses the pinned Gradle/JDK base directly and validates all 87 original
JAR cache entries. It reproduces exactly the previously tested compile-03 Core
and plugin bytes. It no longer needs the retired runtime as a compiler image.
The two JARs total 1,666,723 bytes; no cryptographic primitive or entitlement
check was replaced. The original 85 other executable JARs remain unchanged.

All 483 running JAR/notice/configuration-version files match the assembled image.
The added Apache license, modification notice, source map and 87-component
runtime SBOM live under `/opt/expertauth/licenses/expertauth/atomic`. The original
84-component dependency SBOM is preserved separately. Native/OS/transitive
source/relink obligations and independent distribution review remain open.

The first image run passed both behavioral labs but stopped before replacement.
Its resource checker used Docker's default image list, which omitted the untagged
BuildKit candidate. The failed report and its sources remain intact; the candidate
was retired. The inventory now uses `--all`, and the corrected run passes. The
same complete inventory is used for final replacement accounting; no comparison
was relaxed to ignore unexpected images. The hygiene check also includes all
project-labeled dangling images and finds none.

The successful run removes 34 temporary inspection/test/upgrade helpers, replaces
one original Core container, and retires its old image with `--no-prune`. Its
59,986,010-byte build context is removed. The failed run's 26 temporary containers
and candidate image are also removed. Compile-04's single helper is removed.
The final inventory remains two retained project containers and six task tags.
No image downloads, new persistent volumes/networks or public ports were added.
Build RUN networking is disabled; Docker registry metadata resolution is a
separate build-time surface and has not been certified as air-gapped.

The correspondence verifier passes 481 source/log/binary/state checks. These are
integrity checks, not additional authentication tests or independent review.

## Supported resumption

For changed Core adaptation code, preserve the current candidate, compile into a
separately reviewed replacement workflow, and retain exact build evidence.
The existing compiler's `--verify-existing` mode accepts only byte-identical
recompilation; it is not a general binary replacement option. Do not delete the
current cache just to defeat that guard.

For actual image-content changes with a matching successful build and the
documented original source/dependency caches and private lab:

```powershell
python -B tools/build_atomic_core_runtime.py --name NEW_BUILD --session-build compile-04
python -B tools/verify_atomic_core_installation.py --name NEW_BUILD
```

To exercise a changed test/launcher against the installed images without
rebuilding unchanged layers:

```powershell
python -B tools/run_atomic_reset_lab.py --name NEW_CORE_RUN --session-build compile-04 --installed-core-image sha256:03b4458c532f0d1f212012967f849420761dea14c2c1636ad32c8ed29ee2e97d
python -B tools/run_atomic_reset_lab.py --name NEW_NODE_RUN --session-build compile-04 --installed-core-image sha256:03b4458c532f0d1f212012967f849420761dea14c2c1636ad32c8ed29ee2e97d --with-node --installed-node-image sha256:9375a5bc093d7210da4daa7a06c55e39c1401df56b0dec2b78d5f4816470442f
```

Do not repeat unchanged passing runs. Original notice-only builders/replacers
describe the historical unadapted runtime and are not an in-place upgrade path
for this candidate. Full fresh-host bootstrap remains unqualified: the current
controller requires the existing private lab. App/tenant/link entitlement gaps,
the separately failed refresh policies, all remaining profiles, live/native
qualification and independent review remain open. Keep all 265 requirements,
205 APIs, 8 SDKs, 14 plugins, 10 integrations and M0-M10 binding.
