# Resume the partial implementation

Work in `expert-auth`. Read `PROJECT_STATE.md`, `BLOCKERS.md`, ADR-001 and the
original kickoff before changing engine ownership or acceptance status. Every
baseline requirement, API ID and profile remains binding. The original ZIP is
missing; all20 extracted manifest files match their original bytes and checksums.

This checkpoint has no selected production engine. Do not start feature work that
silently assumes Keycloak acceptance, patch Core entitlement enforcement, duplicate
refresh state in adapters, or directly modify upstream-owned tables.

Latest source/packaging checkpoint: read `docs/native-source-correspondence.md`.
The corrected notice tree has89 archive notice texts and390 files. Core image
`5ec6ccc3fd5d` now contains all479 verified installed files (87JARs unchanged).
Read `docs/runtime-notice-cutover.md` for exact BuildKit and cutover evidence.
All59 native release members are identified,
but no native rebuild/platform acceptance follows. Resolve the explicit JNA/SQLite
source grants, Argon2 native revision/toolchains and source/relink delivery gaps.
Do not package the ignored unresolved JNA helper. Current capture code rejects
missing source identities, path/type mismatches and evidence filename collisions;
actual wrong-hash fetch evidence retains failure and confirms container removal.
No native binary/source archives or images are needed to repeat the offline
package checks; avoid repeating successful work without changed inputs.

Latest Python operational proof: `evidence/operations/python-readiness/run-03`,
with current image `7a4bb6dcfd63` qualified by image-06's19 live HTTP checks
and the subsequent `notice-core-regression-01` against the current Core image.
Image-02 is the original successful image build; image-06 uses the corrected probe.
Readiness now detects an actual database outage, returns503 while liveness stays200,
and recovers with existing-session continuity. Six outage checks include cleanup;
full OPS-004/OPS-011, traffic removal, backup restore and HA remain open.

```powershell
python tools/run_python_readiness.py --name NEW_UNIQUE_OUTAGE_NAME
python tools/verify_checkpoint_hygiene.py
```

This command deliberately stops and restores the isolated owned PostgreSQL
container; it refuses other network consumers and preserves a small private dump.
Run only with Core-a and that database as the network's current consumers. The
before/after source overlay comes from a pinned Git commit on the same current
dependency image. No obsolete image is needed. It creates no images/networks/volumes
and retires all temporary containers. Do not rerun just to refresh a timestamp.
Use `tools/refresh_python_image.py --test-existing --name NEW_UNIQUE_IMAGE_NAME`
after a probe-only change. Installed app/lock bytes must still match. The offline
legacy full-Dockerfile cache path failed in image-04/image-05; exact diagnosis,
retirement and the available error output are preserved. Do not repeat that
unchanged build or rebuild dependencies simply to test a harness correction.
Read the Python README before separately qualifying another build path.

Two failure-lifecycle proofs are now actual, narrow results: the auxiliary signout
transport fault removes the run's own user and preserves incomplete failure
evidence; isolated input drift rejects a distinct image configuration, restores
the prior tag and retires the trial image without outer fallback. Read their
READMEs before repeating in an exclusive lab slot with a fresh evidence name:

```powershell
python tools/run_python_probe_cleanup_fault.py --name NEW_UNIQUE_FAULT_NAME
python tools/check_python_image_lifecycle.py --name NEW_UNIQUE_DRIFT_NAME
```

The latter fixture has identical filesystem layers and does not qualify the
legacy full-Dockerfile rebuild. Do not add its21 lifecycle assertions to the
authentication acceptance count or repeat unchanged passing runs for timestamps.

Latest bounded session proof: `evidence/foundation/sdk-session-faults/run-05`.
It observes Node24.0.3 CDI5.4 on the wire:10 SDK and3 browser checks passed,
including two cleanup rows; raw-header concurrency availability remains failed.
Three transport-loss recoveries, committed-promotion Core crash persistence and
one four-tab/32-request browser expiry cycle passed. The full command exits1 for
the retained failure. No image rebuild is needed to repeat it:

```powershell
python tools/run_sdk_session_faults.py --name NEW_UNIQUE_NAME
python tools/verify_checkpoint_hygiene.py
```

Prerequisites and the browser-only diagnostic mode are documented beside the
results. The runner reuses cached images, creates no network/volume, keeps
credentials private, and retires all temporary containers. Do not repeat the
known raw-header failure unchanged as a remedy. Next session work must address
the remaining frozen policy/SDK failure boundaries, not merely add a grace period
or count this narrow Chromium proof as native/other-profile qualification.

Current blockers to the next foundation decision are recorded with actual evidence:

- `evidence/foundation/keycloak-identity/HANDOFF.md`: reproduced provider ownership
  and last-login-method failures. The corrective implementation turn was rejected
  by automatic review. Do not retry that rejected action by relabeling it or moving
  it to a different agent/tool. Preserve the failed evidence until the restriction
  is resolved through an authorized route.
- `evidence/foundation/keycloak-sessions/probe-report.json`: strict cluster refresh
  policy7/10 passes. A changed, documented implementation/configuration requires new
  legitimate concurrency, replay and lost-response evidence; unchanged repetition
  of the failing suite will not resolve its cause.
- `evidence/foundation/oss-core/results.json`: advanced native operations return402;
  CDI5.6 zero-grace refresh is not an accepted concurrency policy. Audited source is
  preserved; restricted EE source/binaries and license-check modifications are absent.

Inventory and evidence checks can be repeated without changing authentication state:

```powershell
git status --short --branch
python tools/ledger.py check
python tools/capture_contracts.py --validate
python -m unittest discover -s tests/evidence -v
python tools/validate_release.py --output evidence/integrity/NEW_RELEASE_CHECK.json
```

The last command must exit1 until the entire definition of done is satisfied.
Do not count source/ZIP validation, candidate tests orAI review as authentication
completion. Original failure reports remain historical evidence; newer input
hashes must not be presented as if they were tested by older runs.

To rebuild the source-built alternative from pinned public artifacts:

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tools/fetch_pinned_sources.py
python tools/build_oss_core.py
docker run --rm --label org.expertauth.project=expert-auth -v "${PWD}:/workspace" -w /workspace python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tools/fetch_runtime_notice_sources.py
python tools/launch_oss_probe.py
```

The launcher retains owned PostgreSQL data/containers, checks private network
isolation and storage on both replicas, and publishes no ports. Host networking
was broken through Windows/PowerShell; Docker Linux networking worked. No global
network/security settings were changed. Build tools require Docker, Python3.11+
and disk/RAM for the pinned Java/Node/Python images. `.runtime/` secrets are local
only. Do not copy them into a release or use these synthetic credentials elsewhere.

The hygiene checkpoint retired all candidate/example containers except Core-a and
PostgreSQL; it also retired stale images, networks and duplicate extracted/build
trees. H2 databases and raw logs were backed up under ignored `.runtime/retired-*`.
Read `AGENTS.md` and `evidence/operations/hygiene/README.md` before starting resources.
Do not launch the two-replica lab merely for source/license/docs work. Inventory
first, reuse content-addressed builds, and stop/remove temporary resources in
`finally`. Older runners require this cleanup treatment before their next use.

The exact old source ZIP has35 fresh-extraction application checks, documented in
`evidence/extracted-checkpoint/README.md`; Core/database state was reused, so this
does not qualify full-stack restore. Current wrapper cleanup changes have their
own12 integrity/filesystem checks. Four API wire-path resolutions are preserved in
`contracts/runtime-path-resolutions.json`, with9 real checks and original IDs intact.

Runtime notice packaging and locked acquisition are now connected. Preserve the43MB
source cache; normal acquisition verifies it without downloading unchanged files.
`python tools/fetch_runtime_notice_sources.py --offline` verifies83 available source
archives and preserves the one recorded Guava metadata-only absence. Image
`60c7677d0a91` contains474 verified files and is running in Core-a; see
`evidence/runtime/oss-core-notices/preserved-notices-01/report.json` and
`replacement-20260908T232129Z-99cdc5/report.json` in that same evidence directory.

Use `python tools/launch_oss_probe.py --build-only --evidence-name NEW_NAME` when
only an image build/content check is needed. It retires context/inspection resources
and does not create a second service replica. The normal launcher refuses to report
an old container as running a newly built image. `tools/replace_oss_notice_image.py`
is limited to87-JAR-identical notice maintenance, not a general authentication
upgrade or migration tool; its failure rollback branch remains unexecuted. Current
Core uses bounded tmpfs for the inherited unused Gradle cache. Two old nonempty
Gradle caches total385,398 bytes and were preserved after read-only inspection.

Next licensing work is precise: full applicable notices for uncovered dependencies;
native provenance/source/build and source/relink conditions for scrypt, Argon2,
JNA and SQLite; and container OS/dependency closure. Read
`docs/runtime-distribution-review.md`. Neither source JAR availability nor the
packaged notice manifest closes the full distribution gate.

For the tested Node/React and Python examples, use their own README commands.
Keycloak JSON extension and representative client commands/evidence are in their
respective `engine-extensions/keycloak-headless` and `examples/keycloak-clients`
directories. These labs remain distinct experiments, not a dual-engine product.

After an authorized continuation produces stable intended files, refresh partial
traceability carefully, commit locally and make a new validated source snapshot:

```powershell
python tools/update_checkpoint_ledger.py
python tools/package_checkpoint.py --name expertauth-partial-checkpoint-NEXT
```

Packaging requires a clean local commit and never pushes or publishes. The ZIP
contains source, original baseline, reports and a Git bundle. Extract it and run
`git clone SOURCE_REPOSITORY.bundle expert-auth-resume` to restore Git history.
The manifest and SHA-256 validate transport integrity, not full feature acceptance.

Full production deployment, migrations/import/reconciliation/rollback, complete
SDK/UI/plugin/integration delivery, provider/native tests and independent human
security/licensing review remain unfinished. No COMPLETE marker is authorized by
this checkpoint and no production/push/publication/spend approval exists.
