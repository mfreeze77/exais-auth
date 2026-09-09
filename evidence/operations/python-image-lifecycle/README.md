# Python image source-drift lifecycle proof

This bounded operational test runs the actual `tools/refresh_python_image.py`
helper from an isolated copy. It uses the existing private Core/PostgreSQL and
the real 19-case Python HTTP probe. Neither the helper nor HTTP behavior is
mocked. It does not qualify broader authentication parity or the foundation.

Executed once on 2026-09-09 UTC: [`source-drift-01/report.json`](source-drift-01/report.json)
passed all 21 lifecycle assertions. The actual helper intentionally exited 1
with `inputs_unchanged: false`, `image_promoted: false`, and the sole error
`Qualification inputs changed; preserving the prior image`. Its real HTTP
regression passed 19/19 and removed both synthetic users. All eight filesystem
layers remained identical. Helper rollback restored the protected tag and
removed candidate image
`sha256:9bcbd45997b646f211693a9ee862f0968b898108b54eb4f08b39a390938700d4`
before the outer safety checks; `fallback_actions` was empty.

Both recorded app/probe containers, the temporary protection tag, and the exact
private scratch directory were removed. No final container/image/volume/network
inventory changes remained. Core and PostgreSQL kept their exact IDs, images,
start times and mounts. All 14 recorded artifact hashes were independently
recomputed and matched after the run.

The report SHA-256 is
`f9fb03d2e6149719329ea3691da66d7dcdb615d1b3f6ff4f3e5eff9c42ce0945`.
The tested lifecycle tool SHA-256 is
`e417fec208db84019c3c88e23b1b8ebc0c813da932b7140e2b87c584311d06bd`;
the exact copied helper SHA-256 is
`5c8d9bedf14df9e7295293e0129a5010715073196b64696ef0593c25d2e3b9f9`.

Run only in an exclusive coordinated slot after the normal image regression and
other Python fixtures have finished. Preserve prior runs by choosing a new name:

```powershell
python tools/check_python_image_lifecycle.py --name NEW_UNIQUE_NAME
```

The command requires the existing `expertauth-oss-proof` internal network,
running `expertauth-oss-core-a` and `expertauth-oss-postgres`, the private local
`.runtime/oss-core/runtime.env`, and the protected Python tag pointing to image
`sha256:7a4bb6dcfd634a98f603d65bc2c1219fef5b3a46a00be705631201c4f78802f1`.
It does not download dependencies, restart the database, publish ports, or create
a network or volume. A different protected image requires a separate reviewed
test update; the tool refuses to proceed automatically.

The isolated app remains byte-identical to the current source. Only its isolated
Dockerfile is replaced with `FROM` the unique local protection tag, verified to
resolve to the exact protected image ID, plus a harmless unique `LABEL`. Docker
builds a distinct image configuration with `--network=none --pull=false`; the
filesystem layers, inherited command, and runtime user remain identical. This
is an image-tag/source-stability lifecycle proof, not full source-build
qualification. The normal source-build path has a separately preserved
containerd cached-image restoration failure in
`evidence/operations/python-readiness/image-05/` and is not retried here.

After the helper writes its actual app container ID, the test changes only the
isolated `.dockerignore`. The actual HTTP regression and synthetic-user cleanup
then run before the helper must reject promotion because its source inputs
changed. A passing outer test requires helper exit 1, `inputs_unchanged: false`,
`image_promoted: false`, all 19 HTTP checks passing, both created synthetic users
removed, the protected tag restored, and the candidate image and both temporary
containers retired.

Each run preserves the exact seven original input files, the fixture Dockerfile and
post-build ignore file, sanitized helper output, the real helper and HTTP
reports, input/artifact SHA-256 values, and Core/PostgreSQL identity/start-time/
mount snapshots. Private environment contents remain in ignored scratch and are
not packaged. Scratch removal checks the exact resolved task directory and its
ownership marker.

A unique temporary protection tag preserves the prior image during the trial.
The helper's rollback is measured before any outer recovery. Outer recovery
always fails the test even if it restores the image successfully. The protection
tag is removed only after verifying its exact image identity and the restored
main tag. The final assertion compares container/image/volume/network inventory
with the pre-run state; it does not claim Docker BuildKit retains zero cache
bytes. No global prune is used.

The 21 lifecycle assertions cover only this append-drift scenario. Deleted or
unreadable source inputs, an unavailable Docker daemon during cleanup, other
failure timing, production rollout, and broad operational readiness are not
qualified by this test.
