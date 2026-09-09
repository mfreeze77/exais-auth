# Python readiness outage and image proof

OPS-004 and OPS-011 have a real representative correction, not full acceptance.
The old Python route tested only Core protocol advertisement. A warmed Core can
advertise its versions while PostgreSQL is unavailable, so that route falsely
returned200. The current app also requires an authenticated exact `/users/count`
query with CDI5.4, checking the response type/status before returning readiness.
No approximate count cache is used. A four-second total budget and three-second
HTTP timeout bound each request; success and failure prohibit caching. Failure
returns503 with generic text while `/live` remains process-only.

The authoritative before/after proof is `run-03`, using Python image
`sha256:7a4bb6dcfd634a98f603d65bc2c1219fef5b3a46a00be705631201c4f78802f1`
and source-built Core image
`sha256:60c7677d0a9152ff4e854ab21e95df0b1aa50ed0e534ed480608d9b84bae0e58`.
Its exact six checks, with zero failures/skips, include one cleanup check:

| Observation | Actual result |
|---|---|
| Healthy baseline/current/storage | HTTP200 |
| Password signup and online session before outage | Passed |
| Database stopped, Core protocol / old readiness | HTTP200 / HTTP200 |
| Database stopped, current readiness / liveness | HTTP503 in3011.14ms / HTTP200 |
| Database restarted with same container/volume | Current readiness503 then200;6117.52ms after host pg_isready |
| Existing session after recovery | Refresh200, online200, logout200, subsequent refresh401 |
| Synthetic identity cleanup | One created, one removed |

The host controller first checked the exact owned database ID, pinned image,
named volume and isolated network consumers. It created a184,149-byte private
pg_dump, retained under `.runtime/python-readiness/run-03/`, then stopped and
restarted that same database. Its report records the dump hash and explicitly
states `restore_tested: false`. Both probe and host have restoration paths.
The host verifies restoration and container cleanup before claiming success.
Core-a was not restarted. Database restart time changed intentionally.

All three temporary containers were removed with exact ID and project/purpose
label checks. Before/after inventories show zero changes in containers, images,
volumes and networks. Temporary credentials, CID files and baseline source were
removed; only the small private dump remains. No ports were published.

`image-02` separately built the app with `--pull=false --network=none`, proved
all base/dependency filesystem layers unchanged, checked installed app/lock hashes
without a source overlay, and passed19 actual HTTP regression checks. Both of
its synthetic users and two temporary containers were removed. It retired the
obsolete `9ff0be83fb3d` Python image. The current image is the sole retained tag
for this component. Current-image regression with the corrected probe is image-06:
19/19 passed with two users removed, zero resource delta and no image build.
The source-drift rollback case is tested separately in `../python-image-lifecycle`.

`run-01` is the earlier six-check source-overlay proof. It used the old image
as the baseline, which would not remain reproducible after image retirement.
The corrected runner reconstructs only the historical app from Git commit
`fefb9daa2d1da99e5aebbffe10a4785f183153da`, verifies SHA256
`9be27ff8b94665acfa1721ba8011103569caa055dd5f0b1428d0cd3704ee191b`,
and overlays it read-only on the same current dependency image. This correction
is qualified by run-03. The exact original runner is preserved under
`run-01/inputs/tools/run_python_readiness.py`; its old report was not rewritten.
The two private dumps together total367,902 bytes. Numeric names distinguish the
source-overlay runs from intervening image/regression attempts; every attempt is
preserved below.

Review found an auxiliary probe signout exception could bypass user cleanup and
that image retirement preceded the final input-stability check. The probe now
cleans up in `finally` and records a failed/incomplete result after a transport
exception. `../python-probe-cleanup-fault/run-02` actually drops that connection:
the child exits1 with seven unexecuted checks, removes its one user and preserves
52 existing identities. Four outer assertions qualify cleanup only. Its initial
pagination-bound failure and exact prior fault sources are preserved in run-01.

Image-04 attempted to rebuild unchanged code while qualifying these harness
changes. The legacy dependency-stage cache metadata was missing, and offline pip
execution failed. Its exact new stopped intermediate, command, creation time
and lock hash were verified before removal. The old wrapper discarded build
stderr, and the daemon's logging driver cannot recover it; that missing evidence
is explicit in `image-04/failure-diagnosis-and-retirement.json`. No pip-error text
was fabricated. Image-05 added persistent failure output and an explicit cache
source, but Docker failed to restore its cached image with
`failed to read diff archive: InvalidArgument`. That failed run added no resources.
The full offline rebuild path remains blocked and was not retried unchanged.

Current `--test-existing` mode avoids a rebuild for harness-only changes. The
build branch retains exact failure output and uses Docker's documented
[`--force-rm`](https://docs.docker.com/reference/cli/docker/image/build/) to retire
intermediate containers. Input stability and container retirement now precede
image promotion/old-image removal. The real source-drift trial uses a distinct
image configuration with identical filesystem layers, then changes only an
isolated ignore file. All19 HTTP checks pass, but the helper correctly exits1,
restores the prior tag and removes the trial image without outer compensation.
Its21 lifecycle assertions do not qualify the failed full-source rebuild path.
Exact older helper/probe bytes are preserved beneath image-02/image-04/image-05;
immutable reports are never rewritten to match newer source.

Reproduce from a restored Git checkout, with cached images and only the owned
Core-a/PostgreSQL lab on `expertauth-oss-proof`:

```powershell
python tools/run_python_readiness.py --name NEW_UNIQUE_OUTAGE_NAME
python tools/verify_checkpoint_hygiene.py
```

Do not run this against production or a shared dependency network. The helper
requires the private lab and deliberately interrupts its database. The complete
launch/build prerequisites are in the root and Python READMEs. The refresh helper
reuses cached unchanged dependencies and is not a dependency-upgrade mechanism.

No test here proves proxy traffic removal, readiness load capacity, other
dependency failure classes, abrupt database crash recovery, replication/HA,
transaction-internal failure, backup restore, migrations, complete SDK/platform
scope or independent security approval. All original requirement/API/profile IDs
and milestones remain binding. No engine is selected by this proof.
