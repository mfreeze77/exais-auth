# Verified runtime notice image

The current local Core image is
`sha256:60c7677d0a9152ff4e854ab21e95df0b1aa50ed0e534ed480608d9b84bae0e58`.
`preserved-notices-01/report.json` records474 exact installed file hashes, including
all87 JARs. It also records the build source/lock hashes, installed notice manifest,
cached build log and inspection commands. No source archives were duplicated into
the image; all83 available siblings were verified from the bounded cache.

The source notice assembler preserves87 actual embedded notice texts and5
supplemental scrypt/libffi notices. Eight tests passed with Python optimization
enabled, including corrupted-archive/lock/origin rejection, actual byte preservation
and duplicate assembly with identical manifests. The original88-count failure is
retained and explained in `docs/test-corrections.md`.

`replacement-20260908T232129Z-99cdc5/report.json` records the live local replacement
after comparing all87 old/new executable JAR hashes. Authenticated storage readiness
passed before and after. Configuration bytes and the PostgreSQL container were
preserved. The old Core container/logs were held for rollback until readiness; its
logs remain privately under `.runtime/retired-core-logs`. The old container/image
were then removed. Rollback recovery was not exercised, and no complete auth suite
or migration was rerun for this notice-only image change.

The first preflight refusal in `replacement-20260908T231951Z-d2ca53` made no runtime
mutation. It detected the Gradle base's inherited anonymous cache volume. The
corrected path uses bounded16MiB tmpfs for that unused destination. The two former
Gradle volumes were retained after nonempty inspection; their8 files each total
385,398 bytes combined. No database or other data volume was removed.

Subsequent review made all maintenance exceptions force a failed verdict, including
cleanup errors after successful readiness. The current script's already-current
image guard was exercised: it exited1 before mutation and preserved the exact
running container/image. See `same-image-guard-verification.json` and the associated
command evidence. This negative check does not qualify the unexecuted rollback path.

The build/inspection container and context were retired automatically. Resource
verification again found2 task containers and6 task image tags, with all9 hygiene
checks passed (`evidence/runs/runtime-notice-hygiene-01`). The full distribution,
foundation, authentication and production gates remain unqualified. Read
`docs/runtime-distribution-review.md` for the exact native and licensing gaps.
