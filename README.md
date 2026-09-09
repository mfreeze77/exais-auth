# ExpertAuth

Active implementation of the supplied full-parity contract. **Partial foundation
checkpoint; not a production authentication release.** Read `PROJECT_STATE.md` for
measured behavior and `BLOCKERS.md` for outstanding gates. No requirement was removed.

The immutable acceptance baseline lives under `baseline/`; editable traceability is
`ledger/implementation.json`. Engine selection is pending in ADR-001. Source, builds,
real API tests and license evidence are retained separately from plan integrity tests.

## Reproduce the source-built alternative lab

The latest [session policy candidate](docs/session-refresh-grace.md) installs an
explicit Node CDI5.6 adaptation with real grace/replay, transaction-abort and
four-tab browser evidence. It keeps the original failed profiles and full
foundation gates open. Use its current image pins and qualification commands.

The current candidate is documented in [installed Core qualification](docs/installed-atomic-core.md).
Both Core and Node contain their current atomic integration; local upgrade and
rollback pass. Use those current commands for an existing lab. The original
bootstrap sequence below is historical and must not be used as an in-place
replacement of the atomic runtime. Full clean-host bootstrap remains unqualified.

Requirements: Docker Linux containers and Python3.11+ on the host. The recipe keeps
Core and PostgreSQL off public ports. Build-time internet access downloads pinned
permitted sources/dependencies; the running lab network has no external egress.

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tools/fetch_pinned_sources.py
python tools/build_oss_core.py
docker run --rm --label org.expertauth.project=expert-auth -v "${PWD}:/workspace" -w /workspace python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tools/fetch_runtime_notice_sources.py
python tools/launch_oss_probe.py
```

The launcher creates local synthetic secrets under ignored `.runtime/`; never include
that directory in an archive. Source fetch validates archive and file hashes before
using them. It excludes every `ee/` member; the builder also excludes checked-in binary
artifacts. Supported telemetry still needs its separately audited source/artifact path.
The launcher starts both replicas sequentially and checks authenticated storage
readiness. Existing owned containers and data are preserved. Normal builds consume
reviewed Gradle locks and checksum metadata; use `--clean --evidence-name NEW_NAME`
for a new build directory and separate evidence. The recorded clean rebuild matched
all87 original JAR hashes.

The cleanup checkpoint leaves only Core-a/PostgreSQL running. Other candidate and
example containers were retired with database/log backups. Read `AGENTS.md` before
starting labs; inspect resources, reuse cached builds and remove temporary resources
after tests. The cleanup evidence is under `evidence/operations/hygiene`.

The bounded [encrypted recovery drill](docs/encrypted-recovery.md) uses those
cached images to restore a real database/configuration backup into temporary
storage. Its two-action security reconciliation and measured results remain
distinct from full recovery acceptance. The hygiene verifier now also requires
zero dangling project-labeled images.

The [password reset example](docs/password-reset.md) now completes real React
recovery through self-hosted authenticated TLS SMTP. Its combined proof passes
10 transport, 11 HTTP/SMTP and 9 browser checks; a forced worker crash also
qualifies exact owned-account/container cleanup. Full PWD-006, configured tenant
isolation and durable delivery remain unqualified. The complete Node Dockerfile
now builds offline and its installed image passes those reset checks. The
[build report](docs/node-offline-build.md) records package correspondence,
old-image retirement and the remaining fresh-stack/distribution gaps.
[Locked archive acquisition](docs/node-package-bootstrap.md) now passes actual
fresh registry and disconnected install/compile tests using one bounded cache;
its temporary container is removed after verification.

The opt-in [atomic reset adaptation](docs/atomic-password-reset.md) now commits
token consumption, password change and existing-session deletion in one Core
transaction. Eight real Core cases and32 Node/SMTP/React cases pass, including
database abort/retry and legacy-token reissue. That historical run used explicit
source/JAR mounts and created no new image. Full foundation, migration and security-review
acceptance remain open. The later [password-session adaptation](docs/password-session-transactions.md)
closes the demonstrated race for the explicit Node password profile:16 Core
cases and33 HTTP/SMTP/browser cases pass, with actual wire and cleanup evidence.
The latest [installed Node profile](docs/atomic-node-installation.md) passes
34 behavior checks, including missing-storage-writer denial and recovery. Its
new image replaces the prior Node image. The subsequent
[installed Core qualification](docs/installed-atomic-core.md) removes the healthy
Core JAR mounts and proves a bounded local upgrade, rollback and re-upgrade.

The current Core image includes the verified notice package described in
`docs/runtime-image-notices.md`. Use the launcher's `--build-only` option for image
inspection without starting services. Native and full distribution licensing remain
unqualified in `docs/runtime-distribution-review.md`.

The Node/React and Python representative applications are under `examples/`. They
exercise the audited-source candidate; they are not evidence that Keycloak already
implements their FDI/CDI contracts. Deployment, migrations, native SDKs and all remaining
business workflows will be delivered through the selected foundation after the gate.

The latest session proof runs the unchanged Node/React application through two
Core replicas:10 SDK and3 browser checks passed, while uncoordinated raw-header
availability remains failed. Real lost-response, abrupt-restart and four-tab
refresh/logout behavior is recorded in `evidence/foundation/sdk-session-faults`.
The runner reuses cached images and removes all its temporary resources.

Python readiness now checks authenticated storage as well as Core protocol support.
A real PostgreSQL outage/recovery proof passes6 checks, including cleanup, and the
current image passes19 HTTP regression checks. The obsolete Python image was
removed; no new dependency layers, volumes or networks were retained. Reproduction
and the operational limits are in `evidence/operations/python-readiness/README.md`.

## Validate integrity and completion separately

```powershell
python tools/ledger.py check
python tools/capture_contracts.py --validate
python -m unittest discover -s tests/evidence -v
python tools/validate_release.py
```

The completion command must fail while requirements, contracts, profiles, current
evidence or independent review remain unqualified. Test names/counts and successful
container startup never close an authentication requirement on their own.

No remote repository, package publication, paid service or production change has been
performed. Existing unrelated containers and files are preserved.
