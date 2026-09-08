# ExpertAuth

Active implementation of the supplied full-parity contract. **Partial foundation
checkpoint; not a production authentication release.** Read `PROJECT_STATE.md` for
measured behavior and `BLOCKERS.md` for outstanding gates. No requirement was removed.

The immutable acceptance baseline lives under `baseline/`; editable traceability is
`ledger/implementation.json`. Engine selection is pending in ADR-001. Source, builds,
real API tests and license evidence are retained separately from plan integrity tests.

## Reproduce the source-built alternative lab

Requirements: Docker Linux containers and Python3.11+ on the host. The recipe keeps
Core and PostgreSQL off public ports. Build-time internet access downloads pinned
permitted sources/dependencies; the running lab network has no external egress.

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tools/fetch_pinned_sources.py
python tools/build_oss_core.py
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

The Node/React and Python representative applications are under `examples/`. They
exercise the audited-source candidate; they are not evidence that Keycloak already
implements their FDI/CDI contracts. Deployment, migrations, native SDKs and all remaining
business workflows will be delivered through the selected foundation after the gate.

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
