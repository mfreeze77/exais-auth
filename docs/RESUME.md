# Resume the partial implementation

Work in `expert-auth`. Read `PROJECT_STATE.md`, `BLOCKERS.md`, ADR-001 and the
original kickoff before changing engine ownership or acceptance status. Every
baseline requirement, API ID and profile remains binding. The original ZIP is
missing; all20 extracted manifest files match their original bytes and checksums.

This checkpoint has no selected production engine. Do not start feature work that
silently assumes Keycloak acceptance, patch Core entitlement enforcement, duplicate
refresh state in adapters, or directly modify upstream-owned tables.

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
python tools/launch_oss_probe.py
```

The launcher retains owned PostgreSQL data/containers, checks private network
isolation and storage on both replicas, and publishes no ports. Host networking
was broken through Windows/PowerShell; Docker Linux networking worked. No global
network/security settings were changed. Build tools require Docker, Python3.11+
and disk/RAM for the pinned Java/Node/Python images. `.runtime/` secrets are local
only. Do not copy them into a release or use these synthetic credentials elsewhere.

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
