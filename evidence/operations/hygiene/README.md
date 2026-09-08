# Task resource hygiene

The user's disk-hygiene instruction interrupted further builds. All producers
stopped before the scoped cleanup recorded in `20260908T223704Z`.

Removed: 15 task containers, 8 stale task image tags, 3 explicitly recorded unused
task image IDs (plus their unused parents removed by Docker), 4 empty task networks
and 463,715,868 bytes of duplicate workspace scratch. Docker shared image layers
are not additive; this is not a claim that a particular number of physical host
disk bytes was reclaimed from Docker's virtual disk.

Preserved: source, immutable baseline, reports, the original source-build output,
needed pinned source/dependency caches, 6 current image tags, the Core/PostgreSQL
containers, reusable Gradle and Core database volumes. The three retired H2 labs
were stopped and backed up to ignored `.runtime/retired-labs/20260908T223704Z`
before removal. Keycloak's PostgreSQL bind-mounted cluster data remains on disk.
No Docker volumes were deleted. Unrelated projects and shared base images were
outside scope; no global prune, Docker/WSL shutdown, restart or compaction ran.

Both extracted-checkpoint runs' raw logs moved to ignored
`.runtime/retired-proof-logs/20260908T223704Z/<run>/raw-command-logs`. Immutable
historical reports keep their original paths and hashes. The read-only verifier
checks the preserved copies and H2 hashes against those original reports.

`tools/cleanup_checkpoint_resources.ps1` now defaults to audit-only and limits
replay to the originally recorded resource IDs/tags/paths. It is a one-time
checkpoint tool, not a general prune utility. Use PowerShell 7 (`pwsh`); legacy
Windows PowerShell failed to initialize in the recorded first audit attempt.

`tools/qualify_extracted_checkpoint.py` now uses cached builds by default, labels
and names its resources, removes services/images in `finally`, retains hashed
private diagnostics, removes bounded scratch and fails qualification on cleanup
errors. Twelve archive/filesystem tests cover its integrity and actual diagnostic
preservation. The revised full Docker qualification flow has not been rerun;
the earlier 35 application checks apply to their exact recorded wrapper/source
ZIP. No images were rebuilt solely for the cleanup changes.

Read-only checks:

```powershell
python tools/verify_checkpoint_hygiene.py
pwsh -NoProfile -File tools/cleanup_checkpoint_resources.ps1
python tools/qualify_extracted_checkpoint.py --self-test
```

`AGENTS.md` makes this resource lifecycle mandatory for further work. Older probe
runners must be brought under the same cleanup rules before they are run again.
Resource hygiene does not pass any authentication requirement or foundation gate.
