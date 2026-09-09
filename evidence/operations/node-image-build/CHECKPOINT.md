# Offline Node build evidence boundary

`offline-build-02` is the successful full Dockerfile build and installed-image
qualification. Its exact source snapshots, command hashes, original-member
comparison and promotion/cleanup observations are retained. See
`docs/node-offline-build.md` for commands and remaining blockers.

Parent revalidation `evidence-validation-02.json` passes 133 integrity assertions:
current source and captured Git/file bindings, command stream hashes (including
the exact private reset streams), canonical inventories, app/member comparison,
recorded result and cleanup accounting. This does not add authentication tests.
The first validator failed after 125 successful assertions because the transport
report uses `checks`/`passed`, whereas HTTP/browser reports use `rows`/`status`.
`evidence-validator-v1.py` preserves that exact validator source. The corrected
validator reads the actual transport schema explicitly. No authentication lab,
image or successful runtime evidence was rewritten or rerun for that correction.

A separate read-only AI QC lane checked all 25 build bindings, all 24 build logs
and 40 private reset command streams; the prior/candidate dependency arrays and
their canonical hashes matched. Its scoped exact/encoded secret scan covered
106 new public evidence files (8,301,133 bytes), 153 distinct private values and
374 derived variants from this run and Core configuration, with zero matches.
This is a bounded review observation, not a generic secret-scanner guarantee or
the contract's independent human security review. The source ZIP also undergoes
the packager's actual-private-credential check.

The post-promotion compiler report is at
`evidence/operations/node-client-build/promoted-node-01/report.json`.
The obsolete top-level image and its six legacy parents are absent; exact parent
retirement evidence is `evidence/operations/hygiene/legacy-node-intermediates.json`.
The ten-check hygiene report is `verification-20260909T055142Z.json` in that
directory. No physical Windows space-reclamation claim is inferred from image
record sizes or the shared daemon's read-only usage report.

The one-time ZIP retention proof verifies all three exact old archives and every
member before retiring only ae8e3f5502d5, keeping 83daae7876f3 and8bc7ab687c25
and every sidecar/Git commit. A new checkpoint may now be created within the
three-ZIP ceiling. Supplied acceptance archives are outside that scope.
