# Password reset evidence checkpoint

Run-16 is the successful combined source-mounted candidate lab. Its exact older
runner and worker are retained beside the report; current product hashes match.
Cleanup-fault-01 binds the subsequent runner/worker changes and deliberately
preserves `passed: false` for exit73, with the separate cleanup assertion true.
The parent rechecked32 source bindings and56 private command-stream hashes in
`evidence-validation.json`. Independent AI review checked private-value redaction
and the two success screenshots; this is not the required human review.

Current ledger:265 requirements (23 implemented-unverified,10 blocked,7 failed,
225 planned,0 verified),205 APIs,8 SDKs,14 plugins,10 integrations,11 milestones
and36 work packages. All original IDs remain. The full release validator exits1
with557 blocking issues, as required for this partial state. See
`evidence/runs/password-reset-release-gate-01` for actual output and input hashes.

Hygiene verification `../hygiene/verification-20260909T050303Z.json` passes10 checks.
Only Core-a/PostgreSQL remain; six current task image tags and zero dangling
project-labeled images. The sole new test image is pinned Mailpit1.31.1
(17,164,101 image-record bytes). No reset run retained a new network, volume or
published port. Private failed-run fixtures/logs occupy403,130 logical bytes
across707 small files; retained public reset evidence occupies978,798 bytes
before this note. These bounded records preserve failure evidence, not duplicate
dependency trees. Docker shared image layers are not counted as freed host space.

The read-only daemon-wide `docker system df` observation reported152 images,
59 containers,261 volumes and8.84GB build cache. These include unrelated projects
and shared resources; their aggregate "reclaimable" values are not authorization
or proof that they can be safely deleted. No global prune, volume deletion,
Docker/WSL restart or disk compaction was performed.

The oldest generated source ZIP was verified against every manifest member,
CRC, SHA-256, sidecars and Git ancestry, then retired by exact path:12,715,973
logical bytes. Two newer validated ZIPs were preserved before creating the next
checkpoint. All sidecars and source history remain. Automatic approval review
separately rejected the95-file,277,260-byte host Node compile-cache deletion with
only "blocked by policy"; that cache remains ignored locally. The exact inventory
is in `../hygiene/password-reset-host-cache-blocked.json`. No alternate deletion
was attempted, and it is excluded from the ZIP.

The one-off parent evidence verifier initially assumed command streams carried
a path field. They are actually numbered `command-NNN.stdout/stderr` under each
private run directory. Correcting that reader yielded56 exact byte/hash matches;
no live test, report or acceptance check was changed to produce this result.
