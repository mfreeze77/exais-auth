# Encrypted recovery reference lab

This is a bounded operational implementation for the current audited-source
candidate. It does not select an engine or close OPS-006 / AT-OPS-006, WP-033,
M9, or the WP-032 dependency. Read the measured run report before relying on a
particular result. No production recovery procedure has been approved.

The first actual run, [`run-01`](../evidence/operations/recovery/run-01/report.json),
passed on2026-09-09. Its28 real-Fernet format tests passed; the HTTP worker
executed20 stages with19 passes, one explicitly characterized historical-state
observation, zero failures and zero unexecuted/skipped stages. The encrypted
archive is249,804bytes, including a186,055-byte actual database dump. All three
restored file hashes match. The restored Core exposes the same two public
signing keys; revoked/deleted refresh tokens returned401 while their original
stored expiration was still about100days away. Deleted-user signin was denied;
the surviving user's new signin, protected access and logout worked.

Backup plus encryption took1.594seconds. Decryption, fresh PostgreSQL startup,
transactional import and Core launch took2.516seconds, excluding Core/application
readiness. The measured drill interval after preflight, including format tests
and cleanup, took20.958seconds; the enclosing command took22.211seconds.
These are measured timings for a12,121,779-byte database on this host, not
production recovery objectives. Both fixture identities were removed and the
source's original52-identity set was restored exactly.

All nine temporary containers retired; before/after image, container, volume
and network inventories match. The source Core/database processes and mounts
did not change. Six duplicate plaintext payload files were removed after
success, leaving264,356bytes of private archive/state/raw evidence plus the
separate44-byte key. Failure/timeout fallback branches have not yet been
runtime fault-injected; a successful cleanup does not certify those branches.

`tools/recovery_bundle.py` encrypts three exact files: `database.pgdump`,
`core-config.yaml`, and `runtime.env`. It uses the already pinned
cryptography50.0.1 Fernet implementation, with an externally supplied random
44-byte key. Its authenticated envelope carries exact names, lengths and SHA-256
values. Decryption authenticates the entire envelope and validates every member
before staging restored files. Existing keys, archives and nonempty destinations
are preserved. Unknown/duplicate members, invalid paths, unexpected schema,
wrong keys and tampering fail closed. Plaintext is limited to32MiB and the
encrypted archive to48MiB; this is a small-database profile.

The [versioned Fernet documentation](https://cryptography.io/en/50.0.1/fernet/)
describes authentication before plaintext is returned and the requirement to
hold the complete message in memory. Its creation timestamp is visible. The
utility does not impose token TTL on backups, derive keys from passwords, or
invent cryptographic primitives. Losing the external key makes that archive
unrecoverable; rerunning key generation cannot repair it.

```text
python tools/recovery_bundle.py keygen --key EXTERNAL_KEY_PATH
python tools/recovery_bundle.py pack --source PRIVATE_THREE_FILE_DIRECTORY --key EXTERNAL_KEY_PATH --archive NEW_ARCHIVE_PATH
python tools/recovery_bundle.py unpack --archive ARCHIVE_PATH --key EXTERNAL_KEY_PATH --destination NEW_RESTORE_DIRECTORY
```

These commands require the pinned Python application's dependencies. Do not
install another dependency environment just to repeat the lab. The wrapper below
uses the existing immutable image and mounts private files only into owned,
temporary clients.

## Real database drill

```powershell
python -B tools/run_recovery_drill.py --name NEW_UNIQUE_NAME
```

The wrapper refuses changed image pins, unexpected source mounts/labels, existing
evidence directories and a database outside the small lab size profile. It uses
the already running private Core/PostgreSQL and cached images; no build, pull,
published port, new network or persistent volume is part of the drill.

Two synthetic users are created through the real Python SDK. After their
sessions work, the wrapper takes a [PostgreSQL custom-format dump](https://www.postgresql.org/docs/17/app-pgdump.html),
encrypts it together with configuration, then revokes one user's sessions and
deletes the other user. A separately named PostgreSQL container receives the
authenticated dump through [pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html)
with one transaction and exit-on-error. Its data directory is a256MiB tmpfs;
the source database is never a restore destination and is never stopped.

The restored Core receives the exact decrypted configuration with only its
PostgreSQL hostname/database name rerouted. The HTTP probe characterizes the old
snapshot's identities/sessions while the restored application is absent, replays
exactly the two owned revoke/delete actions through supported Core APIs, and
only then requests application startup. It checks signing-key continuity and
real credential/session behavior. This explicit replay does not implement a
general journal for all identities, credentials, policies or administrative
changes. A historical-state observation is not counted as acceptable public
recovery behavior.

Every temporary container has a generated name, exact image/CID, project,
purpose and run labels, resource limits and `--rm`. Cleanup checks those
identities before stopping/removing anything. Existing source container IDs,
start times, mounts and configuration hashes must remain unchanged. Before/after
Docker inventories expose any resource delta. No global prune or shared-image
removal is permitted. Known duplicate plaintext payloads are retired only after
successful behavioral cleanup. Failed inputs, encrypted archives, external keys,
private reconciliation state and exact raw outputs remain under ignored
`.runtime/`; public evidence carries sanitized facts and hashes.

The external key lives in `.runtime/recovery-keys/<run>/`, separate from
`.runtime/recovery/<run>/backup.fernet`. These are two paths on the same host,
not proof of off-machine custody, reviewed Windows ACLs or disaster resilience.
Never add either private directory to source control or the delivery ZIP.

## Reuse and unqualified behavior

The [file-specific reuse manifest](../reuse/recovery-components.json) binds the
authored files, exact reused `cryptography/fernet.py`, all three wheel license
texts and the unchanged runtime image IDs. The13 post-run integrity checks in
`evidence-validation.json` verify source/artifact hashes and private-value
exclusion; they are not additional authentication or recovery tests.

| File / reused component | Provenance and boundary |
| --- | --- |
| `tools/recovery_bundle.py` | New orchestration/envelope code; imports maintained `cryptography.fernet.Fernet`, with no copied cipher implementation. |
| `tools/run_recovery_drill.py` | New local operational wrapper; reuses the repository's Docker inventory/hash helpers. No source engine or entitlement code is modified. |
| `tests/operations/recovery_probe.py` | New HTTP probe of the installed Python SDK and supported Core APIs; private test fixtures are not a second identity/session engine. |
| cryptography50.0.1 | Existing locked wheel SHA256 `51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a`; metadata license expression `Apache-2.0 OR BSD-3-Clause`. Actual installed file/notice evidence remains in `evidence/operations/python-offline-build/buildkit-02/distribution/distribution.json`. No new wheel acquired. |
| PostgreSQL17.11 | Existing pinned container provides maintained `pg_dump` and `pg_restore`; no utility binaries copied into this source package. Full container/OS distribution review remains open. |

The format tests use real Fernet to test byte-level roundtrips and rejection;
their small fixture is not a database restoration test. Only the separate live
drill can provide that evidence. Neither proves crash/disk-full atomicity,
hostile concurrent filesystem writers, key rotation/custody, large datasets,
roles/tablespaces/ACL restoration, point-in-time recovery, off-host loss,
backup retention scheduling, provider/native recovery or human security review.
The dump contains one database; this drill precreates its dedicated role and
uses `--no-owner --no-privileges`. Full original acceptance stays open.
