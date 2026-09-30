# Legacy Unicode password migration and on-login rehash

Status: **implemented; source-built scratch lab passes. Not an installed-image,
foundation or production qualification.** Policy `EXPERTAUTH-PASSWORD-UPGRADE-1`.
Resolves the design of the blocked legacy Unicode migration recorded in
`docs/firebase-scrypt-runtime.md` and adds the missing PWD-005 rehash. Every original
requirement, profile and review gate stays binding. `selected_engine` is still null.

## Problem

Before candidate `firebase-bc-02`, Core read JSON without a servlet charset as
ISO-8859-1. An account created with a non-ASCII password therefore has a bcrypt or
argon2 hash of the *Latin-1 reading of the UTF-8 bytes*. The UTF-8 reader correctly
refuses that password. `firebase-legacy-json-01` measured this as a blocked
migration. Imported and outdated hashes were also never upgraded after login.

## Decision (user-selected: dual-verify + rehash)

`engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java`:

1. Verify with the current decoding through Core's unchanged `PasswordHashing`.
2. Only if that fails, and only when **all** of these hold, retry with
   `new String(utf8Bytes, ISO_8859_1)`:
   - `EXPERTAUTH_LEGACY_PASSWORD_DECODING=servlet-iso-8859-1-v1`, the exact value.
     Absent means disabled. Any other value fails closed for every sign-in.
   - `EXPERTAUTH_LEGACY_PASSWORD_HASHES` names a readable file of lowercase
     SHA-256 digests of the stored hash strings captured at cutover. A missing,
     empty or malformed file fails closed for every sign-in.
   - The stored hash is bcrypt/argon2, a format Core itself created from a servlet
     string. Firebase scrypt imports were hashed by Firebase from real bytes and
     are never eligible.
   - The stored hash's digest is in the snapshot.
3. A legacy match always rehashes the correctly decoded password. Any accepted hash
   whose format or cost differs from the configured Core algorithm is also rehashed:
   bcrypt rounds, argon2id m/t/p, argon2i/d to argon2id, or bcrypt to argon2 and
   the reverse. Imported Firebase hashes move to the configured algorithm. A
   `FIREBASE_SCRYPT` target never rehashes because Core cannot create it.

The snapshot is what makes the fallback exact. Without it, a post-cutover account
whose password text happens to be a Latin-1 reading (for example `Ã©…`) would also
accept `é…`, and the rehash would silently change that user's password. With it,
post-cutover hashes are never eligible. A rehashed or reset credential has a new
hash that is not in the snapshot, so eligibility ends by construction. No
upstream table is altered and no schema or marker row is added.

Rehash writes go through the storage plugin's
`EmailPasswordSQLStorage.updateUsersPassword_Transaction`, under `lockUser`, as a
compare-and-replace against the exact verified hash:

- `/expertauth/password/session` (atomic profile): the replacement commits in the
  **same transaction** as the session insert. Any mismatch rejects the operation.
- `/recipe/signin` (upstream route; `tools/patch_password_upgrade.py` changes only the
  verification call): verification decides acceptance. The rehash is a separate
  best-effort locked transaction; if it fails, the old hash remains and the rehash
  is retried on the next sign-in. Lookup, `WRONG_CREDENTIALS`, the Firebase signer
  key error and audit emission stay upstream.

A legacy-era hash also still accepts the historically decoded string directly,
because that is literally the hashed text. This stops once the account is rehashed.

## Operator procedure (not yet qualified on the retained lab)

1. Before starting any UTF-8-reader Core, capture the snapshot read-only:
   `psql -At -c "SELECT password_hash FROM emailpassword_users" | python -c "import sys,hashlib;[print(hashlib.sha256(l.rstrip('\n').encode()).hexdigest()) for l in sys.stdin if l.strip()]" > legacy-password-hashes.txt`
   Treat this file as sensitive. Mount it read-only.
2. Build: `tools/build_password_session.py --name NEW --candidate-from firebase-bc-02 --firebase-scrypt-bc --password-upgrade`.
3. Start Core with both variables set. Leave them set until the non-rehashed
   population is acceptable, then unset `EXPERTAUTH_LEGACY_PASSWORD_DECODING`. The
   remaining legacy Unicode accounts then need the existing reset flow.

## Evidence

- `evidence/operations/password-upgrade/unit-01/report.json`: 27/27 decision checks
  with the real jbcrypt 0.4 and argon2-jvm 2.11 libraries Core uses.
- `evidence/operations/password-upgrade/cloud-source-01/report.json`: **20/20** real
  cases, 30 HTTP requests. Built by `tools/run_password_upgrade_lab.py` from pinned
  Core/plugin-interface/PostgreSQL-plugin checkouts. Core is compiled with AspectJ
  1.9.24 as upstream does. All 84 third-party JARs match
  `engine-extensions/oss-build/locks/gradle/verification-metadata.xml`. Upstream
  prebuilt SuperTokens JARs, EE code and telemetry binaries are excluded, and the
  patched sources come from the same `patched_source` function as the real
  builder. PostgreSQL 17.11 runs on an `--internal` network. An unpatched
  source-built Core creates the legacy population, and the candidate then runs in
  five configurations. Cases: legacy reader behavior; disabled default reproduces
  the block and changes nothing; bad value and missing snapshot fail closed;
  wrong Unicode refused; legacy bcrypt/argon2 accepted and rehashed; the historical
  string refused after rehash; atomic session accepts and rehashes in one commit;
  same-target ASCII untouched; post-cutover alias refused; bcrypt to argon2 on
  login; untouched accounts stay legacy. All 8 owned containers and the network
  were removed; no volume or image was built.
- `tests/evidence/test_password_upgrade_patch.py`: 4 source-transform guard tests.

## Limits (all remain open)

- Scratch lab on a fresh cloud checkout. It is not the retained Windows lab,
  installed Core `b4a5f18fb782`, the source-built Argon2 library or BC 1.85.2. The
  lab uses the image-locked BC 1.84, the bundled argon2-jvm native library and the
  pinned `gradle@sha256:67b8c4…` JRE pulled via `mirror.gcr.io`. Firebase rows were
  not re-run.
- The candidate is not built through `tools/build_password_session.py`. That needs
  the retained `.cache` and compiler volume. No installed image, upgrade/rollback,
  two-replica concurrency on the rehash, Node/Python/browser regression, or
  snapshot capture against the persistent database has been run.
- Failed verification with a non-ASCII password costs a second hash computation on
  eligible accounts. This reveals nothing beyond the attacker's own input, but it
  should be reviewed alongside SMTP/known-user timing.
- Rehash on the upstream route is best-effort by design, not atomic with the response.
- The snapshot is read once per Core process; changing it requires a restart.
- Rehash transactions run at the plugin's SERIALIZABLE default. Two concurrent
  first logins on one legacy account can conflict. `/recipe/signin` absorbs the
  conflict, but the atomic route may reject one attempt; a retry succeeds. This is
  reasoned from the plugin source, not yet measured.
- Independent human security review, MIG-002 import matrix, full hash/parameter
  bounds and every SDK/platform/provider profile remain required.
