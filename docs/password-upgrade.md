# Password import validation and on-login rehash

Status: **implemented; source-built scratch lab passes. Not an installed-image,
foundation or production qualification.** Policy `EXPERTAUTH-PASSWORD-UPGRADE-2`.
Adds the missing PWD-005 rehash and closes an upstream MIG-002 import gap. Every
original requirement, profile and review gate stays binding. `selected_engine` is still null.

## Scope decision (2026-09-30)

The user confirmed ExpertAuth is **not live**. No account was ever created by the
historical ISO-8859-1 JSON reader, so the "legacy Unicode migration" blocked in
`docs/firebase-scrypt-runtime.md` has no population and is closed by scope. UTF-8 is the
only supported password decoding. The opt-in legacy-decoding fallback built earlier
the same day (policy `-1`, runs `cloud-source-01`/`-02`) was removed rather than kept
as unused attack surface. Its evidence stays as history. If a deployment ever inherits
old-reader accounts, the answer is the existing reset flow, not a second decoding.

## Behavior

`engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java`, applied to
upstream `EmailPassword.java` by `tools/patch_password_upgrade.py`:

- **Rehash on login (PWD-005).** Verification uses Core's unchanged `PasswordHashing`.
  An accepted hash whose format or cost differs from the configured Core algorithm is
  rehashed. That covers imported bcrypt/argon2/Firebase scrypt, changed bcrypt rounds,
  changed argon2id m/t/p, argon2i/d to argon2id, and bcrypt to argon2 and the reverse.
  A `FIREBASE_SCRYPT` target never rehashes because Core cannot create it. Writes use
  `EmailPasswordSQLStorage.updateUsersPassword_Transaction` under `lockUser` as a
  compare-and-replace against the exact verified hash.
  - `/expertauth/password/session`: the rehash commits in the **same transaction** as
    the session. If a concurrent login already rehashed, the attempt fails with
    `HashChanged` and is retried **once**. The retry re-reads the user and re-verifies
    the password against the new hash, so a concurrent reset to a different password
    still rejects.
  - `/recipe/signin`: acceptance follows verification. The rehash is a best-effort
    locked transaction and is retried on the next login if it fails.
- **Import validation (MIG-002).** Upstream accepts any string with a known prefix
  (`$2a$10$short` imports and can never sign in). It also accepts unbounded costs, so
  one imported record can make every login attempt on that account a
  memory/CPU sink. After the unchanged upstream check, single-user import
  (`EmailPassword`) and bulk-import add (`BulkImportUserUtils`) now require full
  structure and bounded cost. Otherwise they report
  `Password hash is malformed or exceeds import cost bounds` (400; per-user for bulk):
  - bcrypt `$2[abxy]$` with a 53-character bcrypt-alphabet body; cost 4–16;
  - argon2 `id|i|d`, `v=16|19`, m ≥ 8·p and ≤ 1 GiB, t 1–100, p 1–64, base64 salt/hash;
  - Firebase `$f_scrypt$<hash>$<salt>$m=$r=$s=` in that order, decodable base64,
    m 1–17, r 1–32.

  These bounds are policy constants for review, not upstream values. Core-created
  hashes are not subject to them, so an operator's own `bcrypt_log_rounds` is unaffected.
- `--password-upgrade` in `tools/build_password_session.py` requires `--firebase-scrypt-bc`,
  so the UTF-8 reader is always present.

## Evidence

- `evidence/operations/password-upgrade/cloud-source-05/report.json`: **72/72** real
  cases, 102 HTTP requests, built by `tools/run_password_upgrade_lab.py` from pinned
  Core/plugin-interface/PostgreSQL-plugin checkouts. Core is compiled with AspectJ
  1.9.24 as upstream does. All 84 third-party JARs match the reviewed Gradle
  verification metadata. Upstream prebuilt SuperTokens JARs, EE code and telemetry
  binaries are excluded. The patched sources come from the builder's own
  `patched_source`. PostgreSQL 17.11 runs on an `--internal` network with a
  configured Firebase signer key. The cases:
  - **Decoding:** UTF-8 signup/signin with and without an explicit charset; the
    Latin-1 reading of the password is refused; a wrong password is refused and
    changes nothing; a same-target hash is left unchanged.
  - **Import matrix:** seven fixtures made by *independent* libraries (Python
    bcrypt 5.0.0: `$2b$`/`$2a$` cost 12/`$2y$`; argon2-cffi 25.1.0: argon2id/i/d at
    m=19456,t=2,p=1; and hashlib scrypt with cryptography 50.0.2 AES-CTR for Firebase
    m=14,r=8). Each imports, refuses a wrong password without change, accepts the
    Unicode password, rehashes to `$2a$11$`, and stays stable.
  - **Atomic session route:** three fixtures rehash in the same commit as exactly
    one session; wrong passwords create no session.
  - **Rejected imports:** 8 unsupported or mismatched imports (md5, sha512-crypt,
    Django pbkdf2, plaintext, passlib scrypt, declared-algorithm mismatches, unknown
    algorithm) report 400. 9 malformed or over-cost imports report 400.
  - **Bulk import:** bulk-import add accepts bcrypt/argon2id/Firebase fixtures. It
    reports four prefix-valid but malformed or over-cost hashes that only the added
    bound catches.
  - **ARGON2 target:** imported bcrypt/argon2id/argon2i/Firebase and native bcrypt
    accounts move to `$argon2id$v=19$m=87795,t=1,p=2`; new argon2 accounts are not
    rehashed.
  - **Two replicas:** 8 concurrent first logins per route. `/recipe/signin` accepts
    8/8 with one final hash; the atomic route accepts 8/8 with exactly 8 sessions
    and one final hash.
  - **No hash exposure:** none of the 102 response bodies, bulk add included,
    contains a hash marker or hash field.
  - **Cleanup:** all containers, the network and the scratch were removed;
    measured `volumes_left: []`.
- `evidence/operations/password-upgrade/unit-02/report.json`: 31/31 rehash-decision
  and structure-bound checks with jbcrypt 0.4 and argon2-jvm 2.11.
- `tests/evidence/test_password_upgrade_patch.py`: 7 transform/guard tests, including
  no remaining alternate decoding.
- History:
  - `cloud-source-04` passed the same cases before bulk-import validation existed
    (65/65).
  - `cloud-source-03` (policy `-2` before these fixes) passed 56 cases but measured
    the problems fixed here. Only 1 of 8 concurrent atomic logins succeeded (the
    other 7 got `PASSWORD_SESSION_REJECTED` after the first rehash), and malformed
    prefixed hashes imported with HTTP 200.
  - `cloud-source-01`/`-02` and `unit-01` are the removed policy `-1`. Run 01's
    volume-cleanup misstatement is corrected in its `CORRECTION.md`.

## Limits (all remain open)

- Scratch lab on a fresh cloud checkout, not the retained Windows lab, installed Core
  `b4a5f18fb782`, the source-built Argon2 library or BC 1.85.2. The lab uses the
  image-locked BC 1.84, the bundled argon2-jvm native library and the pinned
  `gradle@sha256:67b8c4…` JRE via `mirror.gcr.io`. The candidate was not built through
  `tools/build_password_session.py`, which needs the retained `.cache` and compiler
  volume. No installed image, upgrade/rollback or Node/Python/browser regression.
- Bulk-import *processing* (Core's asynchronous cron that creates the users) was not
  exercised; only add-time validation was.
- The concurrent reset-versus-retry path is argued from the code; it was not
  injected deterministically.
- Rehash on the upstream route is best-effort by design. The import cost bounds are
  unreviewed policy. Independent human security review and every SDK/platform/provider
  profile remain required.
