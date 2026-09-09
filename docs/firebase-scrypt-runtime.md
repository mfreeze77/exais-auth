# Firebase verification checkpoint and pause

Status: **PARTIAL; paused at the user's request. Not production approved.**
The current local candidate is Core
`sha256:b4a5f18fb78223e72f83ec17ea08487ce1e476fff25a74c388c7726f3db9a8f9`,
compiled pair `firebase-bc-02`; Node remains `2a02e08d5fcb`.
The foundation is still undecided. All original requirements and profiles remain
binding; no complete acceptance row is newly verified.

Firebase imported-password verification now uses Bouncy Castle scrypt, UTF-8
password bytes, an explicit default UTF-8 JSON reader, pre-shift parameter checks,
and JDK constant-time digest comparison. Credentials and sessions remain owned by
Core. No cryptographic primitive or entitlement enforcement was reimplemented.
The installed provider is BC 1.85.2; BC utility and PKIX are 1.85. The archived
lambdaworks scrypt dependency is removed from the installed image after a scan
found no remaining class references. Original audited artifacts stay in the cache.

Measured behavior and compatibility:

- `evidence/operations/atomic-reset/image-firebase-firebase-01/` passes 12 narrow
  Firebase rows and 110 real requests using two installed candidates. Independent
  Node/OpenSSL fixtures cover ASCII and Unicode imports, wrong passwords, malformed
  import and bounded invalid costs, atomic password/session creation, reset from
  both replicas and eight concurrent distinct owners. All 16 owned users retire.
- `evidence/operations/atomic-reset/firebase-legacy-json-01/` passes the same 12
  candidate rows with 115 requests against the current candidate and the historical
  Core. The old peer explicitly mounts its original scrypt JAR. All 17 users and
  six helpers retire. Actual old-peer Unicode false acceptance and Java shift-cost
  alias acceptance are preserved as security failures, not accepted behavior.
- **Legacy Unicode migration is BLOCKED.** A real BCRYPT account created through
  the old reader accepts its raw UTF-8 password on that reader, rejects the same
  password on the new reader, and accepts the historically decoded character string
  on the new reader. `legacy_json_migration.authentication_acceptance_pass` is false.
  The report's top-level pass concerns the 12 candidate rows only. An explicit
  migration/reset policy and full rolling-upgrade qualification are still needed.
- The installed image also passes seven native startup cases, ten native password/
  import/reset/concurrency cases plus cleanup, 16 Core atomic cases, 34 installed
  Node/SMTP/TLS/React behavior checks, 12 refresh-grace cases, eight guarded session
  cases plus cleanup, and 14 actual local upgrade/rollback phases. Main evidence:
  `evidence/operations/atomic-core-image/firebase-01/report.json`. It verifies 559
  installed files, 85 JARs and 86 SBOM components. PostgreSQL, configuration, schema
  and the original identity set survive the bounded local replacement.
- The source-built Argon2 profile remains installed, including its 68 original
  source/build/notice files. Imported hashes still do not automatically rehash on
  successful login. PWD-005, MIG-002, complete parameter/resource bounds, every
  hash/JSON/platform/profile, and independent security review remain unqualified.

The first source candidate failed literal Unicode tests because the servlet reader
used its historical default charset; its source, failure and diagnosis are retained
under `firebase-bc-source-01`. Candidate 02 fixes that cause and passes. Acquisition
also preserves a failed container-root path calculation before the corrected run.
No failure was erased or counted as implementation.

File-specific reuse and license disposition:

| File/component | Origin and treatment | Evidence / remaining limit |
| --- | --- | --- |
| Core `emailpassword/PasswordHashingUtils.java` | Audited Apache-2.0 Core 12.2.0 source; original headers retained, modification notice added; BC call, encoding, bounds and comparison changed | `tools/patch_firebase_scrypt.py`; exact original and candidate source/JAR hashes in `evidence/operations/password-session-build/firebase-bc-02/` |
| Core `webserver/InputParser.java` | Same audited Apache source; default UTF-8 set only when charset is absent; explicit charset retained | Same transform and source snapshots; legacy migration blocked above |
| `bcprov-jdk18on-1.85.2.jar` | Unchanged published Maven JAR, Bouncy Castle license | SHA-256 `986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5` |
| `bcutil-jdk18on-1.85.jar` | Unchanged published Maven JAR, Bouncy Castle license | SHA-256 `590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d` |
| `bcpkix-jdk18on-1.85.jar` | Unchanged published Maven JAR, Bouncy Castle license | SHA-256 `c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996` |
| Each versioned BC `org/bouncycastle/LICENSE.java`, source POM; provider `crypto/generators/SCrypt.java` | Unchanged source-archive members copied into the installed notices/source map | `tools/install_bouncycastle.py`, installed notice manifest; full source archives remain in the bounded local cache |
| `tests/foundation/firebase-fixtures.mjs`, `FirebaseScryptProbe.java` | Original test glue; independent Node/OpenSSL fixtures and real Core/JDBC probes | Synthetic public signer only; not live Firebase-provider acceptance or an independent review |

Acquisition records, three POMs and source-archive SHA-256 pins are in
`evidence/reuse/bouncycastle/runtime-1852-02/`; hard pins are enforced by
`tools/install_bouncycastle.py`. Provider source SHA is
`b37ac84b1d5435ab7b8d166c16ab9f75e09f68f8ec50479bae433939b241b03f`,
utility source `b470a692878f92abf00b9c3af9147a45453250a80930df8f23f1d092c55e2d5e`,
PKIX source `e5331f467331aba29bda6ddfb0df0da6d568928e29c2b0f20ea2fe123d802d20`.
The source archives are excluded from checkpoint ZIPs as dependency caches.
This is file correspondence and notice evidence, not full legal/source/relink or
vulnerability closure. Existing JNA, SQLite, OS, SDK and human-review blockers stand.
Official source context: [BC downloads](https://www.bouncycastle.org/download/bouncy-castle-java/),
[archived prior scrypt project](https://github.com/wg/scrypt), and
[JSON interchange encoding](https://www.rfc-editor.org/rfc/rfc8259.html#section-8.1).

The main image report binds the exact builder/probe snapshots used at installation.
Later harness changes add the historical dependency mount and the blocked migration
observation; their exact current bytes are bound by `firebase-legacy-json-01`.
A later builder fix selects the actual retained native peer JARs for a runtime-only
rebuild; `evidence/operations/bouncycastle-installation/native-reference-preflight.stdout`
records its successful read-only preflight against the current image. These later
tool changes did not rebuild the already qualified runtime.

Resume from the existing workspace (do not rerun unchanged passing labs for dates):

```powershell
Set-Location 'C:\Users\mfrie\Ai_Projects\exai auth\expert-auth'
git status --short
python -B tools/ledger.py check
python -B tools/capture_contracts.py --validate
python -B tools/validate_release.py --claims-only
python -B tools/verify_checkpoint_hygiene.py
python -B tools/build_atomic_core_runtime.py --name resume-reference --session-build firebase-bc-02 --verify-native-reference-only
```

Next bounded implementation: design and test the explicit legacy Unicode migration/
reset boundary before treating this reader change as broadly deployable; automatic
rehash remains another open dependency-ready item. Preserve one engine and all
original namespace/linking/licensing gates. Do not retry the rejected identity action.
For a future changed source candidate use a new name with
`tools/build_password_session.py --name NEW --candidate-from firebase-bc-02 --firebase-scrypt-bc`.
For its installed qualification use
`tools/build_atomic_core_runtime.py --name NEW --session-build NEW --native-argon2-build linux-03 --qualify-refresh-grace --qualify-guarded-sessions`.
These are local mutation commands, not necessary to resume reading the checkpoint.
Fresh-host complete bootstrap remains unqualified. Historical `guarded-01` candidate
JARs and the superseded image have been retired; their original source/evidence remain.
No implementation package should start until the user resumes work.
