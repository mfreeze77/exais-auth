# Installed source-built Argon2 checkpoint

PARTIAL. Core now starts with the source-built Linux x86-64 Argon2 library
installed in its image. Both source/bundled and source/source Core replicas pass
real password, import, reset and concurrency cases. Foundation selection, full
distribution, automatic rehash and all-platform acceptance remain open.

Current Core image:

```text
sha256:e8c460664ac56573236447da65f4445481dd12b246c4bc4257e665aa4ce87b43
```

The Core/plugin pair is still `guarded-01`. Node remains
`sha256:2a02e08d5fcbdd573974bb21247e4784b23870e86d0de1ced65121b3a11da19a`.
The native library is the same 149,528 bytes qualified by
`evidence/reuse/native-correspondence/argon2/native-build/linux-03`:

```text
45aa95d580e734630f1120b808a27f65aa0c13dddf3f52f865f6be3f4d417065
```

The installer removes the native-only `argon2-jvm-2.11.jar` from its disposable
image context after checking its original hash, zero Java classes and eight
native members. It keeps `argon2-jvm-nolibs-2.11.jar` and JNA unchanged. All 68
original PHC source/build/test/notice files are installed alongside their map;
the image's SBOM replaces that bundle with the CC0 native library. The manifest
has 554 files, including 86 JARs; the SBOM has 87 components. File-specific
source, destination, license and hash bindings are in
`reuse/installed-native-argon2.json`. Historical original-JAR notices remain as
provenance; their inventory is not the new installed dependency list.

The [wrapper's license](https://raw.githubusercontent.com/phxql/argon2-jvm/v2.11/LICENSE.txt)
is LGPL3, which incorporates GPL3 terms. Earlier shorthand saying “GPL wrapper”
was imprecise; the wrapper is unchanged and its obligations remain open.
The [PHC grant](https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/LICENSE)
and per-file headers are retained; this candidate selects CC0. This report does
not constitute independent licensing or maintenance approval.

The image command checks the exact native SHA before starting Core, rejects a
conflicting bundled JAR and JNA loader overrides in the three Java option
environment variables, and runs a public PHC known-answer vector through the
unchanged wrapper/JNA. It checks the actual loaded path. Only then does it start
the original Core command with the explicit native path. Root-owned native files
and a private 0700 JNA temporary directory are installed in the image; no new
data volume is needed. JNA deletes its temporary library after mapping it.
Operators who control Docker commands/images can replace this startup profile;
these checks do not claim protection against that privileged access. Other JVM
options, live tampering and all possible loader paths are not qualified.

Actual evidence, with no healthy application, Core JAR or native-library mounts:

| Evidence directory | Observed result |
|---|---|
| `evidence/operations/native-argon2-startup/image-native-01` | Seven startup cases: missing/corrupt library, conflicting bundle, three loader overrides, healthy self-test; these are bootstrap tests, not authentication |
| `evidence/foundation/refresh-grace/image-native-native-01` | Ten Core behavior rows plus 15-user cleanup, 117 requests; A uses installed source native, B uses the then-retained old bundle |
| `evidence/foundation/refresh-grace/native-installed-peer-01` | Ten behavior rows plus 15-user cleanup, 117 requests; both replicas use the installed source library, confirmed in actual process maps |
| `evidence/foundation/refresh-grace/image-guarded-native-01` | Eight guarded-operation behavior rows plus cleanup; the prior pre-guard 404 case remains in its original separate run |
| `evidence/foundation/refresh-grace/image-core-native-01` | Twelve grace/retry/replay/transaction and transport cases |
| `evidence/operations/atomic-reset/image-core-native-01` | Sixteen actual atomic reset/password-session cases |
| `evidence/operations/password-reset/atomic-image-node-native-01` | 34 HTTP/SMTP/TLS/React behavior checks; wire/cleanup and browser-orchestration rows are not added to that count |
| `evidence/operations/atomic-core-replacement/native-01` | Fourteen actual local seed/upgrade/rollback/re-upgrade/cleanup phase cases; original schema, PostgreSQL process, private configuration and identity set preserved |

The native password cases cover source-to-peer creation and verification, wrong
passwords, original Argon2i v16/v19 and Argon2id v19 imports, bcrypt imports,
malformed/unauthorized import, reset with old-session/token denial, and eight
concurrent owners. Successful login preserves imported hashes: PWD-005 rehash
remains missing. The retained operator configuration still uses its original
BCRYPT default and zero-grace session policy; the isolated labs explicitly
configure Argon2 and/or the five-second candidate as recorded. No operator
password policy was silently changed by image replacement.

The main build's exact source snapshots are retained under
`evidence/operations/atomic-core-image/native-01/source-snapshots`. Afterwards,
only the native lab runner and Java password probe changed to recognize an
already-installed source-native peer for subsequent rebuilds. The separate
`native-installed-peer-01` run qualifies those new harness bytes without
rebuilding unchanged runtime layers. Its report says `installed-source`; the
runner's historical console phrase “source-built and bundled” is not the
authoritative peer-profile record. `tools/verify_installed_native.py` binds these
two source generations explicitly; its correspondence checks are not additional
authentication tests.

The old `db1d29ba6244` image was removed only after successful rollback and final
upgrade. One cached-base image build used no image downloads, new volumes,
networks or public ports. All temporary containers, the 62.8 MB build context and
private build scratch retired. One native candidate cache remains. Hygiene
retains two containers, six task tags and zero dangling project images. Generated
source-checkpoint ZIPs stay capped at three; unrelated Docker resources and
persistent data are outside cleanup scope.

For changed native test cases using the current retained lab:

```powershell
python -B tools/run_refresh_grace_lab.py --name NEW_NATIVE_CASES --session-build guarded-01 --native-argon2-build linux-03 --native-argon2-installed --native-reference-core-image sha256:e8c460664ac56573236447da65f4445481dd12b246c4bc4257e665aa4ce87b43
```

For a material runtime change needing a rebuilt image and local qualification:

```powershell
python -B tools/build_atomic_core_runtime.py --name NEW_NATIVE_IMAGE --session-build guarded-01 --native-argon2-build linux-03 --qualify-refresh-grace --qualify-guarded-sessions
```

Use unique lowercase run names. The second command performs a local lab
replacement after qualification; it requires the existing pinned source/cache,
private lab and original images. It is not a fresh-host deployment claim. Retain
the native argument in subsequent builds to preserve this packaging profile.
Do not rebuild unchanged layers for documentation or harness-only changes.

Continue the documented JNA/scrypt/SQLite/OS and source/relink closure using
permitted audited source. Keep unresolved source grants excluded. Full clean-host
deployment, all original SDK/plugin/integration profiles, configured namespaces
and linking, other platforms and live providers, maintenance updates, complete
hash/migration/rehash coverage and independent review remain open. No entitlement
enforcement or authoritative identity/session ownership changed.
