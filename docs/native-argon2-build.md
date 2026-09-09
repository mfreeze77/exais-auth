# Source-built Argon2 qualification

PARTIAL. A Linux x86-64 Argon2 library now builds from pinned source and runs
actual Core password operations. The retained image is unchanged; the native
library is a declared dependency mount in an isolated lab. No engine, complete
baseline row, full migration or distribution gate is approved.

The original wrapper recipe selects PHC20190702, now resolved to
`62358ba2123abd17fccf2a108a301d4b52c01a7c`. All68 acquired source, test, build and
notice files match Git blobs and SHA-256 records. C/header files have explicit
CC0/Apache grants; this candidate selects CC0 and retains complete terms and
attribution. Unrelated LaTeX/PDF documents are outside the build. See the
[immutable source license](https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/LICENSE)
and `reuse/native-argon2-components.json` for file-specific bindings.

`evidence/reuse/native-correspondence/argon2/native-build/linux-03` uses cached
compiler image `node@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a`,
GCC12.2.0/Debian12 and the unmodified upstream Makefile. Generic reference code,
deterministic debug-prefix mappings and epoch0 are explicit inputs. Two separate
tmpfs build directories produce identical149,528-byte libraries:

```text
45aa95d580e734630f1120b808a27f65aa0c13dddf3f52f865f6be3f4d417065
```

Original `make test` passes twelve comparisons of six known-answer vectors across
its two loops and37 API pass lines, including invalid inputs/passwords. The second
loop does not prove another optimized implementation. Optional testci/large-RAM
tests were not executed or counted. ELF metadata, exported symbols, compiler
packages and hashes are retained. The only NEEDED library is libc.so.6. Historical
Ubuntu16.04 release bytes were not reproduced; all-Linux/libc support is unproven.

`evidence/foundation/refresh-grace/native-argon2-01` passes ten actual Core behavior
cases plus cleanup with117 requests: source-created/bundled-verified passwords,
the reverse direction, wrong passwords, original Argon2i v16/v19 and Argon2id v19
fixtures, bcrypt import, malformed/unauthorized import, resets from both libraries
with session/token invalidation, and eight concurrent users. All15 users are
removed. Imported hashes stay unchanged after login: automatic rehash remains
missing, so PWD-005 is not satisfied.

Both replicas use installed Core `db1d29ba6244` and one disposable PostgreSQL DB.
A uses the wrapper's documented jna.library.path; B uses the existing bundled
library. Actual process maps and the mounted hash confirm A's source selection.
Separate executable32MiB JNA tmpfs mounts permit library loading while ordinary
/tmp stays nonexecutable. No Core/plugin JAR, primitive or entitlement changed.
The GPL Java wrapper, JNA and other native/OS obligations remain unchanged.

Failures linux-01 and linux-02 are preserved. First, a CRLF script failed before
compilation; exact LF emission fixed it. Second, genkat could not execute on the
default nonexecutable tmpfs, yielding an empty output and apparent vector mismatch.
An explicitly executable64MiB compiler tmpfs fixed the environment. Neither
source nor test criteria changed. Both failed containers and the successful
compiler retired, as did the inventory/capture helpers and five Core-lab containers.
Original persistent resources/configuration stayed unchanged. No image was built
or downloaded. One149,528-byte candidate cache and2.97MB of source are retained.

In a fresh checkout with the pinned compiler image cached:

```powershell
python -B tools/build_native_argon2.py --name NEW_UNIQUE_NATIVE_BUILD
```

The builder preserves an existing `.cache/native-argon2` candidate. Do not delete
it or repeat unchanged builds for timestamps. Changed integration tests can use:

```powershell
python -B tools/run_refresh_grace_lab.py --name NEW_UNIQUE_NATIVE_LAB --session-build guarded-01 --native-argon2-build linux-03
```

Next: install through the wrapper's supported nolibs boundary, qualify the image
and loader failure behavior, and close native/OS/source/relink obligations.
Other platforms, full hash/rehash/migration scope, foundation and independent
review remain unqualified.

Checkpoint de6439a31552 failed its fresh native extraction: upstream export-ignore
attributes omitted five tracked build/provenance files. The failure and exact ZIP
identity are preserved under `package-completeness-01`. Packaging now reads and
hash-verifies every regular committed Git blob, preserving upstream attributes
without applying their export filters/substitutions. Three actual-Git regression
cases and22 secret-boundary cases pass. A corrected ZIP must separately pass:

```powershell
python -B tools/verify_extracted_native.py --zip artifacts/NEW_CHECKPOINT.zip
```

That helper extracts75 exact source/build inputs, performs the original native
build/tests, compares the result to the Core-tested library, retains its report,
and removes its temporary source tree, binary and compiler container.
