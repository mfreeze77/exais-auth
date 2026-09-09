# SQLite-JDBC 3.45.1.0 native correspondence

**PARTIAL.** This review identifies the native source/build inputs and checks
retained bytes. It does not approve redistribution, prove a native rebuild,
pass a native platform test, or select an identity engine. No Docker command,
archive download, binary download, native execution or runtime change was made
by this subtask.

The [upstream release](https://github.com/xerial/sqlite-jdbc/releases/tag/3.45.1.0)
points to immutable commit
[`5ac6b0d4bf42244f1d48b39af74e87ce7621cac6`](https://github.com/xerial/sqlite-jdbc/commit/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6).
[`manifest.json`](manifest.json) records exact paths and acquisition status.
Cached Java/JNI sources are identified for reuse instead of downloading them
again. Primary commit/tree metadata now binds release tree
`504a91c037b5d074df6eafb9d1c3632c023a98fa`. All **23 native members**, **57 cached
Java/C sources** and **three cached root license/POM members** match that tree's
Git blob SHA-1 and size. [`research/release-bindings.json`](research/release-bindings.json)
preserves each comparison. The manifest has verified Git object/size facts for
all 93 listed paths; this is release-byte correspondence, not proof that source
was compiled into those native bytes.

[acquisition-request.json](acquisition-request.json) requested only 26 missing
build-control text files, 134,402 bytes total. The parent acquired them under
[`acquired/`](acquired/) using one bounded temporary container; its retained
[`container report`](acquired/container.json) records removal. This subtask then
independently verified all 26 SHA-256 values, Git blob SHA-1 values, sizes, exact
URLs and the acquired file set in
[`research/acquired-verification.json`](research/acquired-verification.json).
The request excluded the six tracked JNI
headers and the extension with unresolved permission evidence; root licenses,
POM and Java/C source members can be reused from the verified cached source JAR.
Of the 93 listed repository inputs, 57 Java/C and three root notice/POM inputs
are already cached, 26 build-control files were acquired, and seven remain
reference-only. The independent SQLite amalgamation and toolchain source inputs
are additional unresolved prerequisites.

## Retained runtime bytes

[`research/cached-members.json`](research/cached-members.json) records a fresh,
non-executing ZIP inspection against the existing archive inventory. The runtime
JAR is 13,501,708 bytes, SHA-256
`f5f5404fa5a60f9e0b15e7bea2ea2d137e255f01babd0bfcb9dafcd2e3bf9cd2`.
Its source JAR is 13,426,088 bytes, SHA-256
`2700e85d6bd9bfafee3b69f17305f6d141ab3fb9be31c7ca5993181e1ee6c823`.
All 53 inspected members match their recorded SHA-256 and size, including all
23 native libraries in each archive. Git blob SHA-1 is independently calculated
as SHA-1 of `blob <byte-length>\0<member-bytes>` for comparison with release Git
objects; SHA-256 remains the retained-byte integrity hash.

All 23 native members contain this exact SQLite source-ID string:

`2024-01-30 16:01:20 e876e51a0ed5c5b3126f52e532044363a014bc594cfefa87ffb5b82257cc467a`

That matches SQLite's [official 3.45.1 release record](https://www.sqlite.org/releaselog/3_45_1.html).
An embedded identification string does not prove how a library was compiled or
replace execution tests. The inspector did not load any native library.

The local inspection is reproduced by
`python -B evidence/reuse/native-correspondence/sqlite/research/inspect_cached_members.py`;
the script deliberately refuses to overwrite its existing report. Preserve that
report before a separately authorized repeat. Git verification uses
`research/verify_release_tree.py --commit-metadata <retained-commit.json> --tree <retained-recursive-tree.json>`.
It verifies the commit/tree relationship, rejects a truncated tree, and compares
member hashes and sizes without downloading a binary.

Recompute fetched-text qualification with
`python -B evidence/reuse/native-correspondence/sqlite/research/verify_acquired.py`.
It preserves existing evidence by refusing to overwrite its report. The final
manifest SHA-256 is
`f3fcf084c137e0f9d414c9e379fde2d3d2351d457d2cf0b8906f7f4ac97d85ee`;
the release-binding report SHA-256 is
`221093ebf574fa38a44dfe54a79b53583b60816b6c69cef72d3f956a6d30a3bf`;
the fetched-text verification SHA-256 is
`4e8de6acd55d50de760572c3c11084c8ded66638b59c8cb139f5f661c429dd5d`.

## SQLite source and modifications

The pinned [`VERSION`](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/VERSION)
sets SQLite 3.45.1. The pinned
[`amalgamation_version.sh`](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/amalgamation_version.sh)
encodes it as `3450100`; the source URL is
[sqlite-amalgamation-3450100.zip](https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip).
The release page publishes SHA3-256
`0474604df9e1b69a5544295dd046aad954749279780d557da80f44b958100295`
for **sqlite3.c**, not for the ZIP. No primary archive hash was established in
this subtask. The manifest therefore leaves archive SHA-256 null and requires
the acquired file to be hashed and its `sqlite3.c` checked against that published
SHA3 value. The Makefile supplies a versioned download filename with older-year
fallback URLs, but no archive digest verification.

The [native recipe](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/Makefile#L60-L104)
changes the amalgamation before compilation: it initializes `sqlite3_api` in a
generated extension header, registers extension functions on successful open,
adds the `JDBC_EXTENSIONS` compile-option marker, and appends the extension C
files. It compiles that result with feature/limit definitions, links JNI glue,
then strips and copies the library. Thus a stock SQLite source archive alone
does not describe these JDBC native bytes. Required amalgamation inputs are
`sqlite3.c`, `sqlite3.h` and `sqlite3ext.h`; `shell.c` is not used by this recipe.

## Component-specific notices and unresolved terms

| Input | Observed origin/terms | Remaining evidence |
| --- | --- | --- |
| Root `LICENSE` | Apache-2.0 text; present in both cached JARs | Preserve it; do not extend it automatically to separately marked third-party inputs |
| `LICENSE.zentus` | David Crawshaw 2006, two-condition BSD-style notice; present in both cached JARs | Preserve this exact notice separately |
| `src/main/java/org/sqlite/core/NativeDB.c` | David Crawshaw 2007, distinct ISC-style permission header | Preserve its exact header; it is not identical to either embedded standalone license |
| SQLite amalgamation | SQLite's public-domain statement applies to SQLite itself | Verify actual acquired source and retain its provenance; do not apply that statement to unrelated additions |
| `src/main/ext/extension-functions.c` | Historical comments identify Liam Healy, original 2006 code by relicoder, and copied SQLite 3.3.13 definitions | No explicit permission/license header was found in this pinned file; exact original contribution/permission chain and modification notices remain unresolved |
| `lib/inc_win/jni.h`, `lib/inc_win/jni_md.h`, `lib/inc_mac/jni.h`, `lib/inc_mac/jni_md.h` | Sun copyright and proprietary/confidential markings; `jni.h` also identifies Netscape JRI origin | Full applicable source/build/distribution terms are not supplied by those short headers; reference/research only pending resolution |
| `lib/inc_linux/jni_md.h` | Oracle 2006 copyright and proprietary/confidential marking | Same unresolved terms boundary; root Apache is insufficient evidence |
| `lib/inc_linux/jni.h` | Oracle 1996/2006 copyright; GPL-2.0-only with a referenced Classpath exception, plus Netscape JRI origin | Preserve the full applicable GPL/exception text and provenance if used; this header has different terms from its sibling `jni_md.h` |

Primary witnesses are the pinned
[JNI glue](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/src/main/java/org/sqlite/core/NativeDB.c#L1-L16),
[extension origins](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/src/main/ext/extension-functions.c#L49-L89),
[Windows JNI header](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/lib/inc_win/jni.h#L1-L14),
[macOS JNI header](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/lib/inc_mac/jni_md.h#L1-L5),
[Linux JNI header](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/lib/inc_linux/jni_md.h#L1-L5),
[Linux JNI interface and exception reference](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/lib/inc_linux/jni.h#L1-L32),
and [SQLite's own statement](https://www.sqlite.org/copyright.html).
The historical [SQLite contribution archive](https://sqlite.org/src/ext/contrib/__download_/about.html)
identifies an extension-functions contribution by Liam Healy; it does not by
itself bind all JDBC modifications or prove a permission grant for this version.
Unresolved permission evidence is not a legal conclusion that the code is
unlicensed, and this review grants no approval.

## JNI, toolchains and the 23 recorded libraries

The recipe generates `NativeDB.h` from `NativeDB.java` using `javac -h` and the
full Java source path, with `slf4j-api:1.7.36` as a build-time classpath input.
`JAVA_HOME`, actual JDK/header versions and generated header bytes need retention.
The [include ordering](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/Makefile.common)
can select bundled JNI headers before discovered JDK directories; merely having
an OpenJDK installed does not prove those marked headers were avoided.

| Recorded native group | Count / architectures | Recorded recipe requirements |
| --- | --- | --- |
| Linux | 7: arm, armv6, armv7, aarch64, ppc64, x86, x86_64 | GCC cross-toolchains or CentOS5 images; ARM float ABI distinctions; default shared link includes static libgcc, pthread and libm |
| Linux-Android | 4: arm, aarch64, x86, x86_64 | Clang/Android cross-toolchains and sysroot; Android/log/dl/libc/math link inputs; default static-libgcc flag also appears |
| Linux-Musl | 3: aarch64, x86, x86_64 | Musl cross-toolchain or Alpine images; these targets fall back to the default compiler/link configuration in this Makefile.common |
| Windows | 4: armv7, aarch64, x86, x86_64 | MinGW GCC for x86 and x86_64; LLVM/Clang for ARM; shared link requests static libgcc and stdcall export decoration handling |
| macOS | 2: aarch64, x86_64 | Apple SDK/osxcross inputs, deployment targets, dynamic-library link, stripping and rcodesign stage |
| FreeBSD | 3: aarch64, x86, x86_64 | FreeBSD9 cross GCC or FreeBSD11.4 cross Clang image/sysroot; shared linkage |

The [native workflow](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/.github/workflows/build-native.yml)
derives its matrix from `native-all`, invokes Make targets and commits produced
resources. Its existence is not evidence that a particular historical run used
identified toolchain bytes or that tests passed. The source manifest includes
the Dockerfiles, generated dockcross wrappers and update controls for inspection.
Representative recipes use mutable images/package installs: `centos:5`,
`alpine:3.11`, and dockcross `latest`. The
[rcodesign recipe](https://github.com/xerial/sqlite-jdbc/blob/5ac6b0d4bf42244f1d48b39af74e87ce7621cac6/docker/Dockerfile.rcodesign)
uses mutable Rust/Ubuntu images and the PyOxidizer main branch.

To claim compiled correspondence still requires exact historical compiler,
linker, strip, C library/sysroot, compiler-runtime archive, JDK and signing inputs,
their source/notices and any applicable exceptions, generated-source hashes,
link maps or equivalent component evidence, and each platform's build result.
`-static-libgcc` identifies an audit obligation; it does not prove which runtime
objects were included or that an exception applies. No platform build or load
test was run here, including Linux x86_64. Matching a Git blob identifies the
release bytes; it is not a reproducible-build result.
