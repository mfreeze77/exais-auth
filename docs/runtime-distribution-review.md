# OSS runtime distribution review

**PARTIAL: archive integrity verified; distribution obligations and native build
provenance remain unproven. This is evidence review, not license approval.**

Reviewed the 84 runtime dependencies in `reuse/runtime-dependencies.json`, the
83 cached source JARs, and the original source-fetch evidence
`evidence/reuse/runtime-source-notices/fetch-20260908T222746Z.json`. All 84 binary
hashes and 83 source hashes matched. Four JARs contain 59 native members; 34 of
those compiled members are repeated byte-for-byte inside their source JARs.
Sources being available under a matching Maven version does not demonstrate
that the complete native source and build inputs correspond to those binaries.

The reproducible local inspection command is:

```powershell
python -B evidence/reuse/runtime-distribution-review/inspect_archives.py
```

It reads ZIP members without extracting or executing native code. Results, exact archive
hashes, all 59 native-member hashes, notice-member hashes, selected Java-source
witnesses, and primary Maven acquisition URLs are in
[`archive-inventory.json`](../evidence/reuse/runtime-distribution-review/archive-inventory.json).
The initial inspection created no containers. The parent subsequently authorized
one named, labeled, short-lived container using the existing pinned Python image
to fetch small notices and release metadata; it was removed after completion.
No image, volume, network, source archive or runtime service was created. The only
new files are this report and its small review evidence directory.
Original evidence, auth code and engine-selection state were not changed.

## Native components

| Component | Observed source JAR contents | Material still unproven |
| --- | --- | --- |
| `com.lambdaworks:scrypt:1.4.0` | Java sources and the same three Darwin/FreeBSD/Linux native binaries; zero C/header/build files or standalone notice files | Exact `src/main/c/*.c`, `src/main/include/*`, root Makefile, JNI/toolchain configuration and native binary correspondence; native copyright/permission notices |
| `de.mkammerer:argon2-jvm:2.11` | Eight native binaries repeated identically, no Java/C/header/build files; separate `argon2-jvm-nolibs` source JAR has Java binding sources | Native Argon2 revision and all per-platform build inputs; JVM wrapper Gradle project/build controls; full license texts, library replacement/relinking and source-access delivery conditions |
| `net.java.dev.jna:jna:5.8.0` | Java sources only; binary JAR has 25 native libraries | `native/dispatch.c`, callback/header sources, native Makefile, generated JNI inputs, complete bundled libffi tree/build configuration, platform toolchains and component notices |
| `org.xerial:sqlite-jdbc:3.45.1.0` | Twenty-three identical native binaries, Java sources and one `org/sqlite/core/NativeDB.c`; POM present | SQLite amalgamation C/headers, `src/main/ext/*.c`, generated JNI header, Makefile/Makefile.common/VERSION/amalgamation script, platform toolchains and exact static runtime dependencies |

For scrypt, the upstream versioned [Makefile](https://raw.githubusercontent.com/wg/scrypt/1.4.0/Makefile)
selects C sources and an SSE variant. Its
[`crypto_scrypt-sse.c`](https://raw.githubusercontent.com/wg/scrypt/1.4.0/src/main/c/crypto_scrypt-sse.c)
has Colin Percival's BSD conditions, including reproducing the copyright,
conditions and disclaimer with binary distributions. Those standalone notices
are absent from both cached JARs; the POM's root Apache declaration does not
resolve that native attribution obligation. Exact binary-to-source binding is
still needed before declaring the complete native notice set.

Argon2's versioned [README](https://raw.githubusercontent.com/phxql/argon2-jvm/v2.11/README.md)
and [Gradle metadata](https://raw.githubusercontent.com/phxql/argon2-jvm/v2.11/build.gradle)
declare LGPL v3 for the JVM binding. The native
[build guide](https://raw.githubusercontent.com/phxql/argon2-jvm/v2.11/docs/compile-argon2.md)
points to the separate PHC repository and permits an external library path, but
does not pin the native revision that produced each cached resource. Do not
infer the native source license or build correspondence solely from the wrapper
POM. Neither wrapper source JAR supplies the complete Gradle build project or
full LGPL/GPL texts.

The later commit-pinned review found that `libargon2/context/build-libargon2.sh`
selects native release tag20190702 for four Linux targets. It still does not pin
the archive digest or mutable Ubuntu/apt toolchains, and does not establish the
Darwin/Windows builds. Wrapper build controls and full LGPL3/GPL3 texts are now
retained under `evidence/reuse/native-correspondence`; native correspondence and
source/relink delivery remain unqualified. See `docs/native-source-correspondence.md`.

JNA [expressly offers Apache-2.0 or LGPL-2.1-or-later](https://github.com/java-native-access/jna/blob/5.8.0/LICENSE).
Its [native Makefile](https://raw.githubusercontent.com/java-native-access/jna/5.8.0/native/Makefile)
defaults to static libffi and can also use static compiler runtimes. The bundled
[libffi license](https://raw.githubusercontent.com/java-native-access/jna/5.8.0/native/libffi/LICENSE)
requires its own MIT copyright and permission notice. The cached JNA JAR's
`META-INF/LICENSE` is a 788-byte JNA dual-license pointer. The same binary JAR
also contains the full alternatives in `META-INF/AL2.0` (10,174 bytes) and
`META-INF/LGPL2.1` (24,389 bytes); the initial filename scanner missed those two
short names. The corrected packager preserves both exact texts. The historical
archive inventory remains unchanged and does not enumerate these two texts.
The source JAR does not contain the libffi license. Choosing Apache for JNA does not remove
libffi's notice requirement. Per-platform static runtime inclusion and exception
applicability remain unverified.

SQLite JDBC's versioned [Makefile](https://raw.githubusercontent.com/xerial/sqlite-jdbc/3.45.1.0/Makefile)
downloads the SQLite amalgamation, modifies it, appends extension C sources and
combines it with JNI glue. The cached source JAR contains only that JNI C file.
[Makefile.common](https://raw.githubusercontent.com/xerial/sqlite-jdbc/3.45.1.0/Makefile.common)
also uses platform-dependent static compiler runtime flags. The upstream
[SQLite public-domain statement](https://www.sqlite.org/copyright.html) concerns
SQLite itself; it does not establish the license of every wrapper, extension or
compiler runtime in this JDBC bundle. Preserve both existing JDBC license files
and audit the appended extension and runtime portions separately.

These are source/build traceability gaps for all four components. They are not
a claim that Apache, BSD, MIT or public-domain distribution universally requires
shipping source or reproducing identical native bytes. Applicable copyleft,
notice conditions and the ExpertAuth reproducibility contract are separate gates.
Version-tag links above establish upstream context. The bounded follow-up below
pins selected scrypt/JNA files and release-byte identities, while native build
correspondence remains unproven.

## Verified supplemental notice material

[`supplemental-notices.json`](../evidence/reuse/runtime-distribution-review/supplemental-notices.json)
lists five eligible supplemental notice files with exact SHA-256, applicable
coordinates, immutable source URLs and limits. They comprise scrypt's root Apache
license, three exact BSD header byte ranges from the retained scrypt C sources,
and JNA's bundled libffi MIT license. This establishes material suitable for
supplemental attribution; it does not approve a distribution or establish an
exhaustive native license set.

Primary GitHub ref metadata pins `wg/scrypt:1.4.0` to
`0675236370458e819ee21e4427c5f7f3f9485d33` and `java-native-access/jna:5.8.0` to
`cc4ce71d511a9aa17219cc36e2338dd1b0f52770`. Locally calculated Git blob hashes
match all three scrypt native resources in that release tree and the entire JNA
runtime JAR against that commit's `dist/jna.jar`. Thus the cached native bundles
are mapped to those releases without downloading another binary. These Git blob
SHA-1 comparisons identify upstream repository objects; the inventory separately
preserves SHA-256 for every retained binary/member/source byte stream. This does
not prove the binaries were reproducibly built from the accompanying source tree.

Reproduce the local binding and exact-notice extraction with:

```powershell
python -B evidence/reuse/runtime-distribution-review/qualify_supplemental_notices.py
```

It verified four release-binary bindings and five supplemental notices.
The fetch retained 17 responses totaling 89,019 bytes under `upstream/`, with
exact URLs and response hashes in `supplemental-fetch.json`. No full archive or
native binary was downloaded. Fetch container
`expertauth-runtime-distribution-notices-20260908`, ID
`83c3823237d23c8dc6812a479f008fe7611a440f3a96003b7ba78640e6d6a3f5`, used
`python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`
with `--pull=never`, `--rm` and project/task labels. It was confirmed absent after
the command's `finally` cleanup. Only this review output folder was writable.

## Exact representative native bindings

All values below are SHA-256; the inventory contains every platform member.

| Runtime JAR / member | SHA-256 |
| --- | --- |
| `scrypt-1.4.0.jar` | `9a82d218099fb14c10c0e86e7eefeebd8c104de920acdc47b8b4b7a686fb73b4` |
| `lib/x86_64/linux/libscrypt.so` | `69100ad6b49646f7f97388c64ed6d9fdf1a9b60c7dcf9787344e9f189359c3eb` |
| `argon2-jvm-2.11.jar` | `c1bb374c93c7f0a989530372c11b286a0b542fdd2b6efbcf9708368a70763eb1` |
| `linux-x86-64/libargon2.so` | `30c47b6591f53fd0b28ad9e679a9f8c62e21094251485a1fb06e8b81e2eeef45` |
| `jna-5.8.0.jar` | `930273cc1c492f25661ea62413a6da3fd7f6e01bf1c4dcc0817fc8696a7b07ac` |
| `com/sun/jna/linux-x86-64/libjnidispatch.so` | `c8ce9ea6a969f967f2df08414d8e17697795bc39d5e354b8bd9bf0a6c23fc006` |
| `sqlite-jdbc-3.45.1.0.jar` | `f5f5404fa5a60f9e0b15e7bea2ea2d137e255f01babd0bfcb9dafcd2e3bf9cd2` |
| `org/sqlite/native/Linux/x86_64/libsqlitejdbc.so` | `8991ba66c5c95a6d2a8bc395e874c5550b5acde267c618db1049cc1d801c34f1` |
| SQLite source member `org/sqlite/core/NativeDB.c` | `1a695760a4bdf8d1a9b50a899b0fad18a87168c1b24de2fb6404b680d44ce31f` |

## Guava metadata-only exception

The unavailable source classifier for
`com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava`
does not hide an executable implementation. Its 2,199-byte runtime JAR has zero
classes/native members and exactly three non-directory members:

| Member | SHA-256 |
| --- | --- |
| JAR itself | `b372a037d4230aa57fbeffdef30fd6123f9c0c2db85d0aced00c91b974f33f99` |
| `META-INF/MANIFEST.MF` | `261de46adefa0b980173ca8de48e924c2068d0f41390d01ff017958f8a2e3c7f` |
| `META-INF/maven/com.google.guava/listenablefuture/pom.xml` | `18d4b1db26153d4e55079ce1f76bb1fe05cdb862ef9954a88cbcc4ff38b8679b` |
| `META-INF/maven/com.google.guava/listenablefuture/pom.properties` | `7443dcd4709998f62380c61303d600b29388bc7a931fa2021c44926a80cd6bdf` |

The embedded POM explains the empty dependency-conflict marker and identifies
parent `guava-parent:26.0-android`; its license inheritance is already captured
in `reuse/runtime-dependencies.json`. The actual `ListenableFuture.class` is in
`guava:33.0.0-jre` (member hash
`08ca5731816bcadfe05d0d59b72de598da872184d63ceb538232e666223c3b9d`).
Its cached source member `com/google/common/util/concurrent/ListenableFuture.java`
has hash `e32a6d8842666901a00940b91622bc63b77fc4d82b3a7538227f9ebf377edf80`.
Preserve the unavailable-classifier fact and this narrow metadata explanation;
do not report 84 source JARs acquired or use it to exempt other missing sources.
Preserve the Apache license and metadata with the distribution.

## Distribution closure still required

Retaining exact embedded notices and providing a separately acquired, pinned
source bundle are useful steps. Source archives need not all reside inside the
runtime image. The release still needs a demonstrated recipient-access mechanism
that satisfies each applicable license, complete license/attribution coverage,
and source/build correspondence where required.

For LGPL v3 components, document the chosen compliance route, prominent library
notice, full GPL and LGPL texts, source delivery, and replacement/relinking rights
and behavior. A Maven source URL, readonly image filesystem, or untested JNA
lookup option alone does not establish all those conditions. See
[LGPL v3 section 4](https://www.gnu.org/licenses/lgpl.html) and the
[incorporated GPL terms](https://www.gnu.org/licenses/lgpl%2Bgpl-3.0-standalone.html).

Logback 1.5.38's inspected source headers permit EPL-2.0 or LGPL-2.1; AspectJ
runtime 1.9.24 declares EPL-2.0. If using EPL, distribute its text, preserve
notices, make the Program source available and tell recipients how to obtain
it under the required terms. Cached source JAR presence does not itself prove
recipient access. See [EPL-2.0 section 3](https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html).
For Apache components, preserve the license, applicable NOTICE material and
modification notices where applicable. See
[Apache-2.0 section 4](https://www.apache.org/licenses/LICENSE-2.0).

This bounded review does not audit the image's operating-system/OpenJDK packages,
every generated-source/build dependency, package export behavior, or independent
legal review. Those remain outside the evidence established here. No full
baseline requirement, engine capability, native platform or security acceptance
is passed by this distribution review.
