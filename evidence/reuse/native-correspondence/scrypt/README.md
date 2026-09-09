# scrypt 1.4.0 native/JNI source correspondence

The authoritative result is [`source-manifest.json`](source-manifest.json).
It verifies **32/32** repository source, header, build/notice, and Java test files
against Git blob SHA-1 and byte size at commit
`0675236370458e819ee21e4427c5f7f3f9485d33`. Every row records its exact local
file or source-JAR member, SHA-256, acquisition URL, role, and observed notice
terms. This establishes source identity and availability, not native binary
reproducibility, license approval, or authentication acceptance.

| Included files | Count | Acquisition |
| --- | ---: | --- |
| C implementations and JNI bridge | 4 | Existing individually cached sources |
| Native headers/configuration | 5 | Parent fetched 8,716 bytes |
| Java crypto/codec sources | 4 | Existing source JAR; every member matches Git |
| Java JNI/platform/loader sources | 7 | Existing source JAR; every member matches Git |
| LICENSE, Makefile, POM, README | 4 | Existing individually cached files |
| Java test sources | 8 | Parent fetched 15,818 bytes |

The original recursive tree contains 71 entries: 42 blobs and 29 subtrees.
All 29 subtree hashes reconstruct correctly. The acquired
[commit object](../metadata/run-01/scrypt/commit.json) binds the reconstructed
root tree `d9a607e3794061fc867796e76c5b35556e2457c9` to the pinned commit.
The trees endpoint's top-level `sha` echoed the requested commit; it was not
mistaken for the root tree object hash. Ten other blobs are explicitly inventoried
as excluded: Git ignore metadata, four upstream native binaries, and five
binary/signature test fixtures. No full archive or native binary was downloaded
for this lane.

The existing binary JAR and sources JAR both contain the same three x86_64
natives for Linux, FreeBSD, and macOS. All three match the corresponding release
tree blobs, sizes, and previously recorded SHA-256 values. The runtime JAR hash
is `9a82d218099fb14c10c0e86e7eefeebd8c104de920acdc47b8b4b7a686fb73b4`.
The sources JAR repeats native binaries and supplies no native C/header sources;
its name does not establish native source completeness. Android's upstream ARM
native is outside this runtime JAR inventory.

Six files have explicit **BSD-2-Clause** notices: `crypto_scrypt-sse.c`,
`crypto_scrypt-nosse.c`, `sha256.c`, `crypto_scrypt.h`, `sha256.h`, and
`sysendian.h`. Their Colin Percival copyright, conditions, and disclaimers
must remain with source redistribution and be reproduced in binary distribution
materials. The remaining rows record the repository's **Apache-2.0** declaration
and applicable inline attribution, rather than treating the root license as an
override of those BSD notices. Exact notice byte ranges and hashes are recorded.
The Java Base64 comment credits MiG Base64's algorithm, and the README describes
the Java port's relationship to Colin Percival's reference implementation; these
provenance statements are retained, without a clean-room or independent legal
approval claim.

The native build still lacks decisive correspondence evidence:

- `Makefile` selects SSE2 by default, uses C99/O2, and emits
  `target/libscrypt.so` or `target/libscrypt.dylib`. It does not copy the result
  into Maven resource directories. The POM has no native compilation step;
  checked-in native resources are packaged instead.
- Compiler/linker, GNU Make, JDK/JNI headers, operating-system headers, libc,
  platform SDK versions, and original build commands are not pinned by these
  files. Link maps and provenance for statically incorporated compiler/runtime
  code are absent. `-shared` does not prove such code is absent.
- The macOS recipe uses the historical `JAVA_HOME/Headers` layout. Linux and
  FreeBSD use platform JNI include directories. Android uses an old
  `arm-linux-androideabi-gcc`/Android-9 NDK recipe and is unqualified here.
- Project header closure is now present for the default `HAVE_CONFIG_H` build.
  Conditional system headers and the optional `CONFIG_H_FILE` override still
  depend on a separately pinned toolchain/configuration.
- Maven declares Java 6 source/target, JUnit 4.8.2, and dated pinned plugins.
  Those build/test dependencies, signing inputs, and a reproducible packaging
  process have not been qualified. The five binary/signature test fixtures were
  not fetched, and no upstream tests or native builds ran in this lane.
- `SCrypt` falls back to Java if native loading fails. Ordinary password tests
  therefore do not prove which native library executed. No loader configuration
  was changed, and no per-platform native execution or bytecode/native rebuild
  comparison is claimed.

[`verification.json`](verification.json) records eleven source-integrity checks,
including rejection of a one-bit corruption in a temporary header copy. The
negative command exited 1 and wrote no output manifest; its scratch was removed.
All current manifest input hashes and all 13 fetched-file hashes were rechecked.
The initial 19/32 inventory remains preserved as
`source-manifest-before-acquisition.json`.

Re-run without overwriting prior evidence:

```powershell
python evidence/reuse/native-correspondence/scrypt/qualify_sources.py --commit-metadata evidence/reuse/native-correspondence/metadata/run-01/scrypt/commit.json --output source-manifest-recheck.json
```

The verifier performs no network, Docker, build, or runtime operations. The
parent's separate bounded acquisition is recorded under `acquired/`; its
`container.json` records the exact fetch container as removed. This lane created
no Docker resources. Native corresponding-source closure, native rebuild,
license approval, foundation approval, and independent security review all
remain explicitly **false**.

Manifest SHA-256:
`fe12737c7483a9930c16296795ec8c0f84d4bd5c323802056838b37f2118c68d`.
