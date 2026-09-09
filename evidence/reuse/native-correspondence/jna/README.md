# JNA 5.8.0 native source correspondence

**PARTIAL — release bytes are identified; native source/build correspondence,
platform tests and distribution closure remain unproven. No license approval or
foundation acceptance is claimed.** This is the bounded JNA lane of WP-002.

`fetch-manifest.json` pins `net.java.dev.jna:jna:5.8.0` to
`java-native-access/jna` commit `cc4ce71d511a9aa17219cc36e2338dd1b0f52770`.
The original GitHub tag and `dist/jna.jar` metadata are retained in
`../../runtime-distribution-review/upstream/`. The cached runtime JAR's Git blob
SHA-1 is `c3d534c1d9f730881590036ac600aede01fd82d4`, matching that release's
`dist/jna.jar`; its SHA-256 is
`930273cc1c492f25661ea62413a6da3fd7f6e01bf1c4dcc0817fc8696a7b07ac`.
That establishes release-byte identity, not that source reconstruction produced
the binaries. The Maven source JAR has 63 Java files and no native source inputs.

## Acquisition boundary

The manifest enumerates **508 text source/build/notice files, 3,487,247 bytes**,
with an immutable raw URL, Git blob SHA-1 and size for every entry. The complete
tree is `04a5ebb1e8b81b6f13cbcbf91dbe0b9ec6af43a6`. The generator verifies that
the parent's acquisition records bind both commit and non-truncated tree
responses, and that the commit points to that tree. Existing small source
responses retain SHA-256 as well. File bytes subsequently must match both the
expected size and Git blob hash; record their SHA-256 too.
Git blob SHA-1 hashes include `blob <length>\0`, unlike a plain file SHA-1.

The conservative selection retains the entire `native/` tree, including bundled
libffi tests/docs/build files and license notices; `ant-tools-src/`; Java files in
`src/` needed by JNI header generation; and root Ant/license/CI/POM inputs. It
excludes binaries and archives. `binary_metadata_only_do_not_fetch` identifies
the 25 upstream platform JAR paths and separate build-tool JAR dependencies.
They are evidence targets, not substitutes for corresponding source. Source
inventory is distinct from complete historical toolchain inventory.

`acquisition-request.json` is the smaller follow-up request: **47 uncached text
files, 699,788 bytes**. It selects dispatch/build inputs and known license
exception witnesses, including GNU configuration scripts/macros and allocator
source. Six other inputs reuse exact cached source/JAR notice bytes. This request
does not acquire the whole libffi tree and cannot itself close all licensing or
native build obligations.

The parent has now acquired all 47 files under `acquired/`. Independent local
verification matched every immutable URL, length, Git blob SHA-1 and SHA-256 to
the request and acquisition evidence. `acquired-review.json` records each exact
file hash and a hashed line/byte witness for its notice observation. It does
not classify every source file or approve a licensing route.

Regenerate locally without any network, native execution or build:

```powershell
python -B evidence/reuse/native-correspondence/jna/build_manifest.py
# Equivalent explicit immutable metadata input:
python -B evidence/reuse/native-correspondence/jna/build_manifest.py --tree evidence/reuse/native-correspondence/metadata/run-01/jna/tree.json
python -B evidence/reuse/native-correspondence/jna/verify_acquired.py
```

The generator verifies the runtime archive and all 25 native members, expands
the source manifest when a complete tree is supplied, and writes only this
directory. Its maximum source request is 2,000 files, 20 MB total and 1 MB per
file; these are ceilings, not permission to fetch or a claim about actual size.
No fetch occurs in the generator. Stop if a bound, unknown blob, submodule or
unexpected symlink prevents a complete inventory; do not discard inputs to fit.

The recorded tree response SHA-256 is
`a07a318a286ba75b9033004f248eb42257ffdb5dace69699eded10b207352fe4`;
the commit response SHA-256 is
`6a911e502efddd312f9e8432ff9b42874c2cc4893f140ea13205607d5d7d6794`.
Both originals and their fetch/container records belong to the parent's
`../metadata/run-01/` evidence; this lane does not modify them.

## Native and generated inputs

The pinned [native tree](https://github.com/java-native-access/jna/tree/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native)
contains `dispatch.c`, `callback.c`, `dispatch.h`, `protect.h`, `snprintf.h`,
`dll-callback.c`, `jnidispatch.rc`, `Makefile`, compiler/linker wrappers, and native
test sources. Callback source selection and Windows resource generation vary by
target. The [Makefile](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/Makefile)
normally links static libffi; `DYNAMIC_LIBFFI` changes that boundary and requires
an independently locked system libffi. It contains platform-specific compiler,
assembler, link and runtime flags, including static compiler-runtime choices.

Bundled libffi is a vendored subtree, as explained in
[`README.libffi`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/README.libffi).
Its [`configure.ac`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/configure.ac)
labels it 3.3 and requires Autoconf 2.68 or later. That label is not a verified
equivalence to the upstream libffi 3.3 release: preserve the JNA-pinned subtree.
Its [source/build inventory](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/Makefile.am)
includes `prep_cif.c`, `types.c`, raw/Java API and closure sources, optional debug
code, `dlmalloc.c`, headers, architecture C/assembly, m4/configure inputs, platform
scripts and tests. The 25 target binaries need x86, ARM, AArch64, MIPS, PowerPC,
RISC-V, s390 and SPARC backends. Retain the whole subtree to avoid losing
configure dependencies or per-file license material.

The [root Ant build](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/build.xml)
sets JNA 5.8.0 / JNI 6.1.1 and JNI checksum
`147a998f0cbc89681a1ae6c0dd121629`. It generates JNI headers from Java declarations,
transforms native build/resource inputs and can create a native build package.
The checked-in native Makefile still has JNI 5.1.0; the separate
[`native/build.xml`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/build.xml)
defaults to JNI 4.0.1. Running either in isolation is not a demonstrated release
reconstruction. The candidate route begins with the root Ant `native` or
`native-build-package` target in an audited, pinned toolchain; no such command
has been executed here. The root build packages prebuilt `lib/native/*.jar`
members alongside the current target. Successful aggregate packaging therefore
would not prove that all 25 native binaries were rebuilt.

Retain generated `com_sun_jna_Function.h`, `com_sun_jna_Native.h`,
`com_sun_jna_win32_DLLCallback.h`, JNI checksum/version inputs, transformed Windows
resources and libffi configuration headers/output with the actual build record.
The [custom Ant build](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/build-ant-tools.xml)
uses JNA's ELF analysis/build-tool sources, Ant and ASM 8.0.1. Other root build
dependencies include animal-sniffer-ant-tasks 1.17 and maven-ant-tasks 2.1.3.
Their binaries, corresponding sources, transitive build dependencies, license
material and execution environment are not qualified by this manifest.

## Platform toolchains still missing

Every native member below has exact SHA-256, length and Git blob SHA-1 in the
manifest. Every source rebuild and platform-test flag remains false.

| Recorded target group | Count | Additional reconstruction inputs still unpinned |
| --- | ---: | --- |
| Linux x86, x86-64, arm, armel, aarch64, ppc, ppc64le, mips64el, s390x, riscv64 | 10 | Compiler/binutils versions, ABI and floating-point choices, libc/sysroot, JNI headers, assembler and static runtime objects |
| Windows x86, x86-64, aarch64 | 3 | MSVC/Windows SDK versions, Cygwin/MinGW packages, callback assembler and resource tools, CRT/static-runtime provenance |
| Darwin x86-64, aarch64 | 2 | Xcode/Clang/SDK revisions, deployment target, Objective-C/Foundation inputs and linker flags |
| AIX ppc, ppc64 | 2 | AIX SDK/system libraries, compiler and archiver versions, 32/64-bit object configuration |
| SunOS x86, x86-64, sparc, sparcv9 | 4 | Solaris SDK/libc, GNU tools, ISA and 32/64-bit flags |
| FreeBSD x86, x86-64 | 2 | OS version/sysroot, compiler, assembler/linker and GNU make |
| OpenBSD x86, x86-64 | 2 | OS version/sysroot, compiler, assembler/linker and GNU make |

The pinned [AppVeyor file](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/appveyor.yml)
names Visual Studio 2015 for x86/x64 and Visual Studio 2019 for ARM64, with
unversioned Chocolatey/Cygwin package installation. It explicitly skips ARM64
tests. The pinned [Travis file](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/.travis.yml)
selects a then-available Ant 1.9 archive over HTTP and installs unpinned APT
packages. These are historical configuration hints, not toolchain locks or
current platform acceptance evidence. JNI header supplier/license, Autoconf,
Automake, libtool, make, shell and package-manager inputs also remain unpinned.

## License and notice exceptions

JNA's root [`LICENSE`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/LICENSE)
offers Apache-2.0 or LGPL-2.1-or-later. Its C source headers carry their own
copyright lines; preserve them. The actual cached JAR also contains complete
`META-INF/AL2.0` and `META-INF/LGPL2.1`, missed by the earlier filename scanner.
This corrects that scanner's incomplete notice-member list without changing
the original evidence. Exact hashes:

| Member | Bytes | SHA-256 |
| --- | ---: | --- |
| `META-INF/LICENSE` | 788 | `521bb271ac56e0e29a1b1b688b94af17d00d378fc8e63478d8c8b2a7c4a229d0` |
| `META-INF/AL2.0` | 10174 | `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` |
| `META-INF/LGPL2.1` | 24389 | `eea173a556abac0370461e57e12aab266894ea6be3874c2be05fd87871f75449` |

Bundled libffi's separate [MIT notice](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/LICENSE)
has already been retained and qualified for supplemental attribution in
`../../runtime-distribution-review/supplemental-notices.json`; SHA-256
`25d56871423a870487edee68000ef66b1a7ec44a7ab84838ceeb3ce07f734b74`.
It remains absent from the JAR's named license members. That supplemental
notice does not establish the full native attribution set.

The acquired files refine the tooling exceptions:

| Pinned source file(s), under `native/libffi/` | Observed notice and remaining boundary |
| --- | --- |
| `LICENSE-BUILDTOOLS` | Distinguishes build/test tools; includes full GPL v2 and summarizes GPL v2 for `msvcc.sh` and `testsuite/libffi.bhaible` |
| `msvcc.sh` | Its own header offers MPL-1.1, GPL-2.0-or-later or LGPL-2.1-or-later. Retain this and the distribution summary; document the chosen route |
| `config.guess`, `config.sub` | GPL-3.0-or-later, with a specific exception for distribution within a program containing an Autoconf-generated configuration script |
| `m4/ax_cc_maxopt.m4`, `ax_cflags_warn_all.m4`, `ax_compiler_vendor.m4`, `ax_enable_builddir.m4`, `ax_gcc_archflag.m4`, `ax_gcc_x86_cpuid.m4` | GPL-3.0-or-later with an exception for generated configure output. The macro source remains subject to its GPL terms |
| `m4/ax_append_flag.m4`, `ax_check_compile_flag.m4`, `ax_configure_args.m4`, `ax_require_defined.m4` | Permissive copying/modification grant requiring preservation of copyright and notice |
| `libtool-ldflags` | GPL-2.0-or-later file header; no header output exception identified |
| `make_sunver.pl` | No individual grant found. `LICENSE-BUILDTOOLS` names it as a tool but does not include it in the subsequent GPL-v2 assignment sentence; enclosing-term/provenance review remains open |
| `include/ffi.h.in`, `ffi_common.h`, `ffi_cfi.h` | Preserve each file's distinct copyright lines; `ffi.h.in` includes MIT permission text, and `ffi_common.h` additionally names the Free Software Foundation |

Exact retained bytes and immutable URLs for these observations are in
`acquired-review.json`, with the original files under `acquired/native/libffi/`.
The source bundle's GPL-v3 text/route remains to be supplied where applicable:
`LICENSE-BUILDTOOLS` carries GPL v2, not GPL v3. These build/source conditions are
separate from whether compiled output incorporates that tooling. Do not label
the entire vendored tree MIT-only or infer that a tool's license automatically
licenses its output identically. The primary
[`LICENSE-BUILDTOOLS`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/LICENSE-BUILDTOOLS)
and [`msvcc.sh`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/msvcc.sh)
must both remain available to reviewers.
[`dlmalloc.c`](https://raw.githubusercontent.com/java-native-access/jna/cc4ce71d511a9aa17219cc36e2338dd1b0f52770/native/libffi/src/dlmalloc.c)
identifies Doug Lea's 2.8.3 allocator with a public-domain statement. Autotools
scripts/macros may carry further terms and exceptions; per-file review is still
needed. Static libgcc/CRT and JDK JNI-header terms depend on the exact supplier,
version and applicable exception; this research does not establish them.

No full source archive/native binary was downloaded and no auth/runtime file was
changed. This review lane created no containers/images/networks/volumes. The
parent's text-acquisition record identifies container
`expertauth-native-source-95c0212f31f4`, ID
`07047ab43e8b12fdfdc81b1a7c6d41e49ec0b2e1b4736190206afedc73f836da`,
and records it absent after completion. This agent did not independently query
Docker. Preserve `acquired/acquisition.json` and `acquired/container.json`. The
remaining release gates are complete source acquisition and file-specific
licensing, audited toolchain capture, corresponding native builds and tests,
recipient delivery/replacement conditions where applicable, and independent
review. Foundation status is unchanged.
