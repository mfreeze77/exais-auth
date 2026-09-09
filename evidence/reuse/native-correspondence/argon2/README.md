# Argon2 JVM 2.11 source correspondence

PARTIAL. The local verifier matched eight native resources in the runtime JAR,
the same eight in its source sibling, and17 Java files in the nolibs source JAR
to wrapper release commit `a6a6ecd15c344983d5955cad6c8e7cb73dd1c1c1`. It also
verified31 acquired build/notice/documentation files totaling47,540bytes. See
`release-bindings.json` for exact SHA-256, Git object identities and source URLs.
No native build, platform test, source-delivery compliance or engine acceptance
is established by these comparisons.

The general compile guide does not select a native revision. However, the pinned
[Linux build script](https://github.com/phxql/argon2-jvm/blob/a6a6ecd15c344983d5955cad6c8e7cb73dd1c1c1/libargon2/context/build-libargon2.sh)
selects PHC release tag20190702 and produces four Linux architectures. This is
a concrete source lead missing from the earlier guide-only review. That tag still
needs immutable commit resolution and a complete native source/notice inspection.
It does not establish the provenance of the four Darwin/Windows resources.

The retained Dockerfile uses an unpinned Ubuntu16.04 tag and mutable apt packages.
It identifies historical compiler families without locking the actual toolchain,
sysroot, compiler runtimes or archive digest. None of these build scripts were
executed. The wrapper's LGPL3 text is retained verbatim in `acquired/LICENSE.txt`;
incorporated GPL3 terms are in `../license-texts/run-01/GPL-3.0.txt`. Preserving
texts does not demonstrate replacement/relinking or recipient source access.

Reproduce the read-only archive/source comparisons into a new report:

```powershell
python -B tools/qualify_native_argon2.py --output evidence/reuse/native-correspondence/argon2/NEW_REPORT.json
```

The output refuses overwrite. Inputs are existing archives and small pinned
metadata/source files. No Docker or network is used by this verifier.
