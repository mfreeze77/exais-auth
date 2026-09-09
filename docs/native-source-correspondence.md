# Native source correspondence checkpoint

PARTIAL. WP-002 has additional source evidence and a corrected notice packager;
no foundation, native platform, complete requirement or distribution approval
passes from this work. The265 requirements,205 API entries and original profiles
remain binding.

| Component | Locally verified evidence | Still needed |
| --- | --- | --- |
| scrypt1.4.0 |32 source/build/test files and3 native release members;6 explicit BSD C/header notices | Native build/copy wiring, compiler/JDK/system inputs, static runtime correspondence and platform tests |
| Argon2 JVM2.11 |8 native release members,17 Java sources and31 acquired text files | Immutable PHC20190702 resolution, all native sources/terms, Darwin/Windows recipes, toolchains, source/relink delivery and platform tests |
| JNA5.8.0 | Pinned508-file source inventory;47 acquired witnesses;25 native members identified through the release JAR | Full source acquisition, generated Ant/JNI inputs, file-specific grants/exceptions, historical toolchains/static runtimes and platform tests |
| SQLite JDBC3.45.1.0 |23 native,57 cached Java/C and3 cached license/POM release matches;26 acquired build files | Amalgamation acquisition/hash, JNI/extension grants, platform/compiler/runtime correspondence and tests |

Exact component reports and immutable source URLs are under
`evidence/reuse/native-correspondence/{scrypt,argon2,jna,sqlite}`. The acquired
JNA `make_sunver.pl` has an unresolved grant; it is preserved locally and excluded
from Git/source ZIP export. Its path, Git identity and SHA-256 remain in the
manifest. SQLite's six JNI headers and extension remain reference-only. Source
verification in a newly extracted ZIP cannot claim those missing inputs present.
Full GPL2/GPL3 and applicable LGPL3 texts accompany the captured source files;
copyright headers and build-tool exceptions are retained verbatim. This is not
an independent legal opinion or approval to redistribute the complete runtime.

The notice packager now includes two previously missed full JNA license texts
(`META-INF/AL2.0`, `META-INF/LGPL2.1`) and three exact scrypt header notices. Its
actual generated tree has89 archive notice texts and390 files in total, including
existing supplemental material/POMs/manifests. The five new files are verified
against source bytes; previously preserved third-party notices remain unchanged.
The currently running Core image has its historical notice manifest. Installing
the corrected package requires a newly qualified image and scoped replacement.
No image was built or service replaced by this source/packaging checkpoint.

Ten tests pass: eight actual cached-archive/package checks and two source-request
tests, including13 real CLI rejections before any acquisition. They are tooling
and package checks; no authentication acceptance is inferred. Independent agents
also verified source mappings and found the request guard flaws subsequently
corrected. These agents do not satisfy the required independent human review.

Source capture uses a cached Python image with `--pull=never`, `--rm`, a256MiB
memory limit and16MiB tmpfs. Only the capture script, request and bounded output
are mounted for subsequent requests. Cleanup verifies the exact CID, image, name
and both task labels before removal; cleanup errors remain failed with evidence.
Six successful captures retained126 responses totaling1,433,007bytes. Historical
fetch-tool snapshots are retained alongside their source hashes. Every successful
capture container was confirmed absent. No image/network/volume was created.

Commands for changed inputs or a new qualified checkpoint:

```powershell
python -B -m unittest discover -s tests/reuse -p "test_*.py" -v
python -B tools/verify_notice_revision.py --output evidence/reuse/native-correspondence/notice-packaging/NEW_RUN
python -B tools/verify_checkpoint_hygiene.py
```

Do not rerun unchanged successful operations only to refresh timestamps. Resolve
the documented source/license/toolchain prerequisites before native builds; do
not download full native archives or create platform images without a bounded
need and cleanup accounting.
