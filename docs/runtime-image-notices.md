# Runtime image notices and source retrieval

The audited OSS candidate places its preserved notices under
`/opt/expertauth/licenses`. The manifest records every installed notice/POM/SBOM
file and its exact SHA-256, the applicable Maven coordinate, binary/source archive
hashes and supplemental source provenance. The runtime keeps dependency JARs
separate under `/opt/expertauth/lib` and the PostgreSQL plugin under
`/opt/expertauth/plugin`; it does not shade or encrypt those libraries.

The package preserves recognized notice texts from the84 runtime dependencies
and83 pinned Maven source siblings, inherited POM declarations, the3 own-source
Apache licenses, and5 independently reviewed scrypt/libffi supplemental notices.
These files are attribution material. Presence of a notice or source archive does
not establish complete distribution rights, native build reproducibility or
compliance with every applicable source/relink condition.

Source archives remain in a bounded cache, outside the image. Their immutable
URLs/hashes are in `reuse/runtime-source-archives.lock.json`. Existing files are
verified and reused; a changed or missing offline file fails. Normal acquisition
does not resolve newer versions, change hashes or substitute the one unavailable
Guava metadata-only source archive:

```powershell
python tools/fetch_runtime_notice_sources.py --offline
```

For missing locked sources, run the same tool without `--offline` using the pinned
Python Docker image from `docs/RESUME.md` when host networking is unavailable.
Source JARs alone are not a complete source-delivery package for all components.
See `docs/runtime-distribution-review.md` for scrypt, Argon2, JNA and SQLite native
source/build gaps, supplemental notice mappings, and LGPL/EPL review requirements.
The current implementation has no fulfilled written source offer and no final
distribution or production approval.

Build and inspect the actual image without starting Core/database services:

```powershell
python tools/launch_oss_probe.py --build-only --evidence-name NEW_UNIQUE_NAME
```

This verifies every installed JAR and notice file against the prepared context,
using a temporary container without network access. Build context and inspection
container are removed afterwards. The image uses the existing current task tag;
existing Core containers are not replaced by this command. Their actual image IDs
must match the built image before subsequent runtime qualification. Image-content
verification is separate from authentication, native-library replacement/relink,
source reconstruction, OS licensing and full release acceptance.
