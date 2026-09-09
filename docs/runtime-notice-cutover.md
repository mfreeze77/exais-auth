# Runtime notice image and private cutover

PARTIAL. The private Core now runs image
`sha256:5ec6ccc3fd5dc7eff16afa48b3bf6abdd4d378077f2428cae3abf8a8bc2e30bf`.
All479 installed files match the source-built package:87 executable JARs,
390 notice/metadata files, the notice inventory itself, and version.yaml.
The89 archive notice texts include JNA's two previously missed short-named
license texts; three scrypt header notices supplement the earlier five native
notices. This is attribution/image-content qualification, not native rebuilds,
distribution approval, engine selection or complete authentication acceptance.

The existing Docker-driver BuildKit builder was used through Docker Desktop's
installed Buildx plugin. No builder was created or global setting changed.
Build input was59,854,247bytes under one temporary workspace directory, limited
to200MiB. Builds used a cached digest-pinned Gradle base, no dependency download
instructions, a512MiB build limit and disabled RUN networking. The Docker driver
loads output into the local image store, as documented by
[Docker](https://docs.docker.com/build/builders/drivers/docker/). These options
do not prove network isolation of registry metadata resolution or full vendor
independence; the existing foundation egress tests have their separate scope.

The first BuildKit attempt built an image but failed to inspect it: this Docker
containerd image store identifies the image by OCI manifest digest while the
IID file contained its configuration digest. Its exact log and source snapshot
are in `evidence/runtime/oss-core-notices/buildkit-notices-01`. The run-specific
candidate was removed, scratch retired and previous tag preserved. The corrected
second attempt binds both digests from BuildKit metadata, verified every file
and then moved the task tag. Six steps reused cache. No source/dependency compile
was repeated. `buildkit-notices-03` then reverified that same image against the
current helper without another image build after moving private cleanup ahead
of promotion. Failure cleanup timeouts remain un-injected runtime cases.

The build helper delays tag promotion until installed bytes, source inputs and
cleanup pass. Inspection containers have exact CIDs, project/purpose/run labels,
no network, a read-only root,256MiB memory and16MiB tmpfs over the inherited
Gradle volume path. Failed-image removal requires its unique run label, matching
project/purpose, no tags/digests and no container references. No global prune,
volume removal or Docker/WSL restart was performed.

Private replacement evidence is
`evidence/runtime/oss-core-notices/replacement-20260909T021339Z-af0c4b/report.json`.
It compares all87 JARs with the existing Core, retains its logs privately, and
holds its stopped container until the replacement passes authenticated storage
readiness and all479 file hashes. New Core container is
`1849f9015945fc395fe3ec45ffbd38873e7bda3224c23cce21f60a04e85b8262`.
The old container8dae07565cf9 and image60c7677d0a91 were removed after success.
Both temporary readiness containers were removed. PostgreSQL retains container
94f223b054ba, its prior start time and named volume; no database replacement or
restore was performed. The new Core is bounded to1GiB memory,2 CPUs and256PIDs.
No load/latency qualification follows from these resource settings.

`evidence/runs/runtime-notice-cutover-01` binds both the executed replacement
helper and readiness helper before/after the run. A subsequent source-only
change also binds readiness inside the standalone replacement helper. Its exact
earlier executed source is retained next to the cutover report. The current
helper rejected a request to replace the already-current image before stopping
anything (`runtime-notice-same-image-guard-02`, expected exit1). Stopped-before-
rename and missing-new-CID rollback paths have been corrected and code-reviewed;
failure injection across the rollback phases remains unexecuted.

Post-cutover regression used the existing Python app image7a4bb6dcfd63:
19 real HTTP checks passed, none failed/skipped, and both synthetic users were
removed. See `evidence/operations/python-readiness/notice-core-regression-01`.
It created no image, network or volume. This does not extend the full Python,
native/browser/provider or original API compatibility claims.

Commands when inputs change:

```powershell
python -B tools/build_oss_runtime.py --evidence-name NEW_BUILD_NAME
python -B tools/build_oss_runtime.py --verify-existing --evidence-name NEW_INSPECTION_NAME
python -B tools/replace_oss_notice_image.py --image-report evidence/runtime/oss-core-notices/NEW_INSPECTION_NAME/report.json
python -B tools/refresh_python_image.py --test-existing --name NEW_REGRESSION_NAME
python -B tools/verify_checkpoint_hygiene.py
```

Do not repeat the cutover or unchanged passing tests for fresh timestamps.

After committing and creating a new source ZIP, qualify its extracted notice
verifier against the existing image with:

```powershell
python -B tools/qualify_notice_checkpoint.py artifacts/EXACT_CHECKPOINT.zip --sha256 EXACT_ZIP_SHA256
```

This verifies every archive member, uses hardlinks to170 hash-verified cached
JAR/source inputs and runs the extracted image inspector. It creates no images
or services, compares task containers/images/networks/volumes before and after,
and removes its temporary extraction. The adjacent `.runtime-validation.json`
retains the result and exact command logs outside the ZIP to avoid self-reference.
This is fresh-source installed-image verification; it does not constitute a
fresh build, full stack restore, native compilation or acceptance completion.

The package remains bound to the full265 requirements/205 APIs and M0–M10.
Foundation failures, native/provider tests, licensing/source obligations and
the independent human security review remain blocking acceptance gaps.
