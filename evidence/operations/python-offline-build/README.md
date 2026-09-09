# Python offline source build qualification

PARTIAL. Current image is
`sha256:5bffadb83aa3127f8339e6dcd3e8bc6a04dcbcabf3b66b7dcddfab81369e78fd`.
`buildkit-02/report.json` binds the full Dockerfile, tools, unchanged dependency
pins, input/output digests, installed audit and19 real HTTP tests. The prior
7a4bb6dcfd63 image was removed only after qualification and client cleanup.
Core/PostgreSQL IDs, start times, mounts and private ports are unchanged.

The49 cached wheels total20,367,857bytes, each SHA-256 and METADATA matched to
the existing version/hash lock. `buildkit-01` downloaded those exact public
artifacts once. `buildkit-02` downloaded nothing, verified the cache again and
reused four BuildKit filesystem steps. One cache remains under ignored
`.cache/python-wheels`; no wheels are copied into image layers. The earlier
empty-cache offline command failed explicitly without downloads.

The existing Docker-driver builder receives a
[named build context](https://docs.docker.com/build/concepts/context/#named-contexts)
and a read-only RUN mount, with build networking disabled. Installation uses
binary-only wheels and [pip hash checking](https://pip.pypa.io/en/stable/topics/secure-installs/),
`--no-index`, `--no-cache-dir`, `--no-compile` and offline `pip check`. The cached
base is pinned; no builder was created or global Docker configuration changed.

The installed audit verifies49 distributions,3,349 unchanged wheel files,
63 notice files and all418 SDK Python source files against immutable upstream
source. It includes declared License-File entries such as pycryptodome's
AUTHORS.rst. Every wheel file except pip-rewritten RECORD must match. The single
empty directory entry is recorded separately; the initial48/49 failure and
primary-source correction remain in `buildkit-01/VERIFIER_CORRECTION.md`.
This is file correspondence, not native rebuild or licensing approval.

The candidate then passed19 actual HTTP checks with zero failed/skipped tests;
both synthetic users and both app/client containers were removed. Each run has
a unique HTTP hostname and exact container ownership checks. No source overlay
is used for the running app. The behavior helper never changes image tags;
promotion belongs to the build helper after source/cache/resource checks.

Resume changed build inputs with a fresh run name:

```powershell
python -B tools/build_python_runtime.py --name NEW_UNIQUE_BUILD_NAME
python -B tools/refresh_python_image.py --test-existing --name NEW_UNIQUE_HTTP_NAME
```

Use `--fetch-wheels` only when locked cache files are missing. The helper requires
the retained component image, cached pinned base and existing private lab. Do not
rerun unchanged successful builds or recreate the retired legacy image.

Full fresh-stack/bootstrap, native wheel/source provenance, container OS/base
distribution closure, load, TLS/browser/provider profiles and independent human
review remain unqualified. The new helper's timeout/tag/cleanup fault injection
is unexecuted; source review does not pass it. The real failed-audit candidate
was retired with the prior tag preserved, and normal promotion was exercised.
No baseline requirement or SDK profile is marked verified by this evidence.
