# Locked Node package acquisition

The Node archive cache can now be populated from the exact public registry URLs
and SHA-512 integrities in the committed lock. It no longer depends on extracting
the retired image's npm cache. This is a tested Linux x64/glibc package bootstrap;
the first complete image and identity-stack deployment on an empty machine remain
unqualified.

From the repository root, with the pinned Node base already cached:

```powershell
python -B tools/run_node_bootstrap.py --name NEW_CACHE_CHECK --mode offline
# Only when archives are missing and registry access is intended:
python -B tools/run_node_bootstrap.py --name NEW_CACHE_ACQUISITION --mode online
```

Both commands preserve existing evidence and use the single
`.cache/node-packages` directory. The current cache contains 143 files totaling
14,891,202 bytes: 141 unique archives totaling 14,580,488 bytes plus its lock and
manifest. Those archives supply 143 applicable packages; 25 other platform
packages remain explicitly excluded from this Linux build, not from the full
acceptance contract. Do not delete this cache to repeat an already passing test.

The downloader allows only HTTPS `registry.npmjs.org` archive URLs without an
alternate port, credentials, query or fragment. Redirects are rejected. It checks
the locked SHA-512 and gzip header before writing, then verifies the persisted
SHA-256. Downloads are sequential, bounded to 15 seconds each and 180 seconds
overall; archives are limited to 32 MiB and the cache to 128 MiB/512 packages.
Unknown files, links and corrupt entries fail closed and are preserved. An
exclusive acquisition lock prevents concurrent writers; the authoritative cache
inventory is reread after acquiring it. Existing manifest bytes stay unchanged.

## Actual proof and its limits

`evidence/operations/node-bootstrap/fresh-registry-03` passes 11 checks with zero
skips. Three online cases perform 141 real fresh downloads, reject a concurrent
writer without another request, reacquire exactly one missing archive, and reject
a real response against an intentionally wrong integrity without persisting it.
Eight offline cases cover unchanged reuse, empty/corrupt/link/oversize/unknown
cache and wrong-origin rejection, plus actual fresh installation and compilation.

The runner disconnected its container from the bridge and verified zero network
attachments before `npm ci --offline --ignore-scripts` and `node build.mjs`.
All 7,629 original archive members match the 143 installed packages. The complete
dependency inventory, including modes and links, matches the previous image.
All eight application files match their expected bytes with explicit `0644`
permissions; the comparison discloses normalization of the historical application
file modes. The later corrected Dockerfile is qualified separately by the full
image build; this fresh-cache proof retains its earlier Dockerfile snapshot.

This proof used one existing Node base and one temporary container, no host npm
cache mount, no image download/build, new volume or network. Its cache and build
tree lived in bounded tmpfs mounts; the container was removed and the exact
container/image/network/volume inventories were preserved. `/work` explicitly
permits execution for esbuild; `/cache` and `/tmp` do not. Docker documents that
[tmpfs can use swap](https://docs.docker.com/engine/storage/tmpfs/), so this is not
a claim of zero physical disk writes.

For a changed acquisition implementation that needs the actual registry probe:

```powershell
python -B tools/run_node_bootstrap.py --name NEW_FRESH_PROBE --mode online --probe
```

Do not repeat downloads just to obtain a newer timestamp. The pinned
[Node HTTPS API](https://nodejs.org/download/release/v22.23.2/docs/api/https.html)
provides the TLS transport; no new npm runtime dependency or SDK patch was added.

The failed `fresh-registry-01` retains the actual default-tmpfs `noexec` failure,
confirmed by `tmpfs-diagnosis-01`. `fresh-registry-02` compiled successfully but
failed the strict inventory comparison on seven application file modes. Its
`--rm` cleanup also raced an explicit removal; a separate exact-ID observation
proves it was already absent. Both reports remain failed. The corrected probe
normalizes only file modes and accepts an auto-removal race only after observing
exact container absence.

A process crash may leave a stale acquisition lock or partial archive. Crash-safe
cache recovery is not qualified: preserve the exact evidence and inspect the
owner/entry before any repair. Actual HTTP timeout, redirect, oversized-response
and truncated-response fault injection remain unexecuted. A missing-archive
resume pass does not close those crash/fault cases.

Actual npm output reports deprecation/maintenance warnings for `scmp` 2.1.0,
`@simplewebauthn/types` 12.0.0 and `crypto-js` 4.2.0. The lock is unchanged; a
compatible maintained replacement/update remains to be evaluated. Original byte
correspondence does not establish maintenance, native source/toolchain
correspondence, OS distribution rights or independent security/license approval.
No requirement, API, SDK profile or milestone is certified by these tooling checks.

`evidence-validation-02.json` separately verifies 89 source, command-log and
inventory facts without rerunning the registry probe. The earlier validator
incorrectly expected CRLF in the one-line Dockerfile change; its failed report
and exact source remain preserved. The correction checks the actual LF bytes.

To recheck retained evidence after an integrity concern, without Docker work:

```powershell
python -B tools/verify_node_bootstrap_evidence.py --output evidence/operations/node-bootstrap/NEW_INTEGRITY_REPORT.json
python -B tools/verify_node_build_evidence.py --build-name deterministic-source-mode-02 --output evidence/operations/node-image-build/NEW_INTEGRITY_REPORT.json
```

## File-specific reuse boundary

| File | Implementation and reuse |
|---|---|
| `tools/fetch_node_packages.mjs` | Locally authored acquisition and lock handling; Node standard library plus the unchanged local exporter selectors, path rules and SRI helpers |
| `tools/run_node_bootstrap.py` | Locally authored bounded Docker orchestration, source/log bindings and exact resource retirement; Python standard library |
| `tests/reuse/node_bootstrap_probe.mjs` | Locally authored real registry, concurrency, cache and offline-install probes; existing local runtime archive verifier and pinned npm/esbuild |
| `examples/node-react/Dockerfile` | Local deterministic file/directory permissions; same pinned Node base, lock, SDKs and recipes |
| `tools/build_node_runtime.py` | Local installed-file permission gate and confirmed-absence handling for automatic container removal |
| `tools/verify_node_build_evidence.py` | Local evidence checker now requires an explicit build name and checks any declared deterministic app mode |
| `tools/verify_node_bootstrap_evidence.py` | Local standard-library comparison of retained source, command streams, actual test rows and inventory bytes; no additional runtime test claim |
| `tools/retire_bootstrap_checkpoint_zip.py` | Reuses the repository's exact-pin/CRC/member/Git-ancestry retirement checks with this checkpoint's three pinned ZIPs; one-time action already completed |

Exact source hashes and snapshots are retained beside each run and mapped in
`ledger/implementation.json`. Existing third-party notices and licenses remain
binding; this change introduces no entitlement override or second identity engine.
