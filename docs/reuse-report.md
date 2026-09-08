# ExpertAuth source reuse and licensing audit checkpoint

Audit date: 2026-09-08 UTC. This report records immutable candidate sources and
real package/archive inspection. It does not select an identity engine, qualify
any SDK, or approve a production distribution. Requirements BAS-002, BAS-004,
and BAS-005 remain subject to complete dependency, build, and release evidence.

`reuse/engine-candidates.json`, `reuse/core-build-dependencies.json`, and
`reuse/profiles.json` are the component index. `reuse/files/` and
`reuse/package-files/` record individual paths, SHA-256, source revision, license
declaration, copyright header excerpts, decision, modifications, dependency
boundary, and qualification limitations. The original registries were not
modified. All eight SDK, fourteen plugin, and ten integration profile IDs remain
present. The current audit validation checks 68 consistency assertions; these
are **source-audit checks, not authentication tests**.

## Engine candidates and source-only build boundary

| Component | Release | Immutable source commit | License boundary |
|---|---|---|---|
| Keycloak community | 26.7.3 | `6d238b6558037085cc25c915893c3d301a80243e` | Root `LICENSE.txt` Apache-2.0; distribution dependency notices still required |
| SuperTokens Core | 12.2.0 | `b2219c4aa019a501e4dfea76cf06ef802ca93fc0` | Apache-2.0 outside `ee/`; original licenses govern third-party components |
| Core plugin interface | 10.0.0 | `2550750188069110753decd06265a59fadefb427` | Apache-2.0 |
| PostgreSQL storage plugin | 9.8.0 | `0b68fd14ca10baee2d0e3c31466984fccfb36c8a` | Apache-2.0 |
| SuperTokens root helper repository | master snapshot | `25d24162afe78488899ebceff81821549470b273` | No license file found; reference only, do not copy tooling |

The Keycloak primary release API reported publication on 2026-08-31, including
security fixes. The Core primary release API reported publication on 2026-09-04.
Full release notes and download digests are retained in the candidate index.
An older cached engine release is not qualified by this audit. Keycloak's
official 26.7.3 tarball digest is
`77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47`.
That is release metadata, not a claim that this audit downloaded or verified the
entire Keycloak binary distribution.

The Core root license explicitly reserves `ee/` to its separate enterprise
license. Only that license was inspected. Source archive traversal skipped all
23 `ee/` paths before reading or extracting their contents; the manifest records
their exclusion and deliberately does not claim their content hashes. There are
941 non-enterprise archive files with hashes. The raw download cache must not be
included in a release because the compressed upstream archive itself includes
the excluded directory.

Core archive SHA-256:
`3c1e2d3e9367b02e0daf12ea99404379921297574e20f47c684fe1dff76cd25c`.
Plugin-interface archive SHA-256:
`2b98a97f122126654a383159497e156e279242018bb8a0f34669428527d41049`.
PostgreSQL plugin archive SHA-256:
`aa6e3ff64f90227f43d515cc382ff04085cbb283074486befb2d259325e45b94`.

Core and the PostgreSQL plugin both declare plugin-interface series `10.0` in
their immutable `pluginInterfaceSupported.json`. Core requires Java 21 and
Gradle AspectJ plugin 8.13. Source compatibility declarations establish the
candidate combination; compilation and runtime evidence establish whether it
works.

An independently authored Gradle root may include precisely:

```groovy
rootProject.name = 'expertauth-core-proof'
include 'supertokens-core'
include 'supertokens-plugin-interface'
include 'supertokens-postgresql-plugin'
```

Use pinned Java 21/Gradle 8.13 build tooling and explicit tasks. Run the storage
plugin's `generateMetaInf` before processing its resources, so its ServiceLoader
declaration is present. Then build the three JARs and collect runtime dependencies
with their `copyJars` tasks. This describes the audited source boundary; the
authoritative executed build and any build corrections are recorded under
`evidence/build/` by the engine build tooling.

Do not execute these upstream convenience paths:

* `supertokens-core/runBuild` unconditionally invokes `ee/runBuild` after other
  modules. A successful root build could therefore incorporate restricted code.
* `.github/helpers/build-core-packages.sh` can fetch `ee.jar` from upstream
  artifact storage. `.github/helpers/Dockerfile` includes `ee/*` on its runtime
  classpath. Their convenience does not establish an unrestricted distribution.
* Prebuilt `jar/core-12.2.0.jar`, `cli/jar/cli.jar`, and
  `downloader/jar/downloader.jar` are not replacements for source build evidence.

No entitlement check was patched, removed, spoofed, or bypassed. The absence of
an enterprise binary does not itself provide the advanced behaviors that its
licensed product implements. Those behaviors remain required and must be
implemented lawfully without adding a competing credential/session authority.

Two third-party JARs are bundled under Core `src/main/resources`:
`opentelemetry-javaagent.jar` (manifest 2.29.0) and
`opentelemetry-jmx-metrics.jar` (manifest 1.56.0-alpha). Their archive hashes,
embedded notice paths, manifests, and nested package metadata are in
`reuse/bundled-telemetry-jars.json`; copied notices are under `reuse/licenses/jars`.
They are not automatically Apache merely because the enclosing repository is.
Their nested artifact provenance and advisory closure are not yet qualified;
omit them from the minimal source build until those obligations are resolved.
This is a build boundary, not removal of the required observability behavior.

An extraction race was diagnosed during the first source-build verification:
the audit reran extraction while the builder hashed a file, exposing a transient
truncated file. A reread matched the immutable hash. Extraction now skips
identical files and replaces changed files atomically. Engine builds and source
refreshes must still be serialized. Case-varying directory names exist, so use
the manifest paths and preferably a Linux filesystem for compilation.

## SDK candidates

Every package pin is a candidate, not an asserted compatible combination.
The profile index retains the complete original profile record alongside the
candidate revision, package dependency constraints, release metadata when
available, file manifests, and advisory queries.

| Profile | Family | Candidate version | Immutable commit |
|---|---|---|---|
| SDKP-01 | Node.js | 24.0.3 | `9b82aefb46da4c0f0a388d8f6656c39a62d7642c` |
| SDKP-02 | Python | 0.31.3 | `b498da1a6d09ca84ca204ac881df76900df19175` |
| SDKP-03 | Go | 0.26.0 | `11fc3b06a06a1050d95dbdb4c404c24b0f8639c6` |
| SDKP-04 | JavaScript | 0.16.0 | `be2e0fd7dcade8352cdc9639abe968e5cda5b1cd` |
| SDKP-05 | React | 0.51.3 | `5d080836741561af3bda5461e1e993d2c4088b3b` |
| SDKP-06 | React Native | 5.1.5 | `ebae74d8661e24759f6f943d457d045d08087e61` |
| SDKP-07 | iOS | 0.4.2 | `3f26d38882cecff7505a9c772fe4a38cd9ce55c6` |
| SDKP-08 | Android | 0.5.3 | `40aaebeaf0e88f63300f1f5c7e474bd1656750e3` |

All eight source roots provide Apache-2.0 license text. The Node and React source
trees include separately declared example-package licenses, including ISC;
these declarations are recorded at their file boundaries. React Native's
`TestingApp/test/tough-cookie/LICENSE` is the Salesforce BSD three-clause license
and is a test dependency exception. No native source build or device lifecycle
test was performed by this source audit. Original SDK feature support remains
language-specific and must be qualified against the selected API contract.

## Fourteen plugin surfaces

| Profile | Package suffix under `@supertokens-plugins/` | Candidate version |
|---|---|---|
| PLGP-01 | captcha-nodejs | 0.2.1 |
| PLGP-02 | captcha-react | 0.3.1 |
| PLGP-03 | opentelemetry-nodejs | 0.1.2 |
| PLGP-04 | profile-base-react | 0.1.0 |
| PLGP-05 | profile-details-nodejs | 0.1.0 |
| PLGP-06 | profile-details-react | 0.1.0 |
| PLGP-07 | progressive-profiling-nodejs | 0.3.0 |
| PLGP-08 | progressive-profiling-react | 0.3.1 |
| PLGP-09 | tenant-discovery-nodejs | 0.2.1 |
| PLGP-10 | tenant-discovery-react | 0.1.0 |
| PLGP-11 | tenants-nodejs | 0.2.0 |
| PLGP-12 | tenants-react | 0.2.0 |
| PLGP-13 | user-banning-nodejs | 0.2.1 |
| PLGP-14 | user-banning-react | 0.2.1 |

For every row, the published npm tarball's SHA-512 integrity was verified, every
package file was hashed, the npm `gitHead` was pinned, and the exact source
`packages/<suffix>/package.json` was matched by package name and version. The
fourteen pins span seven immutable source commits, all recorded in
`reuse/profiles.json`.

All seven pinned repository READMEs explicitly declare Apache License 2.0.
However, their linked `LICENSE` file is absent, every published plugin tarball
omits license text, and eleven package manifests omit a license field. This is
an explicit upstream license declaration with incomplete license packaging;
it is not evidence of an enterprise license. Retain the declaration's source
hash and obtain complete applicable notices before redistribution. Per-file
and transitive dependency review must not be replaced by the repository badge.

Two immediate compatibility conflicts were identified:

* `captcha-nodejs@0.2.1` declares `supertokens-node ^23.0.0`, while the current
  Node SDK candidate is 24.0.3.
* `captcha-react@0.3.1` declares `supertokens-auth-react ^0.50.0`, while the
  React SDK candidate is 0.51.3.

Resolve and test supported combinations or label a reviewed adaptation. Do not
declare all upstream latest releases mutually compatible. Hosted CAPTCHA
provider integrations also do not prove the required local CAPTCHA/risk path.

## Advisory coverage, evidence, and remaining work

All 22 direct SDK/plugin candidates were queried against OSV using exact npm
name/version or source commit as appropriate. These queries returned no listed
vulnerabilities at their recorded observation times. This is limited direct
query evidence: it does not cover every transitive dependency, establish that
every ecosystem maps commits, prove current native maintenance, or substitute
for a security assessment.

The executed Maven runtime collector inspected all **84** dependency artifacts
from the successful source build. All 84 JAR hashes match the build inventory,
all 84 have captured POM license declarations (including inherited declarations),
and all 84 exact Maven OSV queries completed with no listed advisory. Embedded
JAR notices were preserved where present. The first parser missed Bouncy Castle
POM licenses because those valid POMs omit an XML namespace; the parser was
corrected and the complete collector rerun. No missing POM-license declaration
or artifact hash mismatch remains in `reuse/runtime-dependencies.json`.

This closure has material license exceptions: both Argon2 JVM 2.11 packages
declare LGPL-3.0; AspectJ declares EPL-2.0; Logback declares EPL-2.0 and
LGPL-2.1; JNA declares LGPL-2.1 and Apache-2.0 (its embedded notice expressly
permits a choice); Cryptacular declares Apache-2.0 and LGPL-3.0; Bouncy Castle
uses its own permissive license; PostgreSQL uses BSD-2-Clause; jBCrypt uses ISC.
Do not relabel them all Apache or infer an AND/OR license relationship merely
from a POM list. Preserve separate, unmodified libraries for the local proof.
Final LGPL/EPL source, notice, replacement/relink, and distribution obligations
remain a release review item. Argon2, JNA, and SQLite JARs also bundle native
libraries whose nested source provenance is not fully qualified by POM metadata.

`reuse/actual-build-files.json` binds **1,293 actual source-build input files** to
their audited archive hashes, exact destination paths, declarations, and real
build-command evidence. All hashes match. It records eligibility for local
testing under the captured OSS terms, without selecting the engine or approving
release. `reuse/oss-core-runtime.cdx.json` contains the 84 Maven runtime artifacts
as a CycloneDX 1.6 SBOM; its scope is explicitly smaller than the final product
SBOM. Build tools, OS images, SDK transitive closures, data licenses, and omitted
telemetry resources require their own boundaries. Dashboard, ALTCHA, password/IP
datasets, and protocol-schema redistribution are not declared audited here.

No source-audit check qualifies an authentication requirement. All 32 original
SDK/plugin/integration profiles remain functionally unverified here. Missing
provider credentials, native toolchains/devices, and independent security review
remain visible qualification blockers in the implementation ledger.

Reproduce inspection in the repository's pinned Python container (the host's
network stack was unavailable during this run):

```text
python tools/audit_sources.py --engine-probe --core-source --profiles --source-profiles --auxiliary --bundled-jars --validate
python tools/audit_sources.py --dependencies evidence/build/oss-core/dependencies.json
python tools/audit_sources.py --bind-build
python tools/audit_sources.py --validate
```

Downloads stay under `.cache/reuse-audit`; exclude that directory from release
artifacts. Cached discovery responses preserve this snapshot, not a promise that
`latest` remains unchanged on a later date. Command arguments, timestamps,
Python version, script hash, stdout/stderr, and exit status are persisted for
new runs under `evidence/reuse/runs/`. The machine-readable evidence and the
separate implementation ledger control acceptance.
