# Third-party notices — source-audit checkpoint

ExpertAuth does not claim ownership of upstream components. This checkpoint
contains independently authored audit tooling, metadata, notice copies and
verbatim source excerpts/files with their upstream terms preserved. It does not grant permission to redistribute artifacts
whose dependency or licensing boundaries remain unresolved.

* **Keycloak community**, source commit
  `6d238b6558037085cc25c915893c3d301a80243e`: Apache License 2.0. The official
  distribution contains third-party dependencies that retain their own terms.
* **SuperTokens Core**, source commit
  `b2219c4aa019a501e4dfea76cf06ef802ca93fc0`: Apache License 2.0 applies outside
  the excluded enterprise directory and third-party exceptions. Copyright
  notices include VRAI Labs and/or its affiliates. `ee/` source/binaries are
  excluded from ExpertAuth's approved reuse boundary.
* **SuperTokens plugin interface** 10.0.0 and **PostgreSQL storage plugin** 9.8.0:
  Apache License 2.0; exact source revisions and notice hashes are in
  `reuse/core-build-dependencies.json`.
* **SuperTokens SDK candidates** for Node.js, Python, Go, JavaScript, React,
  React Native, iOS, and Android: Apache License 2.0 at their source roots.
  Example and test dependencies may differ. In particular, React Native's
  vendored test copy of **tough-cookie** carries the Salesforce BSD three-clause
  license. Some example package manifests declare ISC.
* **Current Node/React example dependencies**:168 lock entries,143 installed
  Linux packages, with file/notice hashes in
  `evidence/reuse/node-current-checkpoint/report.json`. The scoped Nodemailer9.1.1
  override is MIT-0; `jose`6.2.12 is MIT. The original vulnerable graph is preserved
  separately. React and Express retain MIT notices. Build/test tools and platform
  packages retain their individual licenses, including uninstalled optional entries.
* **Python example dependencies**:49 pinned Linux/CPython3.12 wheels with file and
  license evidence in `evidence/clients/python/dependency-audit.json`. These do not
  establish support for untested operating systems or optional transports.
* **SuperTokens plugin candidates**: all pinned repository READMEs declare
  Apache License 2.0, but the referenced license file and package license text
  are absent. Exact declarations and notice gaps are recorded in
  `reuse/profiles.json`. Complete notices must accompany any future distribution.
* **OpenTelemetry bundled agents**, byte-inspected as candidate resources only:
  their embedded dependency notices are copied under `reuse/licenses/jars`.
  They are not approved for runtime or release inclusion by this checkpoint.
* **The 84 source-build Maven runtime dependencies** are enumerated, hashed, and
  linked to their captured license declarations in `reuse/runtime-dependencies.json`
  and `reuse/oss-core-runtime.cdx.json`. Licenses include Apache-2.0, MIT, ISC,
  BSD-2-Clause, the Bouncy Castle license, EPL-2.0, LGPL-2.1, and LGPL-3.0.
  Both Argon2 JVM 2.11 artifacts declare LGPL-3.0; retain their applicable
  source/notice and library-replacement obligations for distribution. POM lists
  of licenses are preserved as declarations, without silently deciding their
  AND/OR relationship. Embedded native code has additional provenance review.
* **Supplemental native attribution:** the scrypt1.4.0 release contains Colin
  Percival BSD notices in its native sources; JNA5.8.0 bundles libffi with its own
  MIT notice. Five exact supplemental files, immutable source URLs and binary
  release mappings are recorded in
  `evidence/reuse/runtime-distribution-review/supplemental-notices.json`.
  The runtime notice assembler preserves these alongside embedded notices.
  Native source/build and full applicable-license closure remain unqualified.
* **Native source review inputs:** pinned scrypt C/header/Java-test files, Argon2
  wrapper build controls, JNA/libffi build/source witnesses and SQLite build
  controls are retained under `evidence/reuse/native-correspondence`. The component
  manifests record exact source paths, Git objects, SHA-256 and file-specific
  terms. These source files remain unmodified and separately attributed. JNA's
  libffi build helpers include GPL terms and exceptions; full GPL2 is retained in
  its `LICENSE-BUILDTOOLS`, full GPL3 under `license-texts/run-01/GPL-3.0.txt`, and
  Argon2's full LGPL3 under `argon2/acquired/LICENSE.txt`. These files do not change
  ExpertAuth's own license. One unresolved JNA helper, `make_sunver.pl`, remains
  local and excluded from the source checkpoint pending its grant review. SQLite
  headers/extensions with unresolved terms were not acquired. Native rebuilds,
  recipient source/relink delivery and independent licensing review remain open.

The runtime image's `/opt/expertauth/licenses/manifest.json` binds packaged
attribution to actual JAR hashes. Source retrieval uses the83 available hash-locked
Maven siblings in `reuse/runtime-source-archives.lock.json`; those archives are
not represented as a complete native corresponding-source package or written offer.

Full captured licenses are under `reuse/licenses/`, with file-specific hashes
and provenance in the reuse manifests. Preserve relevant copyright, license,
and NOTICE material in source and binary distributions. Modified upstream
files, if any are later introduced, must be identified with a reproducible diff.
No trademark, endorsement, commercial subscription, or enterprise entitlement
is granted by these notices.

This file must be regenerated or reviewed against the final release's actual
SBOM and file manifest. The detailed audit and its remaining gaps are in
`docs/reuse-report.md`.
