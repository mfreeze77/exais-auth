# ExpertAuth execution checkpoint

Status: **PARTIAL, active implementation. No engine selected; M0/M1 not closed.**
All 265 required rows and 205 API IDs remain required. No baseline requirement is
verified as a complete acceptance row. Tests below prove narrower cases only.

Original extracted baseline: 20/20 manifest files verified by size and SHA-256;
265 requirements, 29 families, 36 packages, M0-M10, 49 FDI/156 CDI, 8 SDK,
14 plugin and 10 integration profiles preserved. Original ZIP was not supplied;
its expected checksum remains recorded. Research report is available and preserved.

Actual code and evidence:

- Immutable contract extraction: 205 IDs / 207 path variants; 29 contract-tool tests.
  Source facts/hashes retained; no copied unlicensed schemas or behavioral pass claim.
- Fail-closed ledger/release gate with adversarial tests; full completion correctly fails.
- Core12.2.0/plugin-interface10.0.0/PostgreSQL-plugin9.8.0 compile from pinned source.
  84 runtime JARs audited; no EE JAR. Two real replicas were tested on a private network
  with PostgreSQL17.11 and vendor egress blocked. Source-build and probe evidence under
  `evidence/build/oss-core` and `evidence/foundation/oss-core`.
- OSS Core probe: 12 narrow passes, 5 unavailable. Native app/tenant provisioning
  and linking return402 without entitlements. CDI5.6 with zero refresh grace kills
  a legitimate concurrent refresh session. No license enforcement was altered.
- Python/FastAPI: 19 real HTTP tests passed for default-app/public-tenant password
  and online sessions, cookie/header/CSRF/logout. Full Python profile remains open.
- Node/React:12 live HTTP checks and4 actual Chromium checks pass. Password signup,
  wrong-password rejection, signin, logout/cookie clearing and320px layout are tested.
  Explicit offline JWT issuer/audience verification is separate from online revocation.
  Earlier SDK offline assumptions, invalid React component and overflow failures remain.
- Keycloak26.7.3: organization proof12 passes; JSON password/TOTP proof16 passes.
  Real broker/linking characterization17 passes/2 failures: concurrent ownership and
  final-method unlink. Independent persistence reread confirmed both. No correction
  was implemented after automatic review rejected the agent's hardening turn.
- Keycloak PostgreSQL two-replica probe:7 passes/3 failures. Cross-replica login,
  serial rotation and client revocation work; strict reuse/concurrent refresh and
  lost-response retry fail. Cluster startup does not close those cases.
- Keycloak representative Node backend/React/Python clients:17 real HTTP and5
  Chromium checks pass with supported basic/organization scope configuration,
  PKCE/CSRF/state guards and engine-owned password/TOTP/session behavior. Full
  FDI/CDI/SDK coverage and preauthentication replica failover remain unqualified.
- Fresh isolated OSS build consumed strict checksum/lock verification and reproduced
  all87 JAR hashes. Source fetch reconstructed1300 permitted files with zero EE paths.
- Four original Unicode path ambiguities (FDI-026, CDI-099, CDI-104, CDI-116) now
  have independently authored Apache-source and runtime resolutions:9 actual checks
  passed. The original capture is unchanged. CDI-104's legacy identifier discrepancy
  is explicit; this does not close full schema or operation qualification.
- The exact `69c68e8b4994` source ZIP was freshly extracted, manifest-checked and its
  Node/React and Python images built from the extraction.12 Node HTTP,19 Python HTTP
  and4 Chromium checks passed. Existing Core/PostgreSQL were reused; this is not a
  fresh full-stack restore, migration or complete release qualification. See
  `evidence/extracted-checkpoint/README.md` for the exact ZIP and source bindings.

Disk/Docker hygiene:15 temporary task containers,8 stale image tags,4 networks and
463,715,868 bytes of duplicate scratch were removed. Only Core-a and PostgreSQL
remain as containers, with6 retained task image tags. Retired H2 databases and raw
proof logs were backed up and their hashes verified. No volumes were deleted;
unrelated projects/shared base images were outside scope. Candidate labs and example
servers are stopped/removed, not currently running. See `evidence/operations/hygiene`.
The updated archive runner retires its own resources and fails on cleanup errors;
its12 integrity/filesystem tests passed, but its revised full Docker flow has not
been rerun. `AGENTS.md` requires the same lifecycle for all further work.

Runtime notice packaging now runs in Core image `60c7677d0a91`:474 installed files
were hash-verified, including87 unchanged executable JARs,87 embedded notice texts,
and5 supplemental scrypt/libffi notices mapped to release bytes. The83 available
Maven source archives are locked and verified offline in the existing43MB cache;
the one unavailable Guava source sibling corresponds to a metadata-only binary.
Eight archive/provenance/notice tests pass, including tamper rejection and identical
notice-tree reproduction. This is packaging evidence, not full license approval.

Core-a was replaced only after verifying all87 JARs equal the running old image.
Authenticated storage readiness passed before/after; PostgreSQL/config were preserved,
old Core logs retained privately, and the old container/image retired. This did not
rerun the historical full auth cases or exercise the replacement script's rollback
branch. Its initial preflight refused an inherited Gradle volume; the corrected path
recognizes that mount and uses16MiB tmpfs for the unused Gradle cache. Two old caches
were retained after a nonempty check; their combined file content is385,398 bytes.
Only Core-a/PostgreSQL remain as containers, with6 retained task image tags.

Full notices for other uncovered dependencies, native source/build/relink obligations,
container OS review and independent distribution approval remain open. Four native
bundles need further work: scrypt, Argon2, JNA and SQLite JDBC. See
`docs/runtime-distribution-review.md` and `evidence/runtime/oss-core-notices`.

Editable ledger currently maps19 requirements to partial implementation,10 to blockers,
7 to failed candidate checks and229 to planned work. All205 API rows remain blocked
for complete contract/runtime qualification. These are statuses, not a completion rate.

Read `BLOCKERS.md`, `docs/adr/001-foundation.md`, and the current evidence before
continuing. Candidate labs are experiments, never competing product authorities.
No publication, paid resource, production change or remote push is authorized.

Resume/check commands from this repository:

```powershell
git status --short --branch
python tools/ledger.py check
python tools/capture_contracts.py --validate
python tools/validate_release.py --output evidence/integrity/current-release-check.json
docker ps --filter label=org.expertauth.purpose=oss-foundation
```

The release validator is expected to exit1. Do not convert incomplete contracts,
provider/native tests, review or dependency gates into passes to make it exit0.

Current next work: finish M1 supported extension proofs; settle one authoritative
engine only after identity/link/session/headless/client gates converge. Continue
vertical slices and carry all requirements and original profiles through selection.
