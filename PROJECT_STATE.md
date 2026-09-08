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
  84 runtime JARs audited; no EE JAR. Two real replicas on private Docker network
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
