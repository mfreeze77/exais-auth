# Compatibility checkpoint — partial

The frozen205 API IDs comprise49 FDI and156 CDI operations. All IDs were resolved
to pinned source facts, yielding207 path variants. Four original path artifacts and
five newly observed upstream additions are recorded without rewriting the baseline.
No operation is certified as fully schema- and behavior-compatible. Exact schema
redistribution rights and differential/error/side-effect coverage remain unresolved.
See `contracts/README.md`, `api-contracts.json` and their source/licensing report.

The working OSS Node/React and Python examples exercise password/session subsets.
The new Node/React reset subset uses optional authenticated TLS SMTP and engine
reset APIs. Run-16 passes11 HTTP/SMTP and9 browser checks plus10 transport checks.
The current installed Node image `9375a5bc093d` passes 34 behavior checks for
the opt-in atomic profile, with no app source/bundle mounts. Core uses the exact
two-JAR adaptation. A new Core paired with its old PostgreSQL plugin correctly
rejects readiness and session creation without issuing credentials or adding a
session. The healthy writer can retry. Its dependencies match the prior audited
tree; the earlier Node image `4c03d7306e1e` was retired. See
`docs/atomic-node-installation.md` for the exact scope and preserved failed run.
The package bootstrap now passes actual registry acquisition and disconnected
installation/compilation with the same dependency bytes. This Linux x64/glibc
proof does not qualify any excluded native platform or change the full profiles.
Neither proof qualifies a complete SDK/API profile or a fresh identity-stack deployment.
Nonexistent-tenant rejection is distinct from configured-tenant isolation.
No original API ID is promoted by this result. See `docs/password-reset.md`.

The current Python image `5bffadb83aa3` passes19 HTTP regression checks after the
readiness correction. Its public `/ready` response still uses the same healthy
shape, but now requires authenticated exact Core storage access as well as CDI5.4.
Both successful and failed readiness responses prohibit caching. A real database
outage now returns503 while `/live` remains200; after database recovery the
existing refresh/logout flow passes. This is a representative operational result,
not full OPS-004/OPS-011 or production routing qualification. Exact before/after
source and image evidence are in `evidence/operations/python-readiness`.

Node24.0.3 and Python0.31.3 do not automatically have identical protocol behavior:
Python requires CDI5.4; the new Node24.0.3 wire trace actually observes CDI5.4 on
session operations across two Core replicas. Its separately declared offline JWT
profile remains distinct. Core CDI5.3's two-phase refresh differs
from5.6 rotation. The zero-grace5.6 concurrency failure remains a blocker.

The candidate `OSS-NODE-CDI54-LEGACY-V1` policy preserves the frozen CDI5.3
contract and all original IDs. Real SDK tests recover from dropped refresh
requests/responses, including partial-body transmission, and retain committed
promotion after an abrupt temporary-Core restart. Default SDK theft handling
revokes the family; an uncoordinated raw-header race consequently loses its
selected child. That availability case remains failed. These observations do
not qualify all transaction failures or the other SDK/platform profiles. See
`evidence/foundation/sdk-session-faults` and `session-policy-review`.

The Keycloak JSON SPI demonstrates engine-owned password and TOTP challenges,
PKCE authorization-code exchange and intermediate authentication state. It is not a
205-operation SuperTokens adapter. Candidate organization membership requires an
explicit hard gate and application-side fixed tenant selection; defaults are
insufficient. Identity-link concurrency failures prevent foundation approval.
Its representative Node backend/React/Python client proof passes17 HTTP and5
Chromium cases. Corrected fixtures use the supported basic scope to produce `sub`
and the signed organization string-array shape. Final guards were not weakened to
accept a missing subject. Exact builds, commands and prior failures are retained.

All8 SDK,14 plugin and10 integration profiles remain required. Source pins and
license/package findings exist for every original profile in `reuse/profiles.json`.
The14 plugins are neither installed nor qualified merely because their repositories
were audited. Native/live-provider tests and full feature matrices remain open.

No production migration, rollback/restore qualification or fullM0-M10 acceptance
exists. This report describes measured subsets and gaps, not a parity release.
