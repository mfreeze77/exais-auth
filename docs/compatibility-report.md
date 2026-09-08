# Compatibility checkpoint — partial

The frozen205 API IDs comprise49 FDI and156 CDI operations. All IDs were resolved
to pinned source facts, yielding207 path variants. Four original path artifacts and
five newly observed upstream additions are recorded without rewriting the baseline.
No operation is certified as fully schema- and behavior-compatible. Exact schema
redistribution rights and differential/error/side-effect coverage remain unresolved.
See `contracts/README.md`, `api-contracts.json` and their source/licensing report.

The working OSS Node/React and Python examples exercise password/session subsets.
Node24.0.3 and Python0.31.3 do not automatically have identical protocol behavior:
Python requires CDI5.4; the Node proof uses current negotiated behavior with an
explicitly separate offline JWT profile. Core CDI5.3's two-phase refresh differs
from5.6 rotation. The zero-grace5.6 concurrency failure remains a blocker.

The Keycloak JSON SPI demonstrates engine-owned password and TOTP challenges,
PKCE authorization-code exchange and intermediate authentication state. It is not a
205-operation SuperTokens adapter. Candidate organization membership requires an
explicit hard gate and application-side fixed tenant selection; defaults are
insufficient. Identity-link concurrency failures prevent foundation approval.

All8 SDK,14 plugin and10 integration profiles remain required. Source pins and
license/package findings exist for every original profile in `reuse/profiles.json`.
The14 plugins are neither installed nor qualified merely because their repositories
were audited. Native/live-provider tests and full feature matrices remain open.

No production migration, rollback/restore qualification or fullM0-M10 acceptance
exists. This report describes measured subsets and gaps, not a parity release.
