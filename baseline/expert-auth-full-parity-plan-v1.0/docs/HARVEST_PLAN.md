# Open-source reuse and independent extension plan

This is a **repository/subsystem selection and audit plan**, not a completed file-specific source harvest. No immutable commits or full transitive dependency audit have yet been completed. M0 must produce the file-specific manifest before copying code. The reference inventory and public repository availability do not establish that every file or runtime dependency is freely redistributable.

## Candidate reuse map

| Candidate | Intended use | Audit / technical gate |
|---|---|---|
| `keycloak/keycloak` | Initial engine candidate, protocol implementation, administration primitives, supported provider/authentication/event extensions. | Apache community boundary [S19]; chosen release advisory/license audit; pass all M1 identity/session/embedded-flow cases. |
| `supertokens/supertokens-core` | Alternative candidate when preserving Core identity/session/recipe semantics is substantially more reliable than remapping another engine. | File-level rights and runtime dependency closure; exclude unapproved `ee/` components [S14, S15]; source build with no paid activation. |
| `supertokens/supertokens-node`, `supertokens-python`, `supertokens-golang` | Backend protocol/middleware behavior; candidate maintained SDK reuse. | Pin each repo/package and license; trace any feature checks or external services; qualify original language-specific feature profiles. |
| `supertokens/supertokens-web-js`, `supertokens-auth-react` | Browser/session APIs and UI customization baseline. | Package/license/dependency audit; test cookies/interceptors/hooks against the selected engine adapter. |
| `supertokens/supertokens-react-native`, `supertokens-ios`, `supertokens-android` | Native session/authentication integration reuse. | Confirm currently authoritative repo/package names and versions, audit licenses, build in supported native toolchains, test lifecycle/deep links. |
| `supertokens/dashboard` | Candidate user/admin UI structure. | Check current license/dependencies and API assumptions; no platform admin access is granted merely because a UI is reusable. |
| `supertokens/supertokens-plugins` | Fourteen documented plugin surfaces [S12, S13]. | Check every package and dependency, preserve notices and review commercial/external-service boundaries. |
| `supertokens/core-driver-interface`, `frontend-driver-interface` | Protocol reference and behavioral test fixtures [S21, S22]. | Verify exact version alignment and rights before redistributing schema files. A public repo is not a blanket license grant. |
| ALTCHA core | Candidate local proof-of-work/challenge primitive [S25]. | Confirm pinned MIT-core boundary and dependency licenses; do not incorporate commercial risk features by assumption. |
| Approved local password/IP datasets | Optional selected inputs required for operational local risk detection. | Verify source, license, update rights, footprint, provenance and staleness behavior before choosing a dataset. |

Do not harvest every candidate engine into production. M1 selects one credential/session authority. Other candidate repositories remain comparison evidence unless a separately bounded, licensed, non-competing utility is intentionally reused.

## File-specific manifest required in M0

For every copied, modified, vendored or build-fetched file record: repository, release, full commit, original path, content hash, license/SPDX identifier, copyright/notices, dependency origin, destination path, modifications, purpose, tests, security sensitivity, upstream tracking owner and update strategy.

Decisions are `depend`, `extend`, `fork`, `independently implement`, `reference only`, or `exclude`. No unknown license is treated as approved. License review applies to containers, vendored libraries, generated assets, runtime downloads and code snippets—not only the repository root.

Prefer upstream supported APIs and extensions. Keep patches small and carry a reproducible diff. Avoid moving security-critical code into a language rewrite merely for uniformity. Fork when needed for ownership and specific requirements, not because a long-lived fork is automatically cheaper to maintain.

## Restricted material and independent implementation

Do not copy or alter restricted enterprise code, patch license validation, distribute enterprise binaries, or fabricate entitlement responses. Build missing business behavior from public contracts, standards and authorized observations, with independently authored code and provenance. Obtain qualified licensing review for final distribution decisions; this plan is not a legal opinion.

Because this is an OSS reuse-plus-extension project, do not label the entire result a strict clean-room implementation. Reused licensed code should be identified as such. Separately developed proprietary-feature equivalents must have their own source/provenance record, without claiming access to hidden vendor implementation details.

## Build and update gate

A clean source build must produce the pinned engine/SDK/plugin artifacts without an unapproved download or activation. Preserve notices in distributions. Generate the software bill of materials and verify the runtime feature graph. Triage security advisories before pinning and on each update. Avoid permanently freezing an authentication fork merely because the initial release worked.

The first engineering deliverable is an actual manifest and gate report—not a claim that these candidate rows already constitute a completed harvest.
