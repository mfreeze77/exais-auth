# Source register

Checked September 8, 2026. Sources establish baseline facts; all architecture, requirements, milestones, and acceptance thresholds in this package are proposals, not implementation results.

## DR — Original SuperTokens Documentation and Reverse-Engineering Report

`User Library; file_00000000c7cc82309746d8702e0f075e, version 1`

Full report retrieved in this conversation; inherited feature inventory and configuration catalog.

## S01 — SuperTokens documentation navigation and architecture

`https://supertokens.com/docs`

Current documentation surface and private Core boundary.

## S02 — SuperTokens current FDI reference

`https://supertokens.com/docs/references/fdi/introduction`

Navigation contains 49 operation entries. Exact operation schemas still require version-specific capture.

## S03 — SuperTokens current CDI reference

`https://supertokens.com/docs/references/cdi/introduction`

Navigation contains 156 operation entries; version selection is tied to coreDriverInterfaceSupported.json.

## S04 — SuperTokens application and tenant semantics

`https://supertokens.com/docs/authentication/enterprise/important-concepts`

Separate app/tenant identity scopes, optional shared users, app-scoped roles with tenant assignments.

## S05 — SuperTokens session management

`https://supertokens.com/docs/post-authentication/session-management/introduction`

Access/refresh session model and lifecycle.

## S06 — SuperTokens account-linking concepts

`https://supertokens.com/docs/post-authentication/account-linking/important-concepts`

Primary and recipe identities; linking boundaries.

## S07 — SuperTokens MFA

`https://supertokens.com/docs/additional-verification/mfa/introduction`

MFA recipe and factor surface.

## S08 — SuperTokens passkeys

`https://supertokens.com/docs/authentication/passkeys/introduction`

WebAuthn/passkey product scope.

## S09 — SuperTokens Attack Protection Suite

`https://supertokens.com/docs/additional-verification/attack-protection-suite/introduction`

Eight published detection categories; beta status.

## S10 — SuperTokens MCP authentication

`https://supertokens.com/docs/authentication/ai-authentication`

Node-oriented beta with OAuth dependency.

## S11 — SuperTokens CAPTCHA

`https://supertokens.com/docs/additional-verification/captcha`

reCAPTCHA v2/v3 and Turnstile integration; React/Node scope.

## S12 — SuperTokens plugin reference

`https://supertokens.com/docs/references/plugins/introduction`

Plugin extension model; expanded navigation includes fourteen listed packages.

## S13 — SuperTokens plugin repository

`https://github.com/supertokens/supertokens-plugins`

Repository describes Apache 2.0 licensing. Inspect individual packages and dependency licenses at the chosen commit.

## S14 — SuperTokens Core license

`https://github.com/supertokens/supertokens-core/blob/master/LICENSE.md`

Apache-licensed content must be distinguished from enterprise and third-party components.

## S15 — SuperTokens enterprise license

`https://github.com/supertokens/supertokens-core/blob/master/ee/LICENSE.md`

Restricted enterprise material is excluded from unrestricted copying/production dependency.

## S16 — SuperTokens pricing

`https://supertokens.com/pricing`

Self-hosting does not remove paid-feature entitlements in the vendor distribution.

## S17 — Keycloak administration guide

`https://www.keycloak.org/docs/latest/server_admin/index.html`

Candidate identity/protocol capabilities, not proof of SuperTokens semantic equivalence.

## S18 — Keycloak extension guide

`https://www.keycloak.org/docs/latest/server_development/index.html`

Documented authentication, user storage, REST, event-listener and other SPIs.

## S19 — Keycloak license

`https://github.com/keycloak/keycloak/blob/main/LICENSE.txt`

Apache 2.0 community code.

## S20 — Keycloak container deployment

`https://www.keycloak.org/server/containers`

Production container/deployment reference.

## S21 — Core Driver Interface repository

`https://github.com/supertokens/core-driver-interface`

Reference repository; api_spec.yaml exists. A fetched raw view identified 5.2.0, so master/raw must not be assumed equal to current docs.

## S22 — Frontend Driver Interface repository

`https://github.com/supertokens/frontend-driver-interface`

Reference repository; api_spec.yaml exists. Redistribution rights require separate verification.

## S23 — MCP authorization, version 2025-11-25

`https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization`

Versioned primary reference for resource metadata, audience binding and resource indicators; not a claim that this is the newest possible future revision.

## S24 — OAuth Security Best Current Practice, RFC 9700

`https://www.rfc-editor.org/info/rfc9700/`

Do not implement Resource Owner Password Credentials as a shortcut for embedded MFA flows.

## S25 — ALTCHA open-source product boundary

`https://altcha.org/open-source-captcha/`

MIT core is a local challenge building block; commercial risk intelligence is not included in that assumption.

## S26 — Have I Been Pwned password API documentation

`https://haveibeenpwned.com/API/v3#PwnedPasswords`

Candidate breach-password data interface; validate local snapshot/download rights and footprint before selecting it.
