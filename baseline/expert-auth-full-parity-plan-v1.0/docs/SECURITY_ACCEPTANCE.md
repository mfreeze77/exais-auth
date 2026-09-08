# Security and operational acceptance specification

These are **proposed mandatory tests**, not passing results. Sources: [DR], [S04–S10], [S23, S24]. Every case needs exact versions/configuration, synthetic fixture IDs, observed outcomes and reviewed evidence. Tests must use owned or explicitly authorized systems. Never publish live credentials in fixtures, traces or reports.

## A. Trust boundaries and tenant isolation

| Test | Required result |
|---|---|
| Public request to private CDI or database | Network policy blocks access; no privileged endpoint is accidentally proxied. |
| Backend without API authentication or using retired key | Request rejected; key-rotation overlap works only for explicitly active keys. |
| Tenant ID replaced in URL, header, body or token context | Membership and app scope are revalidated; no data/credential/provider crossover. |
| Host/proxy header spoofing | Tenant/origin resolution trusts only configured proxy boundaries and allowed domains. |
| Same email, two apps and two tenants | Identity scope follows selected isolated/shared mode; no accidental linking. |
| Shared identity, different tenant roles | Authorization uses the authenticated tenant, not the most privileged role anywhere. |
| Delegated administrator invokes platform operation | Denied server-side even when the UI is bypassed. |
| Valid token accesses other tenant's record/search result | Resource authorization denies access independently of authentication success. |
| SSRF through provider metadata, webhook or custom URL | Private/admin endpoints and unintended outbound destinations remain unreachable. |
| User enumeration through discovery/reset/lookup | Behavior matches the declared API/security profile; rate limits and anti-enumeration policy are tested rather than assumed. |

## B. Password, OTP and account recovery

| Test | Required result |
|---|---|
| Sign-in, reset or OTP brute-force across IPs/replicas | Account/tenant and network controls remain effective without a simple per-process bypass. |
| Simultaneous reset/OTP/link consumption | At most one security-changing consumption succeeds under the defined contract. |
| Expired code, wrong tenant, wrong flow or substituted recipient | Rejected without exposing challenge secrets or creating identities. |
| Resend after exhausting attempts | Does not reset protection or silently extend lifetime beyond policy. |
| Email-link preview fetch | Does not create an unintended authenticated account/session; deliberate consumption policy is tested. |
| Password change or email change via profile API | Requires appropriate recent authentication and verification; protected fields cannot be mass assigned. |
| Imported hashes | Each supported algorithm/version has representative positive and negative fixtures; rehash policy is measured. |
| Missing/nonportable hash | Explicit reset or authorized migration route; no invented default password. |
| Recovery after all devices lost | Flow requires declared sufficient evidence; recovery cannot silently bypass stronger tenant policy. |
| Delivery timeout/retry or duplicate callback | No duplicate security state transition; bounded outbox retries and protected payloads. |

## C. Sessions and refresh transactions

Run refresh tests through at least two engine replicas against authoritative shared state. Inject failures before commit, after commit but before response, and after response transmission begins.

| Test | Required result |
|---|---|
| Same current refresh token sent concurrently | Deterministic policy; atomic rotation prevents two unrelated valid successor chains. |
| Previous token reused after lost response | Behavior follows the frozen, documented retry/reuse policy; not blanket acceptance of stale tokens. |
| Stolen stale token outside accepted retry semantics | Rejected and revocation/theft handling follows policy. |
| Logout followed by refresh | Refresh fails. |
| Logout followed by still-valid offline access JWT | Report the real residual acceptance window; do not assert immediate revocation. |
| Online revocation profile | Old session/token denied within the measured declared propagation bound, including replicas/caches. |
| Logout/ban/membership removal concurrent with refresh | Revocation or removal wins according to the declared transaction order; no resurrection. |
| Restart after refresh commit | Authoritative verifier state survives and previous credentials do not regain validity. |
| Key rotation and old token overlap | Valid expected overlap works; unknown/retired keys fail after the defined boundary. |
| Signing-key or DB unavailable | Failures follow declared policy; liveness is not mistaken for readiness. |
| Cookie transport | Secure/HttpOnly/path/domain/SameSite attributes and CSRF protections are correct in the selected browser deployment. |
| Header transport | Credentials stay out of URLs, logs and unsafe storage; authorization headers are not sent to untrusted origins. |
| Concurrent browser tabs and frontend retries | Refresh coordination prevents storms, infinite loops and overwritten new credentials. |
| SSR, WebSocket, iframe, mobile resume | Each supported profile handles expiry and reauthorization explicitly; browser security restrictions are not represented as bypassed. |
| Anonymous session promoted to user | Rotation and identity binding prevent session fixation or privilege inheritance. |
| Administrator impersonation | Explicit permission, reason/audit, actor+subject identity, lifetime and prohibited-action rules remain enforced. |

## D. Identity linking and factors

| Test | Required result |
|---|---|
| Unverified equal email or claimed domain | Insufficient to link accounts or acquire membership. |
| Verified account linking | Evidence proves control under configured trust rules; primary/method ID resolution remains consistent. |
| Link/unlink race | Unique ownership invariants hold; no partial transfer of roles, credentials or tenant association. |
| Last login method removed | Explicit safe rejection or controlled alternative recovery, not accidental lockout. |
| Add MFA device from old session | Appropriate recent authentication and policy gate required. |
| TOTP replay in accepted time window | Prevent replay for the protected action according to declared factor semantics. |
| Recovery code reused | Fails after atomic first use; stored verifier does not expose plaintext recovery codes. |
| New factor or recovery resets privileges | Step-up claims and session freshness reflect the actual verified factors, not a client flag. |
| Passkey wrong RP/origin/challenge | Rejected; registration and authentication state are one-time and bound to context. |
| Passkey migration to different domain | Nonportable credentials trigger re-enrollment rather than false claims of transparent migration. |

## E. OAuth, SAML, M2M and MCP

Use the frozen supported standards profile and maintained conformance tools where suitable. A standards test suite is evidence for its tested profile, not proof that every product workflow is correct.

| Test | Required result |
|---|---|
| OAuth code intercepted/replayed or wrong verifier | PKCE and one-time authorization-code controls reject the request. |
| Redirect URI/state/nonce/issuer mismatch | Rejected; no open redirects or issuer confusion. |
| Password-grant shortcut | Not implemented as a substitute for first-party embedded authentication [S24]. |
| Token intended for different resource/client | Audience/client binding enforced; no generic accept-any-valid-JWT logic. |
| SAML malformed XML, signature wrapping, wrong audience/recipient | Maintained parser/signature validation rejects invalid assertions with no unsafe XML expansion. |
| SAML assertion replay or expired assertion | Rejected; time skew and replay cache semantics are explicit. |
| Provider metadata/certificate rotation | Validate ownership/trust and support overlap without trusting unapproved keys. |
| Machine client secret retired | Old secret fails after intended overlap; permissions remain tenant/resource scoped. |
| MCP discovery/resource metadata | Matches selected protocol version; missing or malformed metadata has controlled errors. |
| MCP wrong-audience bearer or unauthorized tool | Denied even where another tool/resource is authorized. |
| Dynamic client registration | Implement only as required/allowed by the chosen profile; do not treat it as mandatory in every MCP version. |
| Logout across relying applications | Session termination behavior is tested and bounded; browser-cookie clearing alone is insufficient evidence. |

## F. Risk quality and CAPTCHA

Freeze a labeled evaluation corpus before evaluating. Include legitimate travel, VPNs, shared NAT, accessibility tooling, low-powered devices, device resets, cookie blocking and simulated malicious patterns. Record dataset versions/licenses and privacy constraints.

Required outputs: signal availability, missing/unknown rate, false-positive rate, missed attacks by category, action outcomes, decision latency, and minimum local protection when a feed is stale. Product/security owners set acceptance thresholds before measurement. Until those thresholds and evidence exist, quality remains unqualified.

A detector returning a plausible score without using meaningful evidence fails. A missing signal must not become an invented safe verdict. A CAPTCHA challenge must be bound to the correct site/action/transaction, expire, and reject replay. Locally operated challenge completion is not proof of complete bot detection or equivalent proprietary requester recognition.

## G. Migration, data recovery and upgrades

Reconcile identities, primary/method mappings, memberships, roles, verification, metadata, sessions, factors and credentials. Record intentional nonportable material; there must be zero unexplained discrepancies. Validate actual authentication with representative imports, not counts alone.

Test backups with encryption keys and signing-key state in a clean deployment. Determine how restored session/recovery state avoids resurrecting credentials revoked after the snapshot. A recovery procedure may intentionally invalidate restored sessions; that decision must be explicit and tested. Protect rollback from destructive database downgrades and reintroducing already migrated stale credential state.

Set RPO, RTO, load and revocation targets before production qualification. Measure recovery and requalification against those targets; do not label unmeasured operations highly available. Configuration-only backups are not sufficient for identity data recovery.

## H. No mandatory authentication-vendor fees

In a prebuilt isolated environment, block outbound authentication-vendor domains and reject unlisted outbound destinations. Exercise local authentication, sessions, factor enrollment/recovery, administration, roles, linking, tenant provisioning, local risk, local CAPTCHA, migration and export. Ensure no activation key, SaaS dashboard, feature seat or trial countdown is needed.

Run social IdP, mail and SMS integration tests with separately declared operator-selected network/provider prerequisites. These external transports are not auth licensing, and their costs are not represented as eliminated. Check runtime dependencies as well as source licenses, including optional downloaded binaries that could otherwise silently reintroduce vendor services.

## Release decision

The author of security-critical custom code is not the sole reviewer. Independent review covers code, configuration, threat model and evidence. Resolve exploitable critical/high findings before production approval. Never replace the acceptance report with a test count, route count, coverage percentage or attractive UI demonstration.
