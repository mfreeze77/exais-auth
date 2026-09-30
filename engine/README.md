# ExpertAuth Engine

The ExpertAuth authentication engine: **independently authored**, the single write authority for
identities, credentials, tenancy, sessions and signing keys (ADR-001, 2026-09-30). SuperTokens is the
functional and API **reference only**. No SuperTokens code is used. Routes and response shapes follow
the published CDI contracts captured in `../contracts/`, so reference-style backends can talk to it,
but behavior is our own design and is tested here.

Status: **first vertical slice (M1). Partial; not production-approved.** 41/41 tests pass against real
PostgreSQL. Everything not listed below is still planned; see `../ledger/implementation.json`.

## Implemented

| Area | Routes (prefix `/appid-<app>/<tenant>` optional; both default to `public`) |
| --- | --- |
| Health / version | `GET /hello`, `GET /apiversion` (advertises CDI `5.4` shapes for the implemented subset only) |
| Native multi-tenancy | `PUT /recipe/multitenancy/app/v2` (public app only), `PUT …/tenant/v2`, `GET …/tenant/list/v2`, `POST <tenant>/recipe/multitenancy/tenant/user[/remove]` |
| Email/password | `POST <tenant>/recipe/signup`, `…/signin`, `…/user/passwordhash/import`, `GET/PUT /recipe/user` |
| Password reset | `POST <tenant>/recipe/user/password/reset/token`, `…/reset/token/consume` (two-step), `…/user/password/reset` (atomic) |
| Sessions | `POST <tenant>/recipe/session`, `POST /recipe/session/refresh`, `…/verify`, `…/remove`, `GET /recipe/session` |
| Keys | `GET /.well-known/jwks.json` (unauthenticated), `GET /recipe/jwt/jwks` |

## Security design

- **Identity:** email identities are tenant-scoped. The same email in two tenants is two identities.
  Sharing across tenants happens only through explicit association, and a conflicting email is refused.
  There is no global unique-email constraint. Apps are isolated namespaces with separate signing keys.
- **Passwords:** new credentials use argon2id, by default m=19456 KiB, t=2, p=1. Imported bcrypt
  (`$2a/b/x/y$`, cost 4–16) and argon2 id/i/d hashes must be structurally valid and within cost
  bounds, and are rehashed to the configured argon2id on the next successful login. The rehash is a
  compare-and-swap, so it never decides acceptance. Bodies are always decoded as strict UTF-8, and
  invalid bytes are refused. Unknown accounts still do argon2 work, so response time doesn't reveal
  whether an email exists. Hashes never appear in any response.
- **Sessions:** RS256 access tokens use reference-compatible claim names (`sub`, `rsub`, `tId`,
  `sessionHandle`, `refreshTokenHash1`, `antiCsrfToken`). Protected claims can't be overridden by user
  data. Refresh tokens are opaque and stored only as SHA-256 digests. Refresh rotation:
  - The successor is `HMAC(EXPERTAUTH_REFRESH_SECRET, handle | parentDigest)`, so concurrent or retried
    refreshes with the immediate parent inside `EXPERTAUTH_REFRESH_GRACE_SECONDS` (default 5) receive
    the **same** successor. Eight concurrent refreshes produce one rotation.
  - Reusing a parent after the window, or any older token at any time, is theft: the session is revoked
    and `TOKEN_THEFT_DETECTED` is returned. A grace of `0` is available as a strict, opt-in policy.
  - `verify` with `checkDatabase: true` observes revocation immediately. Without it, verification is
    offline JWT validation until expiry, which is a separate, documented profile.
- **Reset:** tokens are 384-bit random and stored as SHA-256 digests. Consuming a token, replacing the
  password and revoking every session commit in one transaction. The token row is locked, so exactly
  one concurrent consumer wins. A successful reset spends all of the account's outstanding tokens. An
  expired token spends only itself. Tokens are bound to their tenant and to the email they were issued
  for.
- **Operations:** API keys are required on every route except `/hello` and JWKS, and compared in
  constant time. Private signing keys are sealed with AES-256-GCM under `EXPERTAUTH_KEY_ENCRYPTION_KEY`.
  Schema install is idempotent under an advisory lock, which is safe with several replicas. Internal
  errors return `500 Internal Error` without details. A dropped idle database connection doesn't crash
  the process.

## Run

```bash
npm ci
export EXPERTAUTH_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/expertauth
export EXPERTAUTH_API_KEYS=<20+ chars [A-Za-z0-9=_-], comma-separated for rotation>
export EXPERTAUTH_KEY_ENCRYPTION_KEY=$(openssl rand -base64 32)
export EXPERTAUTH_REFRESH_SECRET=$(openssl rand -base64 32)
npm start            # listens on 127.0.0.1:3567 unless EXPERTAUTH_HOST/PORT are set
```

Optional: `EXPERTAUTH_ACCESS_TOKEN_SECONDS` (3600), `EXPERTAUTH_REFRESH_TOKEN_SECONDS` (100 days),
`EXPERTAUTH_REFRESH_GRACE_SECONDS` (5, max 60), `EXPERTAUTH_RESET_TOKEN_SECONDS` (3600),
`EXPERTAUTH_ARGON2_MEMORY_KIB`/`_ITERATIONS`/`_PARALLELISM`, and `EXPERTAUTH_ISSUER`. Invalid values
refuse startup. Keep the two secrets in a secret store: losing the key-encryption key loses the
signing keys, and changing the refresh secret invalidates in-flight grace retries.

## Test

```bash
npm run typecheck
EXPERTAUTH_TEST_ADMIN_URL=postgresql://postgres:<pw>@127.0.0.1:5432/postgres npm test
```

Each test file creates and drops its own database. The suites cover identity and multi-tenancy (10),
sessions and refresh (13), reset (5), and config/routing/primitives (13).

## Known gaps (open, tracked)

The engine has no rate limiting or abuse controls yet; it is designed to sit behind the application
backend. `PUT /recipe/user` changes a password without revoking sessions (the reference two-step
flow); the atomic reset route does revoke. Still missing: email verification, account linking,
passwordless, third-party/OAuth/SAML, MFA/TOTP/WebAuthn, roles, metadata, user search, key rotation,
user-ID mapping, audit/outbox, the remaining CDI routes, SDK/FDI backends, the dashboard and control
plane, plus load, HA, backup and independent security review. All 265 requirements remain binding.
