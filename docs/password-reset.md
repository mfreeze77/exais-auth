# Password reset candidate: working, not full PWD-006 acceptance

This page records the default upstream profile. The opt-in, source-mounted
atomic Core adaptation and its current evidence are in
[atomic-password-reset.md](atomic-password-reset.md). Its remaining SDK/linking,
migration and session-issuance race limitations are explicit there.

The Node/React example now sends a real password reset message through an
operator-configured, authenticated SMTP server using verified implicit TLS.
The maintained SDK and Core own reset tokens, password validation and password
updates. The adapter supplies plain-text mail content and uses the supported
session API after a successful reset. No authentication vendor service is used.
Without SMTP configuration, both reset endpoints are disabled (HTTP 404).

Set the commented `EXPERTAUTH_SMTP_*` settings in the example's `.env.example`.
`EXPERTAUTH_SMTP_PASSWORD_FILE` must point to a mounted, private UTF-8 file;
one optional trailing newline is removed. The file must be readable by the
application's unprivileged user. Port defaults to 465; every configured port
uses implicit TLS. Supply a private CA through `NODE_EXTRA_CA_CERTS` when needed.
The adapter rejects disabled TLS certificate verification. Links must match
the configured public origin and `/auth/reset-password` path. Production HTTPS
ingress and live mail-provider delivery have not been qualified.

## Measured evidence

`evidence/operations/password-reset/run-16` records the combined successful run:

- 10 real SMTP/HTTPS transport checks: trusted authenticated delivery access,
  wrong/missing authentication, untrusted certificates and plaintext rejection.
- 11 HTTP/SMTP checks: token issue and consumption, replay denial, weak-password
  rejection without consumption, eight concurrent consumers with exactly one
  winner, sibling-token invalidation, configured expiry, unknown email, failed
  SMTP authentication/trust/connectivity, successful manual resend, and disabled
  endpoints. Old online sessions and refresh credentials are denied after reset.
- 9 actual Chromium checks: login/logout, request email through the React form,
  follow the delivered link, change password, reject the consumed link and old
  password, authenticate with the new password, then logout without page errors.
- The separate fixture-cleanup row removes 11 owned identities and restores the
  exact original 52-identity set. All 12 temporary containers are retired;
  persistent Core/PostgreSQL processes, mounts and configuration are unchanged.

The browser aggregate and cleanup row are not extra authentication tests.
`evidence/runs/password-reset-unit-01` records 55 configuration/content checks,
including a deliberately injected error-redaction check; that injected failure
is not SMTP success evidence. Node exited 0 and stored evidence is hash-valid.
The outer wrapper subsequently failed printing Unicode on the host's cp1252
console; use `python -X utf8` for future wrapper invocations.

`cleanup-fault-01` deliberately exits the worker with code 73 after account
creation, before its cleanup. The host fallback validates ownership, deletes
exactly that account through Core, restores the original 52 identities and
retires all 6 temporary containers. Its normal `passed` remains false;
`cleanup_fault_passed` records only this intentionally injected lifecycle case.
Fallback timeouts and Docker daemon failures were not injected.

The complete updated image was subsequently built offline and tested in
`evidence/operations/password-reset/installed-deterministic-source-mode-02`. It passes the
same10 transport/11 HTTP/SMTP/9 browser checks with **no application source or
bundle mounts**, again retiring12 containers and11 identities and preserving
the original52. This also verifies the55 delivery unit checks inside the image.
The installed-image cleanup-fault and new main-deadline expiry branches were
not injected. See [the image build evidence](node-offline-build.md).

## Reproduce changed work

Use the existing private `expertauth-oss-proof` network and source Core/database.
The runners refuse missing cached images; they create no networks, volumes or
published ports. They reuse the pinned Node dependency and Playwright images.
The new mail receiver is Mailpit 1.31.1, pinned to
`ghcr.io/axllent/mailpit:v1.31.1@sha256:3856f9327f3f228afe8c4ce2dcca3cb2aa00f6ec60b569f36483f7ebb1ff44f7`.
Its one local image record is 17,164,101 bytes; no Mailpit binary enters the ZIP.
MIT notice and registry/source evidence are under `evidence/reuse/mailpit-artifact`.

From the repository root, choose fresh evidence names only when inputs or the
case under test change:

```powershell
python -B tools/build_node_client.py --name NEW_CLIENT_BUILD
python -B tools/run_password_reset_lab.py --name NEW_FULL_RESET_RUN
python -B tools/run_password_reset_lab.py --name NEW_BROWSER_RUN --browser-only
python -B tools/run_password_reset_lab.py --name NEW_CLEANUP_FAULT --cleanup-fault
python -B tools/verify_checkpoint_hygiene.py
```

The compiler runs offline inside the existing immutable Node image, checks its
installed lock and esbuild version, and overwrites only the generated client
bundle. `reset-client-03` produced the bundle tested in run-16, which used
read-only source/bundle mounts. `promoted-node-01` reproduced the same589,321-byte
bundle using the earlier image2c4ad0be07b8. The current image4c03d7306e1e
contains the same application bytes with deterministic0644 file permissions and
passes the installed-image lab. Fresh archive acquisition and disconnected
installation/compilation now pass; full fresh extraction/stack bootstrap remains
unqualified. See `docs/node-package-bootstrap.md`. The image builder command and precise prerequisites
are documented in `docs/node-offline-build.md`.
Private fixture credentials and raw logs stay under ignored `.runtime/`.

## Unfinished acceptance and disclosed failures

No foundation is selected. Configured cross-tenant/application and linked-account
cases remain blocked by the foundation; rejecting a nonexistent tenant with
HTTP 500 does not prove isolation between two configured tenants. PWD-006 is
implemented-unverified. WP-009/WP-010 and their dependencies remain open.

Password update and session revocation use separate engine calls/transactions.
A crash after password commit but before revocation can leave old sessions
usable. No atomic reset-plus-revocation claim follows. The revocation API covers
linked users across tenants within the application; only an unlinked public
tenant identity was tested. Equal known/unknown-email status and body do not
eliminate SMTP-dependent timing differences. Durable outbox/retry, delivery
policy, bounce handling and password-change notifications remain absent.

Failed runs remain evidence of failures. Early failures exposed startup logging,
partial CID-file reads, file ownership and unsupported read-only Core paths.
The runner now validates complete container IDs and uses the previously proven
Core writable-root profile with bounded temporary directories. Later browser
failures exposed unconsumed response bodies, navigation-sensitive test reads,
and a wrong placeholder selector. The actual form was inside a shadow root;
generic SDK routing was retained. Test waits and teardown are bounded.
One startup run required exact-ID follow-up container retirement, recorded in
run-02. Historical source snapshots bind run-16 and later failed variants;
the exact earlier run-01/run-02 runner bodies were not retained, although their
input hashes and available failure evidence remain. They cannot certify source
behavior. Full native/platform/live-provider and independent human security
review remain blocked. The historical file-specific reuse report preserves its
then-unresolved Nodemailer source gap; the newer
`reuse/nodemailer-9.1.1-source-correspondence.json` closes original-tarball
correspondence for its selected files. Complete distribution obligations remain open.
