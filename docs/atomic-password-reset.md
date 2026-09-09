# Atomic password reset candidate

This is an explicit, opt-in Core adaptation for the existing password method.
It is working reference code, not foundation selection or complete PWD-006
acceptance. The Node profile is `EXPERTAUTH_RESET_POLICY=atomic-v1`; the default
remains the separately characterized upstream profile. Both use one Core-owned
identity/session database. No entitlement check or license boundary is changed.

The adapted Core issues a context-bound opaque token in its existing reset-token
table. Its context includes the application, tenant, primary identity, password
method and email. Consumption locks and rechecks that identity and token, updates
the password using Core's configured hasher, deletes sibling reset tokens and
deletes existing sessions in one storage transaction. Internal and external user
ID mappings are resolved inside that transaction. A context mismatch, expiry,
ambiguous method or cross-storage-pool identity fails closed. No adapter writes
identity, token, password or session tables directly.

The private POST APIs are `/expertauth/password/reset/token` (`userId`, `email`)
and `/expertauth/password/reset` (`token`, `newPassword`), under the existing Core
application/tenant routing. They inherit Core's API-key, recipe and namespace
guards. Successful replies carry `EXPERTAUTH-ATOMIC-RESET-1`; issuance returns
`token`, and consumption returns `userId`, `recipeUserId`, `email`. Rejection uses
fixed status codes in JSON; transaction failures return HTTP500 with
`ATOMIC_RESET_OPERATION_FAILED`. Password form validation remains in the SDK;
the private Core endpoint additionally rejects empty or over4096-byte values.
These extension APIs do not replace or certify any of the205 baseline APIs.

The Node implementation uses supported SDK function/API overrides. It validates
the committed identity returned by Core and never falls back to the original
multi-call reset path after an atomic API failure. It accepts one private Core
URL, bounds responses at64KiB, rejects redirects and uses a15-second deadline.
Readiness combines a storage query with a deliberately malformed token request
that returns before password hashing or storage writes. Missing extension APIs
produce503 readiness. Actual ingress traffic removal is not qualified by this
local check.

## Evidence and exact binary

`evidence/operations/core-reset-build/compile-03` records offline compilation with
the cached JDK21 Core image. Candidate JAR SHA-256:
`8fc49b17a4521b8d704a27a39bcfac1aab3821db854bc7ee5f10c3c73dde9523`.
It is1,254,808 bytes.557 original JAR members remain byte-identical, two Webserver
classes are replaced, and three extension classes are added. The two source
registration additions are recorded in the modified Webserver source. No
enterprise member, entitlement alteration, new dependency or new image is used.

`evidence/operations/atomic-reset/run-02` contains eight real Core checks: private
API authorization; malformed/tampered input; successful reset and revocation
across two replicas; replay/sibling denial; eight concurrent consumers with one
committed winner; an actual database transaction abort and retry; external-ID
session revocation; configured expiry. The fault probe first blocks the session
delete after password/token writes, identifies that exact blocked backend in the
owned disposable database, and terminates it. Old password and sessions remain
usable after the abort; retrying the same token succeeds and revokes them.
The test uses PostgreSQL's documented [blocking-process inspection](https://www.postgresql.org/docs/17/functions-info.html)
and [backend termination](https://www.postgresql.org/docs/17/functions-admin.html).
It does not write application tables. Five temporary containers were retired.

The Node/SMTP/React runs use the same JAR and exact read-only application source
mounts over the cached Node dependency image. `atomic-reset/node-01` and its
`password-reset/atomic-node-01` child passed30 transport, HTTP and browser checks;
all15 containers were retired. The reset-success screenshot was inspected.
`node-02` adds a real older-Core mismatch test; product checks pass but overall
preservation verification fails because Docker returned unchanged mount entries
in a different order. Keep that failed report. The corrected runner compares
all mount values in stable order and saves both source projections.

Latest combined rerun and token migration evidence is in
`evidence/operations/atomic-reset/node-03` and its `password-reset/atomic-node-03`
child:13 HTTP/SMTP,10 TLS and9 browser checks pass, with fixture cleanup also
passing. All17 containers were retired; before/after source projections and
complete resource inventories match. No original database connection was made.
The Core transaction proof and Node HTTP proof are separate,
bound to the same binary; the latter does not inject a database abort itself.

`evidence/operations/atomic-reset/evidence-validation.json` passes105 read-only
source/snapshot/JAR/license/evidence correspondence checks. These are integrity
checks, not additional authentication behavior or independent security review.

## Migration and qualification boundaries

Atomic tokens start with `ear1.`. Existing upstream tokens are rejected without
consumption; an explicit new reset request is required. The migration test uses
a real Core-issued legacy token, proves rejection leaves it intact and the old
password/session usable, then issues an atomic replacement and exercises reset
and revocation. No data migration or mass token invalidation is implemented.

The original private Core reset APIs still exist and do not acquire these new
atomic semantics. A deployment mixing old reset writers with the new profile
is unqualified. The Node override does not implement upstream optional automatic
account linking, email-verification side effects or creation of a password method
for a social-only identity. The example initializes EmailPassword and Session
only. Native SDK migration, rollback, linked and configured multi-tenant/app
contexts remain blocked pending a capable unrestricted foundation and tests.

A sign-in that validates the old password before reset and creates its session
after the reset commits is a separate unresolved race. The tested guarantee
covers existing sessions deleted in the transaction. It does not make offline
access tokens immediately invalid. Lost committed responses, post-commit SDK
identity lookup failure, timing privacy, durable mail outbox, full transport and
platform matrices, final engine distribution and independent human security
review remain unqualified. None of265 requirements is promoted to verified.

## Reproduce without image accumulation

The current candidate cache is `.cache/core-reset/core-12.2.0-atomic-reset.jar`.
The compiler refuses to overwrite an existing candidate or evidence directory.
Use the retained candidate for unchanged source. For an empty cache, after the
documented OSS source/runtime bootstrap, run:

```powershell
python -B tools/build_core_reset.py --name NEW_COMPILE_NAME
python -B tools/run_atomic_reset_lab.py --name NEW_CORE_RUN
python -B tools/run_atomic_reset_lab.py --name NEW_NODE_RUN --with-node
```

The lab checks current Java/compiler bytes against the recorded compile-03 build
and the exact candidate JAR. A changed extension requires an explicitly reviewed
new candidate/build-report binding before those commands can proceed. The
cached image IDs and existing internal network are prerequisites; this is not a
fresh-host deployment claim. Installed Node image4c03d7306e1e contains the earlier
server, and the adapted JAR is not promoted to the running Core image. Source
mounts are explicit in the lab evidence. Both persistent services stay untouched;
all test databases are disposable tmpfs with no published ports or new volumes.
Docker logs are capped at1MiB per new lab container. The single candidate cache
adds about1.25MB; no new Docker image is retained for this adaptation.

File-specific upstream paths, commits, SHA-256 values, licenses and retained
license texts are in `engine-extensions/core-reset/reuse.json`. New Java source
is Apache-2.0. This file report does not resolve the pre-existing full native/OS
distribution or independent licensing-review blockers.
