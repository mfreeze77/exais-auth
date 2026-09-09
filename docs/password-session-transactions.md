# Password validation and session creation

The [installed Core qualification](installed-atomic-core.md) now covers both
images without healthy-path JAR/application mounts, including real local
upgrade/rollback continuity. Its compile-04 supersedes the old compiler-image
dependency while preserving the tested JAR bytes.

The later [installed Node qualification](atomic-node-installation.md) passes
34 behavior checks, including the missing-writer deployment fault. Node now
contains this integration in its image; Core still uses the two JAR mounts.
The original source-mounted results and limitations below remain historical.

The opt-in `atomic-v1` Node profile now prevents its password sign-in/signup
flows from creating a usable session based on a password invalidated by the
atomic reset operation. Core validates the password with its existing hasher,
prepares tokens with its existing minting code, then locks and rechecks the
credential and identity mapping and inserts the session in one transaction.
Tokens are returned only after commit. The reset operation takes the same
engine-owned user lock. Neither Node nor the control plane writes identity or
session tables or keeps a second session store.

Core's original session method retains its default behavior. A new optional
insertion callback lets the private `/expertauth/password/session` API use a
transaction-aware PostgreSQL writer. The writer adapts the original session
INSERT columns and parameters and uses the provided transaction connection;
it does not open or commit its own connection. Token preparation occurs before
the transaction to avoid borrowing a second connection while holding a user
lock. The PostgreSQL provider is loaded through the existing plugin classloader
using [Java's service-provider mechanism](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/ServiceLoader.html).
Its explicit single-writer selection rejects unsupported/ambiguous storage.

The Node integration uses supported API overrides, a network interceptor and
request-scoped AsyncLocalStorage. Credentials exist only within the current
sign-in/signup call and are cleared afterward; they are not added to userContext
or logs. The SDK continues creating the session object, cookies and headers.
The private Core session request is rewritten only for the matching configured
Core origin and tenant. Readiness requires the new writer capability as well as
storage and atomic reset. No fallback is used when these APIs are unavailable.

## Executed proof

`evidence/operations/atomic-reset/session-02` passes the existing eight Core
reset checks and eight new password-session checks:

- Private capability authorization and real token/online/refresh behavior.
- Incorrect passwords, email substitution and empty credentials rejected.
- Reset acquires the lock first: the already validated old password cannot
  create a late session; the new password works.
- Session insertion acquires the lock first: reset subsequently revokes that
  session and its refresh credential.
- An actual database backend termination while insertion waits on a table lock
  leaves zero sessions; the same password can retry successfully.
- Eight legitimate concurrent session creations across two Core replicas pass.
- External user-ID mappings retain the correct session subject.

Both requests are observed waiting on the actual `app_id_to_user_id` row lock
before the test releases the blocker. This exercises PostgreSQL's documented
[row-lock ordering](https://www.postgresql.org/docs/17/explicit-locking.html),
not a mocked race. Test SQL takes locks, inspects state, and terminates only an
identified backend in the owned disposable database. Six containers were removed.

`atomic-reset/session-node-02` and its `password-reset/atomic-session-node-02`
child pass 14 HTTP/SMTP, 10 actual TLS and 9 Chromium behavior checks. Eight
concurrent users preserve their own subjects. A separate test-only fetch observer
records 36 real successful session requests to the new private API, each with
`EXPERTAUTH-PASSWORD-SESSION-1`, and zero legacy session requests. It changes no
request/response bytes and records no credentials or token bodies. Fixture
cleanup also passes; all 17 containers were retired. The persistent database was
never contacted, and the original Docker resource inventory is restored.

The failed `session-01` test targeted the wrong table: Core's user lock is on
`app_id_to_user_id`, not `all_auth_recipe_users`. Its failed result and exact
source are retained; the corrected test matches the pinned plugin source.
`session-node-01` failed before signup because an extracted override-proxy method
lost its required receiver. The fix calls the original method through its proxy
object. All failed-run resources were removed; neither failure was waived.

## Binary, source and license correspondence

`password-session-build/compile-03` includes explicit modification notices in the
generated Session/Webserver sources. A fresh offline compilation produces exactly
the same tested binary bytes as `compile-02`:

| Candidate | Bytes | SHA-256 |
| --- | ---: | --- |
| Core | 1,258,481 | `eba1922f796368b4c8df7dc0cc5eaaa0dfe8ba96490a6bd44e18e7b97a1310a6` |
| PostgreSQL plugin | 408,242 | `d7a7ae7cefd18724658e3bc24f3351bcacc69439245433429d10879da487624c` |

Three original Core class members change (Session and two Webserver classes);
eight extension class members are added. Every original PostgreSQL plugin
member remains unchanged; one provider class and its service declaration are
added. Original source-built JARs, audited sources, entitlement checks and
running services are preserved. No Docker image or dependency was downloaded
or built. File-specific provenance is in `reuse/password-session-components.json`.
It explicitly distinguishes current source checks from prior Node TypeScript
archive manifests whose source files are not retained in the sparse cache.
The file-specific report records the runtime-tested compile-02 adaptations;
compile-03 retains those bytes and adds the source modification notices.
Native/OS distribution and complete transitive maintenance/source provenance
remain unqualified. This is not independent human licensing or security review.

## Scope and resumption

The new private API currently declares CDI 5.4, matching the tested Node SDK.
Original private Core session writers, other SDK profiles, configured application
and tenant namespaces, linking/MFA/step-up, lost committed responses, audit
delivery, missing-writer deployment faults, pool saturation/load targets,
rolling deployment and independent human review remain unqualified. This closes
the demonstrated race for this explicit
password-session/reset profile; it does not qualify all SES-001/005/006 or
PWD-006 behavior or remove any original requirement. All 265 requirements,
205 APIs and original SDK/plugin/integration/milestone profiles remain required.

The retained candidate consists of two JARs under `.cache/password-session`.
The superseded 1,254,808-byte reset-only JAR was retired after exact member/hash
and unmounted-state checks; its original source/build evidence remains available.
The current source/binary/runtime correspondence report passes 128 integrity
checks, separate from the executed authentication behavior above.
Use the recorded build with fresh run names when implementation changes warrant
testing; do not rerun unchanged passes for timestamps:

```powershell
python -B tools/run_atomic_reset_lab.py --name NEW_CORE_RUN --session-build compile-03
python -B tools/run_atomic_reset_lab.py --name NEW_NODE_RUN --session-build compile-03 --with-node
```

For an empty candidate cache, after the documented original source/runtime
bootstrap, use `python -B tools/build_password_session.py --name NEW_BUILD` and
pass that build name to the lab. To verify identical source-only build changes
against the existing cache, use a new name and `--verify-existing compile-03`;
the tool refuses different binary bytes and never replaces the retained JARs.
The labs require the existing pinned images and private network. They use
explicit read-only JAR/application mounts. No installed-image or fresh-host
deployment claim is made; the retained Core/Node images still contain earlier
code. Foundation selection remains pending. Keep missing live-provider/native
execution and independent review visibly blocked.
