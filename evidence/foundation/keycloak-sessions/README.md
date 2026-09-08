# Two-replica Keycloak candidate session evidence

Status: **PARTIAL / foundation blocked**. The actual probe executed 10 checks: 7 passed, 3 failed, none skipped or unexecuted. The engine remains unselected. This is a private candidate lab, not a production or high-availability deployment claim.

The lab uses Keycloak 26.7.3, source commit `6d238b6558037085cc25c915893c3d301a80243e`, the pinned original JSON Authenticator extension, two engine replicas with JDBC_PING/Infinispan discovery, and one shared PostgreSQL 17.11 instance. Both replicas report a two-member cluster view. The network is internal and no ports are published. `startup-report.json` preserves runtime image IDs, cluster-view log lines, configuration policy, and source hashes. `probe-command.json` preserves the exact command and nonzero exit code. `probe-report.json` contains each real HTTP result without credentials, token strings, cookies, or private fixture content.

Passing behavior: cross-replica password/TOTP authentication and PKCE exchange; verified access/ID token claims; real bearer validation on both nodes and negative signature/missing-header checks; observed HttpOnly/SameSite engine cookies and no-store token response; four alternating sequential refresh rotations; client-specific revocation preserving another client's refresh session; global RP logout clearing engine cookies and denying both clients. Both clients correctly share an engine parent `sid`; this is explicitly not considered a failure.

The realm policy is `revokeRefreshToken=true`, `refreshTokenMaxReuse=0`. Three stronger recovery expectations fail:

| Probe | Actual engine response | Remaining gap |
| --- | --- | --- |
| Stale refresh after successful rotation | Stale token: HTTP 400 `Maximum allowed refresh token reuse exceeded`; legitimate child: HTTP 400 `Session doesn't have required client` | Ordinary stale retry and confirmed compromise are not distinguished by this profile |
| Simultaneous same-token refresh on two replicas | One HTTP 200, one HTTP 400; the winner's replacement then receives HTTP 400 `Session doesn't have required client` | A race does not leave a usable rotation |
| Lost committed refresh response | The first refresh actually returns 200 and is intentionally discarded from the retrying client's perspective; retry at the other replica receives HTTP 400 reuse exceeded | No recovery from this postcommit response-loss scenario |

These are observed failures under the declared candidate policy, not a claim that all Keycloak configurations behave identically. No policy experiment, engine patch, extra session store, retry stub, or disabled test was used to hide them. The response-loss test exercises an actual committed server response that the application discards; it is not a network-level packet-drop or process-crash experiment.

`TRACEABILITY.json` maps this bounded evidence to original requirement IDs without marking any full requirement complete. The HTTP-only lab does not qualify secure public cookies, browser/native transfer, independent data-tier resilience, failover under crashes, rolling upgrade, recovery, or independent security review.

On an authorized continuation, from the ExpertAuth repository root:

```powershell
# Preserve an already-running owned lab; create it only if absent.
python tools/run_keycloak_cluster.py up
# Runs actual tests; exit 1 is expected while the three known gaps remain.
python tools/run_keycloak_cluster.py probe
# Recreate ONLY this labeled lab and its synthetic database when a fresh fixture is required.
python tools/run_keycloak_cluster.py up --reset
# Remove only this harness's labeled containers; preserve evidence/source files.
python tools/run_keycloak_cluster.py stop
```

Do not repeat probes inside the 30-second OTP reuse window; fresh isolated fixtures are available through the explicit reset command. `--reset` destroys only this lab's synthetic database in its labeled container; it must never be repurposed for production. The harness does not remove unrelated containers. Private `.runtime/cluster/` files are intentionally excluded from source archives; `up` generates them locally. Rebuilding uses exact base-image digests, strict dependency verification and Java 21. The test client uses the separately pinned and audited Python example image.
