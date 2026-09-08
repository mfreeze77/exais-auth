# Keycloak identity characterization checkpoint

Status: **BLOCKED for foundation acceptance; characterization preserved.**

The parent stopped this lane before any identity-hardening implementation. No
`engine-extensions/keycloak-identity-safety` directory, extension JAR, schema
change, provider override, or runtime hardening configuration was created.
No further concurrency or security probes should be inferred as authorized by
this handoff. The original acceptance contract and requirement IDs are unchanged.

## Files to checkpoint

- `tests/foundation/keycloak_identity.py`: actual owned-provider browser/PKCE
  characterization, not product authentication code.
- `evidence/foundation/keycloak-identity/results.json`: latest complete result.
- `evidence/foundation/keycloak-identity/attempts/*/results.json`: all three
  historical result files, including earlier narrower coverage and both failures.
- `evidence/foundation/keycloak-identity/independent-persistence-reread.json`:
  separate process and fresh administrative authentication, read-only persistence
  confirmation after the latest completed probe.
- `evidence/foundation/keycloak-identity/source/*.java` and `source/manifest.json`:
  eighteen Apache-licensed upstream files with exact source paths, commit and
  SHA-256. Ten of these were downloaded during the final source-interception
  investigation; that already-running read-only download completed, but its
  proposed interception route was not implemented or runtime-qualified.
- This handoff and `checkpoint-files.json` bind the preserved current bytes.

The source is pinned to Keycloak 26.7.3 commit
`6d238b6558037085cc25c915893c3d301a80243e`. Original copyright/license headers remain
in the source. These are review evidence, not modified upstream engine files.

## Completed execution and results

The completed characterization command, run from the repository directory, was:

```powershell
docker run --rm --network expertauth-foundation-kc --env-file 'C:\Users\mfrie\Ai_Projects\exai auth\expert-auth\.runtime\keycloak\bootstrap.env' --mount 'type=bind,source=C:\Users\mfrie\Ai_Projects\exai auth\expert-auth,target=/work' -w /work python:3.12-slim python -B tests/foundation/keycloak_identity.py
```

This is a historical command, not a request to repeat the stopped tests.
It used the existing private Keycloak candidate and uniquely named new fixture
realms. It did not use a password grant, fabricated successful broker callback,
pre-seeded bearer token, external provider account, or existing test-realm edit.
Administrative APIs provisioned fixtures and read persisted state. Linking used
the supported `idp_link` application-initiated action with real owned-provider
authentication; unlinking used actual self-service Account REST authorization.

| Run | Passed | Failed | Harness error | Meaning |
| --- | ---: | ---: | --- | --- |
| `992188296522` | 11 | 0 | none | Earlier narrower sequential characterization; no full acceptance claim |
| `126206249977` | 15 | 2 | none | First completed concurrency characterization |
| `239652545592` | 17 | 2 | none | Fresh independent fixture realms; confirmed both failures |

All results retain `foundation_passed: false` and `production_approved: false`.
Script exit zero means the characterization harness completed; failed assertions
remain failed in the JSON and cannot be counted as implementation or acceptance.
Earlier result files bind the script revision they actually ran; only the latest
script revision is currently present, so earlier result hashes do not claim
identical source coverage.

Latest script SHA-256:
`48f3b290c4b7f68731de6346ba3f8ee19544e530728fd4cfc14817938a318bdd`.
Latest results SHA-256:
`e5910580daecfa8be78c2ad11c3ed903dc6b63f0633ae2f3c5f8318e0be28df5`.
Independent persistence reread SHA-256:
`084202aa38d073f67f586aaf00e6aba66a36624f797e5c1ac077533e6d9c1cc2`.

The independent reread used a one-off Docker/Python process with a fresh service
account token and supported read APIs. Its exact transient shell source was not
saved as a standalone script; the persisted evidence records the method, target
realm, result binding, credential types, and identity fingerprints. Do not claim
it is a separately reproducible checked-in test command.

## Established findings and remaining blockers

- **IDN-012 / LNK-007 failed:** two genuine provider callbacks for the same
  realm/provider alias/upstream subject both issued codes and persisted that
  identity on two different primary users. The fresh persistence reread confirms
  both records have the same external-subject fingerprint.
- **LNK-006 / LNK-007 failed:** parallel self-service removal of the last two
  provider methods returned HTTP 204 twice and left the primary with zero
  provider links and zero password credentials. This also persisted.
- Sequential isolation, explicit shared-provider alias behavior, proof of local
  and provider control, existing-owner conflict rejection, stable primary IDs,
  sequential last-provider protection, and remaining-provider login passed the
  bounded cases recorded in the result. These do not override the concurrency
  failures or establish full baseline parity.
- Alias namespacing alone did not prevent one tenant client from selecting the
  other tenant's provider alias. Tenant/provider authorization remains unresolved
  (IDN-003 / IDN-010).
- The native provider method is an alias plus upstream subject, not a separate
  stable recipe-user UUID; split/unlink lifecycle compatibility remains unresolved
  (IDN-005 / LNK-006 / LNK-008).
- Refresh still succeeded after native unlink. Session consequence and recent
  authentication policy require an explicit implementation and qualification
  (LNK-008), rather than assuming native unlink revokes sessions.
- Multi-replica correctness, conflicting-data migration, upgrade compatibility,
  native/live third-party-provider tests, and independent security review remain
  unqualified. No candidate selection or overall Keycloak impossibility claim
  follows from this bounded evidence.

Source supports the observed failure mechanism: `FederatedIdentityEntity.java`
lines 48-60 key a link by local primary and provider, while its lookup at line 40
uses realm/provider/external subject. `JpaUserProvider.java` line 185 persists a
new link without an ownership-serialization check; line 213 locks only the
selected existing link for removal. `LinkedAccountsResource.java` lines 326-330
count remaining methods before invoking that removal. `IdentityBrokerService.java`
lines 1168-1210 check and insert through the engine user provider.

A proposed engine-owned, transaction-held provider guard was investigated only.
It would need verified factory precedence, all mutation paths including direct
Account/Admin APIs and credentials, safe existing-data admission, lock ordering,
multi-replica proof, and a clearly version-pinned internal-SPI compatibility
contract. A guard only on application routes or the AIA confirmation screen
would leave the direct engine operations unprotected. No such guard is delivered
or approved by this checkpoint.

No fixture cleanup was performed. Synthetic uniquely named realms remain in the
private candidate runtime, including intentionally conflicting records from the
completed tests; they must not become release or production data. The bootstrap
credential file and `.runtime` directories are private runtime state and must not
be included in any public/distribution archive. Checkpoint evidence contains
synthetic identifiers and some browser state/tab identifiers, but does not
intentionally save passwords or bearer token values.

Parent checkpointing may hash or archive these files without rerunning the
stopped tests. Resume of hardening or new probes requires the parent to resolve
the stop; this document does not bypass that boundary.
