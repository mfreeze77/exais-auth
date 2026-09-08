# Four original runtime path resolutions

All four paths are resolved for the tested candidates, with **9/9 actual checks passed**. This closes the Unicode wire-path ambiguity for these four IDs only. The original baseline and `contracts/api-contracts.json` remain byte-for-byte unchanged. The supplemental result is `contracts/runtime-path-resolutions.json`; it explicitly leaves complete schemas, all tenant/version profiles and full operation qualification unproved.

| Original ID | Method | Actual tested path | Recipe header | Protocol header | Deprecated support |
| --- | --- | --- | --- | --- | --- |
| FDI-026 | GET | `/auth/public/signup/email/exists`; `/auth/signup/email/exists` | `rid: passwordless` | `fdi-version: 4.2` | Old route remains supported in Node SDK 24.0.3 |
| CDI-099 | GET | `/appid-public/public/recipe/user` | `rid: passwordless` | `cdi-version: 5.3` | Deprecated read remains supported in Core 12.2.0 |
| CDI-104 | PUT | `/appid-public/public/recipe/user` | `rid: passwordless` | `cdi-version: 5.3` | Update is not deprecated in the baseline |
| CDI-116 | GET | `/appid-public/public/recipe/user` | `rid: thirdparty` | `cdi-version: 5.3` | Deprecated read remains supported in Core 12.2.0 |

Core requests authenticate using the private `api-key` header. The probe verifies missing-key HTTP 401 and unsupported-CDI HTTP 400. Key values never enter evidence. The recipe router selects an exact `rid`; missing/unrecognized values fall back to the first registered email/password handler, so callers must send the intended recipe ID.

The wire paths were independently read from the actual Apache-licensed SDK constants/route dispatch and Core `getPath()` implementations, then exercised. Separate requests send the original published U+2800 suffixes intact (two characters for FDI-026/CDI-099/CDI-104; one for CDI-116); all return 404. The report retains escaped Unicode and actual percent-encoded request paths. No Unicode-stripping assumption was used.

Positive behavior uses real synthetic records in the existing private Core database. A generated passwordless code is consumed directly through the internal Core API, the resulting user is read by ID/email, the contact is updated and read back, and the old email stops matching. Negative cases include ambiguous selectors, absent records, missing email, legacy update identifier and clearing the sole contact. A separate trusted internal synthetic third-party record is read by ID and provider/subject pair; incomplete and absent pairs are tested. This is database/API fixture evidence, not live OAuth/provider authentication. No email/SMS/vendor delivery is configured or contacted. The small SDK test app permits GET only and supplies a fail-closed local delivery service.

There is an additional schema discrepancy: CDI-104's captured 5.3 declaration requires `userId` while defining `recipeUserId`. The pinned Core implementation requires `recipeUserId` at CDI 4.0 and later; the actual 5.3 request with only legacy `userId` returns 400. The supplement states this conflict without changing or redistributing the original OpenAPI schema. Null and omission facts were independently authored from Apache source; full schema conformance remains unqualified.

Source pins: Core `b2219c4aa019a501e4dfea76cf06ef802ca93fc0`; Node SDK `9b82aefb46da4c0f0a388d8f6656c39a62d7642c`. `source-report.json` hashes 21 retained source/license files against the existing immutable reuse audit. The files retain upstream headers and both projects' licenses. No restricted enterprise files or unlicensed OpenAPI were copied. `runtime-report.json` identifies exact running image/container IDs and verifies the installed Node recipe/router/constants against pinned compiled files. `probe-report.json` records each real result; `command-report.json` records exit 0 and exact invocation.

The first run's requests passed but artifact writing failed because the capture directory was owned by the capture container's UID. `command-report-first-evidence-permission-failure.json` retains that nonzero run. The final test writer uses UID 0 only inside its short-lived test container to write evidence; the actual SDK server remains the existing image's non-root user. No engine configuration or authentication policy was changed to obtain passing results.

On an authorized continuation, from the repository root, with the existing audited Core and example images available:

```powershell
$runtimePathRoot = (Get-Location).Path
docker run --rm --mount "type=bind,source=$runtimePathRoot,target=/work,readonly" --mount "type=bind,source=$runtimePathRoot\evidence\contracts,target=/work/evidence/contracts" -w /work python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 python tests/contracts/runtime_path_probe.py --capture
python tests/contracts/runtime_path_probe.py --run
```

No new image, network or volume was created by this lane. Its sole task-created runtime container, `expertauth-runtime-path-node` (label `org.expertauth.lab=runtime-paths`), is disposable after evidence capture. Source/evidence files must be retained. Existing shared Core/SDK image cleanup is coordinated by the parent task. Do not start new containers or rebuild images solely to repeat already-passing evidence during the disk-hygiene checkpoint.
