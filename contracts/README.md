# ExpertAuth API contract capture

The immutable acceptance inventory contains **205 operations: 49 FDI and 156 CDI**. `api-contracts.json` accounts for all of them, preserving original IDs, names, recipes, methods, deprecation flags, classifications, source IDs, and planned test IDs. Two session entries have both application and tenant paths, so the artifact contains 207 path variants. This is executable source capture and accounting, **not proof of authentication behavior or full API compatibility**.

`operation-map.json` explicitly maps each original entry to a published operation ID, or a path when the upstream operation has no ID. Mapping validation checks the method, recipe, and deprecation flag. The original inventory remains unchanged. Five newer source operations are listed separately; they do not change the frozen API denominator or remove any related feature requirements.

## What is captured

`tools/capture_contracts.py` fetches the exact commits and SHA-256 digests in `source-pins.json`, parses the specifications in memory, audits the immutable repository tree and README/contribution files, and generates:

- Published methods, paths, operation IDs, protocol versions, and source JSON pointers with fragment digests.
- Request body presence, media types, parameter/header facts, field types and constraints, enum values, required-property rules, and explicit nullable flags.
- Response HTTP codes, status enum values, response header names, cookie security scheme names, and security alternatives.
- Explicit source-path tenancy information, pagination parameter names, deprecations, and separate unresolved side effects, idempotency, claims, cookies, concurrency, and runtime semantics.

No raw YAML, prose, examples, copied OpenAPI document, or enterprise implementation is saved. Exact schemas remain pinned references pending redistribution-rights resolution. The generated field facts are independently normalized for interoperability research. An omitted OpenAPI `required` declaration and a nullable field remain distinct. Conditional schemas retain their `oneOf`/`anyOf`/`allOf` branches. These are published constraints; actual missing-versus-null behavior must still be tested against the chosen implementation.

## Verified limitations and source anomalies

- The GitHub default branches were stale for this inventory: FDI master described 3.0.0 and CDI master described 5.2.0. Capture selects the separately published FDI 4.2.0 and CDI 5.3.0 branches by immutable commit, without claiming these match the selected runtime or every SDK.
- CDI-028 (staged-user count) and CDI-030 (direct bulk import) are absent from the pinned 5.3 branch. Their references come from the separately pinned official `fix/bulk-import-missing-endpoints` branch, whose `info.version` also says 5.3.0. They remain explicitly blocked on supported-release/runtime qualification.
- FDI-026 and CDI-099, CDI-104, CDI-116 contain U+2800 Braille blank characters in published path keys, apparently separating recipe-overloaded paths in the source document. The raw paths and escaped forms are preserved, with a blocker. The tool does not silently strip characters or assert a corrected wire endpoint. SDK/runtime resolution is required.
- CDI-106 and CDI-110 each publish both tenant and application path variants with the same operation ID. Both are retained.
- CDI-150 WebAuthn recovery is published as **GET** with a query token. Its side effects, cache safety, and token consumption behavior remain uncharacterized. The method was not converted to POST from its name.
- FDI-014 continues OAuth login at `/oauth/login`; FDI-023 starts login at `/oauth/auth`. These distinct mappings have a regression test.
- CDI-002, CDI-007, CDI-010, CDI-013, and CDI-021 require explicit vendor-control non-equivalence. No commercial licensing service is fabricated, and all advanced business capabilities remain required.
- All 205 entries are `captured-reference-only`; zero are behavioral compatibility passes. Cookie clearing/attributes, tenant enforcement, timing, refresh races, side effects, complete errors, pagination boundaries, deprecations, and claim semantics need real implementation tests. Independent security review remains outside this evidence.

## Reproduce

From the repository root with Python 3.11+ and PyYAML 6.0.3:

```powershell
python -m pip install -r contracts/requirements.txt
python tools/capture_contracts.py
python tools/capture_contracts.py --check
python tools/capture_contracts.py --validate
python tests/contracts/run.py
python tools/capture_contracts.py --validate --require-complete
```

The final command must exit **1** while unresolved contracts remain. Successful `--validate` checks only the integrity and honesty of the capture. `--check` downloads the pinned source again and requires exact deterministic equality with the stored normalized artifact. It does not use moving branch names and does not rewrite the artifact. Source-fetch or digest errors exit 2. Host Windows networking failed during this run; the following local Docker execution completed the downloads without changing global networking settings:

```powershell
$contractRoot = (Get-Location).Path
docker run --rm --mount "type=bind,source=$contractRoot,target=/work,readonly" --mount "type=bind,source=$contractRoot\contracts,target=/work/contracts" --mount "type=bind,source=$contractRoot\evidence\contracts,target=/work/evidence/contracts" -w /work python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 sh -c 'pip install --quiet --root-user-action ignore --disable-pip-version-check -r contracts/requirements.txt && python tools/capture_contracts.py'
```

Use `--check` in the last Python invocation for an independent recapture comparison. There are no provider credentials or authentication tokens in these captures. Network downloads are public-source research only. API keys represented by names in the specification are never actual values.

`evidence/contracts/capture-report.json` records capture inputs, output digest, dependencies, and counts. `evidence/contracts/tests-report.json` records the actual test results and source hashes. Extractor tests include synthetic parser cases; those cases are expressly not provider or authentication evidence.
