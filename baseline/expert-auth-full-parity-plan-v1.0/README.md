# ExpertAuth full-parity planning package v1.0

**Goal:** independently host the complete researched SuperTokens functional surface without mandatory authentication-vendor license, feature or seat fees.

**Status:** plan and implementation backlog, not an authentication implementation. Checked public references and original research baseline: September 8, 2026.

## Start here

Read `FULL_PARITY_PLAN.md`, then `docs/FEATURE_MATRIX.md` and `docs/BACKLOG.md`.

| Content | Location |
|---|---|
| Product scope, architecture gate, full-parity definition and roadmap | `FULL_PARITY_PLAN.md` |
| 265 required behaviors and acceptance conditions across 29 families | `docs/FEATURE_MATRIX.md`, `registry/requirements.json` |
| 11 milestones and 36 implementation work packages with dependencies | `docs/BACKLOG.md`, `registry/milestones.json`, `registry/work-packages.json` |
| 49 FDI and 156 CDI operation entries | `docs/API_OPERATIONS.md`, `registry/api-operations.json` |
| Eight SDK, fourteen plugin and ten integration profiles | `registry/sdk-and-plugins.json` |
| Security, concurrency, migration, sovereignty and release gates | `docs/SECURITY_ACCEPTANCE.md` |
| Required configuration mapping and logical data model | `docs/CONFIGURATION_AND_DATA_MODEL.md` |
| Repository/subsystem reuse and file-specific harvest audit instructions | `docs/HARVEST_PLAN.md` |
| Source provenance | `docs/SOURCES.md`, `registry/sources.json` |
| Deliberately unfilled immutable baseline template | `registry/baseline-lock.template.json` |
| Inventory checker and its result | `tools/validate_plan.py`, `validation-report.json` |

The requirement/family/work-package counts are this plan's organization of the researched surface plus necessary self-hosting/security acceptance requirements. They are not official vendor feature counts or completion percentages.

## Validate inventory consistency

```bash
python tools/validate_plan.py
```

Requires Python 3.10 or later and no third-party packages. This checks identifiers, counts, sources, dependencies and evidence-state integrity. **A passing result does not mean any authentication feature works.** The planned acceptance/contract test identifiers are not executable authentication tests.

## Explicit unknowns and exclusions

Exact engine/source/version pins, full API paths/schemas, package-level dependency audits and runtime behavior remain first-milestone work. The plan does not invent them. The API registry is not OpenAPI. The harvest report is an actionable audit/selection plan, not a completed file-level code harvest.

Every required business capability remains in scope, including advanced features. Vendor-specific entitlement/telemetry workflows are transparently non-equivalent; the platform must not fabricate vendor licenses or claim exact compatibility for those workflows. Paid transport/infrastructure costs are separate from authentication software licensing.

This package contains no vendor source code, proprietary enterprise implementation, secrets, compiled SDKs, authentication service or independently reviewed production configuration.
