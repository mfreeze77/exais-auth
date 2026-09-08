# File-specific contract source and license report

This report covers only the contract extraction boundary. It makes no licensing claim about the selected authentication engine, SDKs, or other implementation packages.

| Upstream repository and immutable revision | Source files examined | License evidence | Destination / reuse boundary | Mapped scope |
|---|---|---|---|---|
| `supertokens/frontend-driver-interface` at `b7e8581d196a5e4d45a9431ca614b8aa68384008` | `api_spec.yaml`, repository tree, `README.md`, `CONTRIBUTING.md` | No LICENSE/COPYING/NOTICE/COPYRIGHT file found in complete tree; no OpenAPI `info.license`; no licensing keyword in README/contribution file. No redistribution grant established. | Read into capture-process memory only. `contracts/api-contracts.json` contains independently generated protocol facts, immutable references, and digests. Raw source and prose not redistributed. | FDI-001 through FDI-049; source publishes four additional operations retained outside the frozen inventory. |
| `supertokens/core-driver-interface` at `51072a01e22477833fbba250d5ce27d09541327c` | `api_spec.yaml`, repository tree, `README.md`, `CONTRIBUTING.md` | Same reference-only decision after this revision's separate audit. A public repository or Apache license in a different repository does not grant this schema's redistribution rights. | Same generated-facts boundary; no source adaptation or raw copy. | All frozen CDI entries except CDI-028 and CDI-030, including both path variants of CDI-106/CDI-110. One extra OAuth POST operation is retained separately. |
| `supertokens/core-driver-interface` at `e15e4693498f9c0bbbcc2b90ac33959a476703a1` | `api_spec.yaml`, repository tree, `README.md`, `CONTRIBUTING.md` | Same reference-only decision after separate audit. This is the official bulk-import fix branch, not a qualified supported release. | Read-only supplemental source; no raw copy. | CDI-028 and CDI-030 only. |
| PyYAML 6.0.3 | Installed parser dependency, declared in `contracts/requirements.txt` | MIT; retain its distributed license if vendoring. The parser package is installed as a dependency and is not copied into this source deliverable. | `tools/capture_contracts.py:parse_yaml`; SafeLoader subclass rejects duplicate keys and unsafe constructors. | All 205 entries; parser/extractor tests. |

Source SHA-256 values, immutable links, complete tree paths, checked text-file hashes, and machine-readable decisions are included per source in `contracts/api-contracts.json`. The exact source pins are in `contracts/source-pins.json`. No upstream source file has been modified. The tool, explicit ID mapping, tests, reports, and normalized representation were written for this repository.

The schema-rights blocker is narrow: redistributing complete upstream schema documents has not been authorized. It does not remove any business feature requirement, permit copying restricted enterprise code, or claim that factual protocol research and independent implementation require vendor entitlements. Resolve the blocker by obtaining a suitable grant or completing independently authored, runtime-qualified contracts with traceable lawful provenance. Continue to label those as ExpertAuth contracts rather than unmodified vendor schemas.

Primary pinned references:

- [FDI specification](https://github.com/supertokens/frontend-driver-interface/blob/b7e8581d196a5e4d45a9431ca614b8aa68384008/api_spec.yaml)
- [CDI specification](https://github.com/supertokens/core-driver-interface/blob/51072a01e22477833fbba250d5ce27d09541327c/api_spec.yaml)
- [CDI supplemental bulk-import specification](https://github.com/supertokens/core-driver-interface/blob/e15e4693498f9c0bbbcc2b90ac33959a476703a1/api_spec.yaml)
- [PyYAML 6.0.3 license](https://github.com/yaml/pyyaml/blob/6.0.3/LICENSE)
