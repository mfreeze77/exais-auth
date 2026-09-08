The editable ledger is `implementation.json`. Original acceptance text, titles,
source IDs and original test IDs stay in the frozen registries. Every row points
to that registry's SHA-256 and the canonical JSON SHA-256 of its original record.
The supplied package manifest has a compiled-in trust anchor. Editing a baseline,
removing an ID or replacing it while keeping the count fails validation.

Run from the `expert-auth` directory:

```powershell
python tools/ledger.py check
python tools/ledger.py run-tests --discover tests/evidence --output evidence/integrity/unique-run-name.json --profile integrity
python tools/validate_release.py --claims-only
python tools/validate_release.py --output evidence/integrity/release-check.json
```

`check` proves inventory integrity only. `--claims-only` checks currently verified
claims without approving a release. The full release command intentionally exits
1 while any acceptance item or independent review is missing. Integrity tests
cannot be used as authentication evidence. The runner rejects skipped/xfail
tests, empty runs, and changes to release source during execution. Evidence names
must be new; prior recorded execution artifacts cannot be overwritten by the runner.

Each row uses exactly one status: `planned`, `implemented-unverified`, `verified`,
`failed`, or `blocked`. Failed and blocked rows require concrete `blockers`.
Additional requirements go in `additional_requirements` with new IDs, explicit
acceptance text and source provenance; they do not replace baseline rows.

To support a verified row:

* `implementation`: actual source `{ "path": "...", "sha256": "..." }` artifacts.
* `positive_test_ids` and `negative_test_ids`: distinct actual executed test IDs.
* `baseline_test_mapping`: maps each original acceptance test ID to executed IDs.
* `runs`: hashed `test-execution-v1` reports; each report includes command, times,
  environment, outcome of every test, hashed output, complete source snapshot and
  dependency hashes. Record real unittest integration wrappers with an appropriate
  `--profile` and one `--dependency-lock path` per root `dependency_lock_paths` item.
* `environment`: exact supported environment versions, and `review`: named reviewer
  plus accepted disposition. Retain limitations as blockers, not verified claims.

API rows also require a complete `contract` and a matching `contract_artifact` in
release source, so editing a claimed API contract invalidates run evidence. Contract
fields are enforced by `API_FIELDS` in `tools/validate_release.py`. An inapplicable
field needs an explicit reason, not null. CDI must declare private authenticated
exposure. Only the original vendor-control rows can use explicit non-equivalence;
deprecated business operations remain business compatibility obligations.

SDK/plugin/integration `qualification` records require exact versions, runtime/OS,
feature matrix, transport/storage behavior, hashed build evidence and restrictions.
Native SDKs additionally need native execution evidence. Live integration status
must be qualified. Missing native hardware or provider accounts remain blockers.

Completion also checks all milestones and work packages, seven separate
`qualification_artifacts`, and `independent_security_review`. Security review must
identify an independent human reviewer, security-code authors, accepted disposition,
current source tree, code/configuration/threat-model/evidence coverage, findings and
the hashed actual report. Its `ledger_claims_sha256` binds the review to the current
ledger and evidence references, using `validate_release.claims_hash(ledger)`.
Unremediated critical/high findings block release.

The gate is conservative: any source or dependency change invalidates old runs.
Source snapshots omit immutable baseline (separately hashed), ledger, evidence,
release output and caches. Artifact hashes establish consistency, not truthfulness:
JSON cannot establish a reviewer's real identity or prove a fabricated test honest.
The required independent review must assess actual behavior and evidence quality.
