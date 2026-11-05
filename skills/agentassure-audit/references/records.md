# Audit record contract

The helper uses standard Python libraries. It performs no network calls and runs no target code. The parent owns `audit.json`. Keep it outside the target and all sandbox mounts. Use a trusted directory with one writer. This helper is not a hostile-file exporter or a database service.

## Run

`schema_version` is 1. `run` contains `id`, `target`, `revision`, `snapshot_id`, `created_at`, `status`, `scope_paths`, and `gaps`.

Use the exact Git commit for `revision`. For a target without Git, use a clearly named immutable source snapshot. Set `snapshot_id` to a SHA-256 digest of a sorted manifest of in-scope paths and file hashes. Include relevant local edits. Record exclusions. Preserve the manifest with the audit. Do not hash secrets into a public report.

The initializer creates an incomplete record. Fill its scope and snapshot before validation. `status` is `in_progress`, `partial`, or `complete`. Complete means that the declared checks completed with no unresolved gap. It does not mean exhaustive security coverage. A missing source, planned check, blocked check, or unresolved finding requires `partial` at handoff.

## Collections

All five arrays are required. IDs must be unique across the document. Use letters, digits, underscores, and hyphens. Start each ID with a letter. Keep IDs under 81 characters.

| Collection | Required fields |
|---|---|
| `evidence` | `id`, `kind`, `summary`, `snapshot_id`, `observed_at` |
| `coverage` | `id`, `surface`, `boundary`, `attack_class`, `state`, `evidence_refs` |
| `findings` | `id`, `claim`, `verdict`, `snapshot_id`, `hunter_id`, `reason`, `evidence_refs`, `coverage_refs`, `severity` |
| `prevention` | `id`, `status`, `rule`, `control`, `regression_test`, `ci_check`, `retest_condition`, `finding_refs`, `coverage_refs`, `evidence_refs` |
| `visual_elements` | `id`, `kind`, `status`, `evidence_refs`, `finding_refs`, `prevention_refs` |

Use ISO 8601 timestamps with a time zone. All evidence and findings refer to the run snapshot.

Evidence kinds:

- `source`: add target-relative `path` and file `sha256`. Add line numbers or a symbol when useful. The validator checks hashes when passed `--target`. It refuses symlinked evidence paths.
- `observation`: add `method`, `result`, and `limitations`. Record test input, command, environment, sandbox receipt, and actual output references when relevant. Use safe values only.
- `advisory`: add `url` and `source_status`. Preserve source timestamps, identity, affected versions, aliases, and source disagreement in additional fields.

Coverage states are `planned`, `checked`, `candidate`, `blocked`, and `out_of_scope`. Checked and candidate units need evidence. Blocked and excluded units need `reason`. A candidate unit prevents a complete run. After resolving its findings, change the unit to `checked` and retain its evidence and findings.

Confirmed findings also require `verifier_id`, `trace`, `observed_result`, `counterevidence`, source evidence, and observation evidence. The verifier ID must differ from the hunter ID. Severity is `critical`, `high`, `medium`, or `low`. A string comparison only checks recorded identity. The parent must establish actual independence.

For `needs_validation`, set `severity` to null. Add `next_test`. State the blocker in `reason`. For `rejected`, set severity to null and record the disproving evidence. Do not hide either class from the report.

Prevention statuses are `proposed`, `implemented`, and `verified`. Link at least one finding or coverage unit. Implemented controls need change evidence. Verified controls need an observation from the changed revision. Use a new audit run after a source change. Record any previous finding ID in an additional `prior_finding_ref` field.

Visual kinds are `node` and `edge`. Statuses are `observed`, `inferred`, `untested`, and `proposed`. Observed elements need evidence. Use the Archify element ID as `id`. Keep findings, advisories, and control status explicit in map labels and cards.

## Checkpoints

Write edits to a candidate file, then run `checkpoint`. The command validates source hashes before saving. It archives the previous record in `audit.json.history/` and atomically replaces the current record. Keep that directory with the audit. It is a local history, not tamper-proof storage.

Existing evidence and finalized findings are immutable within a run. Checkpoints must retain all existing IDs. A new source snapshot needs a new run. The checkpoint cannot silently clear a rejected candidate or inherit a finding from changed source.

Before handoff, check record references, current source hashes, and the exact map:

```bash
python3 "$SKILL_DIR/scripts/audit_records.py" validate "$RUN_DIR/audit.json" --target "$TARGET" --map "$RUN_DIR/security-map.json"
```

The map check supports `diagram_type: architecture` with `components` and `connections`, or `diagram_type: workflow` with `nodes` and `edges`. It requires every node and edge to have a unique ID and a corresponding record. It does not check the full Archify schema, label meaning, or HTML escaping. Archify performs its own artifact checks. The parent checks semantic consistency.

Run helper tests after changing the scripts:

```bash
python3 -m unittest discover -s "$SKILL_DIR/scripts" -p 'test_*.py'
```
