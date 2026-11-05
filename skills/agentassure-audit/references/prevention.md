# Prevention

Convert each supported root cause into a control with a test. Keep advisory remediation separate from application design defects.

Each prevention record contains:

- The linked finding or coverage unit.
- The security rule that must hold.
- The proposed control and its enforcement location.
- A regression test with expected denial and permitted behavior.
- The relevant CI check or review check.
- The owner, when known.
- The retest condition and evidence references.
- Status: `proposed`, `implemented`, or `verified`.

Do not invent an owner or a completed test. `Implemented` requires evidence of a change. `Verified` requires a result from a test of the changed revision. A plan is not proof of enforcement.

| Root cause | Control | Regression evidence |
|---|---|---|
| A request supplies a tenant ID without authorization | Bind resource access to the authenticated tenant at the data boundary | Tenant A cannot read, update, export, or delete tenant B's object. Valid access still works. |
| Approval remains usable after revocation | Check current approval state at use time | Revoked and expired approvals fail. A valid approval succeeds. Include a bounded race check when relevant. |
| A vulnerable dependency is reachable | Use a supported fixed version and remove the affected path where possible | The resolved version changes. Recheck the advisory. Test behavior and compatibility. |
| A job repeats a sensitive action | Enforce an idempotency rule at the state transition | A duplicate event cannot repeat the effect. Distinct authorized actions still work. |
| Untrusted text controls an agent tool | Enforce permissions outside the model | A malicious fixture cannot expand scope, access secrets, or bypass required approval. |

Prefer controls that remove the root cause. A WAF rule or disabled feature can be a temporary mitigation. Label residual risk and the condition for removal. Do not promise a patch version until the authoritative advisory supports it for the installed branch.

For an audit-only request, provide proposed changes and tests. When fixes are authorized, use the repository's normal change process. Use focused behavioral checks. Do not create broad CI failure gates from unverified alerts. Give exceptions an owner, reason, scope, and expiry.

Suggest an advisory refresh cadence when useful. Do not create an automation unless requested. On refresh, retain the previous retrieval time. Report changed applicability, newly exploited CVEs, withdrawn advisories, and resolved gaps. A new date alone is not a meaningful security change.
