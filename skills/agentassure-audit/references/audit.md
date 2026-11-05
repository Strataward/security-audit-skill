# Audit and verification

## Map before hunting

Read the entry points and owners of trust decisions. Identify callers, authenticated principals, resources, tenant selectors, persistence, and outbound requests. Separate build-time, runtime, test-only, and optional components. Record unknown deployment facts.

Use a coverage unit for each relevant surface, boundary, and attack class. Each unit has an ID, scope, state, and evidence references. States are `planned`, `checked`, `candidate`, `blocked`, and `out_of_scope`. A checked unit means that its stated check ran. It does not mean that the surface has no defects.

Choose classes from the target:

| Area | Questions to test |
|---|---|
| Authorization and tenants | Can one principal select or modify another principal's resource? Does enforcement occur at the final read or write? |
| Input and outbound traffic | Can untrusted input reach a query, command, template, redirect, parser, or outbound destination? |
| State and lifecycle | Can retries, races, expiry, deletion, revocation, or stale caches bypass a security rule? |
| Dependencies and releases | Does the deployed dependency graph include affected versions? Can build or update inputs cross a trust boundary? |
| Agent tools and prompts | Can target content change tool authority, expose secrets, or bypass an approval boundary? |
| Availability | Can one caller exhaust a shared resource? Check only bounded local fixtures. |

Add target-specific classes only when source evidence supports them. For wallets, relevant classes can include approval expiry, signature domains, transaction facts, and replay. Never infer authority to move funds or use real keys.

## Hunter assignment

Use a packet with the run ID, snapshot ID, unit IDs, source paths, permitted tools, execution limits, and output location. State the security rule to examine. Give enough surrounding source to test the whole path. Let the hunter request more bounded evidence through the parent. Do not restrict discovery to scanner alerts.

The hunter returns:

- A candidate claim with an affected principal, resource, and outcome.
- The entry point, source-to-sink trace, and enforcement points.
- Source evidence IDs and preconditions.
- A safe reproduction or the exact missing fact.
- Plausible explanations that would make the claim false.

No hunter writes canonical records or assigns its own final verdict.

## Independent verifier assignment

Give a fresh agent the claim, evidence references, source snapshot, and scope. Ask it to disprove the claim. It must inspect the source and relevant caller or framework behavior. It must examine guards, validators, deployment conditions, and alternate explanations. It must not accept the hunter's prose as proof.

A separate context is required. A different model can add diversity, but does not establish correctness. The same agent reading its own claim again is not independent verification.

Use these verdicts:

- `confirmed`: The current source trace is complete. An independent verifier confirms a bounded observed security result. State fixture limits. A fixture result does not prove production exploitation.
- `needs_validation`: A specific unresolved fact prevents confirmation. Keep the blocker and the next safe test. Do not assign an application severity.
- `rejected`: Evidence disproves the specific claim. Keep the claim and the reason. This verdict does not clear the entire coverage unit.

For an advisory, separately record `affected`, `not_affected`, or `unknown` for package applicability. Do not convert an advisory match into a confirmed application finding without the same verification rules.

Record the discovery agent and verification agent IDs. Record each verifier's counterevidence and observed result. The parent checks that final wording stays within those observations. Before a long or cross-system audit ends, request an architect review when the session's agent rules require it.

## Persistence and changes

Only the parent changes shared records. Each checkpoint preserves existing IDs and prior records. If a claim changes, retain its history in a new run or a linked replacement record. Do not erase a rejected claim when resuming.

Hash the files used by each source evidence item. The snapshot ID identifies the audited tree, including local edits. When a hash changes, keep the old run and create a new run. Recheck affected units and findings. Prior confirmation does not carry to a new snapshot automatically.

On a rate limit, authentication failure, or unavailable tool, save the gap and stop dependent work. Keep the rest of the report useful. A tool failure is not a clean scan.
