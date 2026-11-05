# Visual evidence map

Use the installed `archify` skill when available. Discover it from the skill catalog or local skill directories. Read its `SKILL.md`. Do not assume a fixed username or renderer version. Resolve the renderer relative to that skill directory.

For each full audit, create a standalone HTML map of the actual target. Use `architecture` for services and trust boundaries. Use `workflow` for a focused security decision. Read the matching schema, common schema, and one example. Follow Archify's candidate, validation, delivery, and browser-check rules. Do not copy example topology as target facts.

Keep one clear main path and at most 12 primary nodes. Use a second map only when one map cannot explain the scope. Use stable IDs for every node and edge. Keep labels short. Show the source revision and evidence cutoff in a card. Use the viewer's theme, pan, zoom, and search controls. Keep motion off unless requested.

Map semantic status explicitly in labels or cards:

- Observed path: source or test evidence establishes the relationship.
- Inferred path: available evidence suggests the relationship.
- Untested boundary: the stated test has not run.
- Confirmed finding: link its finding ID.
- Advisory match: label it as package exposure, not confirmed exploitation.
- Proposed control: label it as proposed.

Colors and renderer variants do not prove security status. Do not use green to imply that a whole component is secure. Keep vendor severity separate from local finding severity. Do not draw a proposed control as if it exists.

Create `visual-evidence.json` as a sidecar. Each item contains `element_id`, `kind` (`node` or `edge`), `status`, `evidence_refs`, `finding_refs`, and `prevention_refs`. Each ID must exist in the delivered specification. Each reference must resolve in `audit.json`. Put the same element IDs in `audit.json` under `visual_elements`. Keep source excerpts and secrets out of HTML. Escape labels as data. Do not embed raw target HTML, scripts, or external tracking resources.

From the installed Archify directory, use its documented commands with absolute input and output paths:

```bash
node bin/archify.mjs validate architecture "$RUN_DIR/security-map.json" --quality showcase --json
node bin/archify.mjs deliver architecture "$RUN_DIR/security-map.json" "$RUN_DIR/security-map.html" --quality showcase --json
node bin/archify.mjs visual-check "$RUN_DIR/security-map.html" --json
```

Use the actual diagram type. A failed delivery does not create a valid new artifact. Do not inspect a stale previous HTML file as if it came from the failed candidate. Keep delivery checks, browser evidence, and perceptual review separate.

If Archify is unavailable, deliver the evidence table and a Mermaid or JSON draft. Mark HTML delivery incomplete. Do not install or download another renderer automatically. A missing viewer does not block the written report.

The bundled `assets/audit-workflow.json` shows this skill's process. It is a demonstration only. It cannot replace a target-specific security map.
