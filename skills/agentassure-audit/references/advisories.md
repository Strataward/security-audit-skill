# Current CVEs and advisories

## Inventory

Read lockfiles, installed-version receipts, container digests, and runtime manifests without executing them. Record ecosystem, package name, exact resolved version, dependency path, and deployment role. Manifest ranges are insufficient. Track multiple installed versions separately. Record unresolved versions as gaps.

Identify public packages before making external requests. A familiar name is not enough when it can name an internal package. Use local registry metadata or established package identity. Do not upload a private SBOM, full lockfile, source, or internal URLs. If publication status is unknown, keep the item local and ask only when disclosure is needed.

## Live lookup

Use vendor advisories for applicability and remediation. Use OSV or GitHub advisories for package matches. Use NVD for CVE enrichment. Check CISA KEV for known exploitation. Verify current details from primary sources. Search news only to discover a primary advisory.

Check all applicable advisories for installed versions. Also show records published or modified in the last 30 days, unless the user selects another window. A recent-only filter can hide an old defect in the installed version.

The bundled helper queries OSV and CISA KEV. It does not query vendors, GitHub, or NVD independently. Follow up on important candidates with authoritative vendor and CVE records. It does not cover every product ecosystem or discover dependencies automatically.

Create a reviewed input file outside the target:

```json
{
  "recent_days": 30,
  "packages": [
    {"name": "lodash", "ecosystem": "npm", "version": "4.17.20", "public": true}
  ]
}
```

This package is an example, not an inventory recommendation. Use actual resolved versions for an audit.

```bash
python3 "$SKILL_DIR/scripts/advisories.py" "$RUN_DIR/packages.json" --online --output "$RUN_DIR/advisories.json"
```

The output path must be new. The helper sends only items with `public: true`. It uses fixed official HTTPS endpoints. It refuses redirects and inherited proxies. It has request, response, package, and pagination limits. Read its `sources`, `package_checks`, `limitations`, and `status` fields.

Exit 0 means the requested helper lookups completed. Exit 2 means partial coverage. Exit 1 means an input or write failure. None means that the application is secure. If a proxy is required, use an approved existing connector or report the gap. Do not weaken the helper silently.

OSV version lookup can use fuzzy matching. Review the returned affected package, ecosystem, ranges, and vendor exceptions. Use ecosystem-aware version rules. Never compare versions as plain strings. Review distribution backports and patched forks against their vendor records.

## Candidate assessment

Retain the original IDs and aliases. Group explicit aliases per package and version. Do not merge distinct advisories because their descriptions look similar. Preserve disagreement between sources. Review withdrawn, rejected, disputed, or revised records before making a claim.

For each candidate, record:

- Package identity, resolved version, and inventory evidence.
- CVE, GHSA, and OSV aliases.
- Source URLs, retrieval time, publication time, and modification time.
- Source status: complete, partial, failed, or not checked.
- Affected range and supported fixed version, if known.
- Package applicability: affected, not affected, or unknown.
- Runtime or build exposure, reachable path, and missing preconditions.
- Vendor severity with its scoring system and version.
- Local application verdict, separately from vendor severity.
- KEV membership, catalog date, and any required mitigation.

A complete KEV lookup with no match means only that the CVE was absent from that catalog snapshot. It does not prove that nobody exploits it. If KEV fails, exploitation status is unknown. An unavailable OSV source never means that no vulnerability exists.

A package version match is dependency exposure evidence. It is not proof of a reachable application defect or a successful exploit. Independent verification must establish those claims. Avoid a runnable exploit merely to confirm an already established version match.

## Connect results to the audit

Review each retained candidate. Add advisory evidence records to `audit.json`. Use stable evidence IDs. Keep the raw helper output as a separate reference. Add package exposure and unresolved applicability to `REPORT.md`, even when no application finding is confirmed. Give each incomplete lookup a coverage gap.

Suggested report columns: package/version, advisory IDs, recent change, applicability, KEV status, application evidence, remedy, source time. Never collapse unknown to false.
