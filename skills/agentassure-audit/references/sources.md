# Sources and maintenance

Method reviewed on 2026-11-05. These instructions are a local adaptation. They do not claim Cloudflare endorsement. They do not vendor Cloudflare's prompt files.

- [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill): staged discovery, separate verification, structured findings, and coverage records.
- [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/): persistence, bounded agents, and independent validation.
- [Evidence-grounded security operations](https://blog.cloudflare.com/agentic-security-operations/): scoped evidence collection, explicit source gaps, and typed results. This article covers alert operations. Do not present it as a SAST requirement.
- [OSV query API](https://google.github.io/osv.dev/post-v1-query/): ecosystem and version queries, pagination, and record retrieval.
- [OSV schema](https://ossf.github.io/osv-schema/): aliases, affected ranges, dates, and withdrawal.
- [GitHub Advisory Database](https://github.com/advisories): reviewed package advisories and GHSA aliases.
- [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities): CVE records and enrichment. NVD absence or delayed enrichment is not proof of safety.
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): known exploitation. Absence is not proof of no exploitation.
- [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json): structured enrichment for exact CVE IDs.
- Installed `archify` skill: visual authoring and delivery contract. Read the installed instructions when producing a map.

Consult live official documentation before changing API behavior. Do not use a third-party summary as the only source for exploitability or a fixed version. Keep adapted guidance separate from future vendored files. Preserve the applicable license and attribution if such files are copied.
