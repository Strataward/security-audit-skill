# Contributing

Use an issue to describe a defect or proposed change. Do not include private source, credentials, or exploit details in a public issue. Follow SECURITY.md for sensitive reports.

Keep the skill instructions concise. Put detailed procedures in the relevant reference file. Preserve the distinction between observed evidence, inferred behavior, and unresolved checks.

For a code change, add a focused test for changed behavior. Run:

```bash
python3 -m unittest discover -s skills/agentassure-audit/scripts -p 'test_*.py'
```

Keep tests offline. Use synthetic fixtures. Do not add credentials or target source to the repository. Keep the helpers limited to standard Python libraries unless a dependency has a clear benefit.

A pull request should explain the problem, resulting behavior, and checks. Document changes to record fields or exit codes. Do not treat a test pass as proof of a security claim.

Changes to the advisory client must preserve public metadata filtering, fixed source URLs, bounded responses, explicit failures, and older matching advisories. Changes to records must preserve prior evidence and rejected candidates.

By submitting a contribution, you agree to license it under this repository's MIT License.
