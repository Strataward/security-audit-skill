"""Check privacy, source failures, and advisory candidate behavior."""
import copy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import advisories as module

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
PUBLIC = {"name": "demo", "ecosystem": "npm", "version": "1.0.0", "public": True}
PROVENANCE = {"url": "fixture", "retrieved_at": "2026-11-05T00:00:00Z", "sha256": "fixture", "bytes": 1}


def record(identifier="GHSA-demo", aliases=None, **values):
    return {"id": identifier, "aliases": aliases or [], "published": "2020-01-01T00:00:00Z",
            "modified": "2020-01-02T00:00:00Z", "affected": [{"package": {"name": "demo", "ecosystem": "npm"}}],
            **values}


class FixtureFetch:
    def __init__(self, pages, kev=None, fail_kev=False):
        self.pages = iter(pages)
        self.kev = kev or {"count": 0, "vulnerabilities": []}
        self.fail_kev = fail_kev
        self.calls = []

    def __call__(self, url, payload=None):
        self.calls.append((url, copy.deepcopy(payload)))
        if url == module.KEV_URL:
            if self.fail_kev:
                raise module.LookupError("Fixture KEV failure.")
            return self.kev, PROVENANCE
        value = next(self.pages)
        if isinstance(value, Exception):
            raise value
        return value, PROVENANCE


class AdvisoryTests(unittest.TestCase):
    def collect(self, fetch, packages=None):
        return module.collect({"packages": packages or [PUBLIC]}, fetch=fetch, now=NOW)

    def test_private_metadata_never_leaves_machine(self):
        packages = [dict(PUBLIC, name="private", public=False), dict(PUBLIC, name="unknown", public="true")]
        fetch = FixtureFetch([])
        result = self.collect(fetch, packages)
        self.assertEqual(fetch.calls, [])
        self.assertEqual(result["sources"]["osv"]["status"], "not_checked")
        self.assertEqual(result["status"], "partial")

    def test_only_reviewed_fields_are_sent(self):
        package = dict(PUBLIC, url="https://attacker.invalid", secret="never-send", repository="private")
        fetch = FixtureFetch([{}])
        self.collect(fetch, [package])
        self.assertEqual(fetch.calls[1], (module.OSV_URL, {
            "package": {"name": "demo", "ecosystem": "npm"}, "version": "1.0.0"}))

    def test_failed_osv_is_never_clean(self):
        result = self.collect(FixtureFetch([module.LookupError("Fixture failure.")]))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["package_checks"][0]["status"], "failed")
        self.assertEqual(result["candidates"], [])

    def test_failed_kev_is_unknown(self):
        result = self.collect(FixtureFetch([{"vulns": [record(aliases=["CVE-2020-1234"])]}], fail_kev=True))
        self.assertIsNone(result["candidates"][0]["known_exploited"])
        self.assertEqual(result["sources"]["cisa_kev"]["status"], "failed")
        self.assertEqual(result["status"], "partial")

    def test_aliases_merge_and_kev_enriches(self):
        first = record(aliases=["CVE-2020-1234"])
        second = record("CVE-2020-1234", ["GHSA-demo"])
        kev = {"count": 1, "vulnerabilities": [{"cveID": "CVE-2020-1234", "dateAdded": "2026-11-04"}]}
        result = self.collect(FixtureFetch([{"vulns": [first, second]}], kev=kev))
        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertTrue(candidate["known_exploited"])
        self.assertEqual(len(candidate["source_records"]), 2)
        self.assertEqual(candidate["application_status"], "needs_validation")

    def test_alias_groups_do_not_cross_package_versions(self):
        pages = [{"vulns": [record(aliases=["CVE-2020-1234"])]}] * 2
        result = self.collect(FixtureFetch(pages), [PUBLIC, dict(PUBLIC, version="2.0.0")])
        self.assertEqual(len(result["candidates"]), 2)

    def test_old_matches_remain_and_modified_record_is_recent(self):
        old = record("GHSA-old")
        changed = record("GHSA-changed", modified="2026-11-04T00:00:00Z")
        result = self.collect(FixtureFetch([{"vulns": [old, changed]}]))
        self.assertEqual(len(result["candidates"]), 2)
        self.assertFalse(result["candidates"][0]["recent"])
        self.assertTrue(result["candidates"][1]["recent"])
        self.assertEqual(result["candidates"][0]["source_records"][0], old)

    def test_withdrawn_record_is_explicit(self):
        result = self.collect(FixtureFetch([{"vulns": [record(withdrawn="2026-11-01T00:00:00Z")]}]))
        self.assertEqual(result["candidates"][0]["withdrawal_status"], "withdrawn")

    def test_pagination_keeps_records_and_uses_fixed_endpoint(self):
        fetch = FixtureFetch([{"vulns": [record("one")], "next_page_token": "next"}, {"vulns": [record("two")]}])
        result = self.collect(fetch)
        self.assertEqual(len(result["candidates"]), 2)
        self.assertEqual(fetch.calls[2][1]["page_token"], "next")
        self.assertEqual(result["package_checks"][0]["status"], "complete")

    def test_page_failure_preserves_partial_evidence(self):
        result = self.collect(FixtureFetch([{"vulns": [record()], "next_page_token": "next"}, module.LookupError("Failure.")]))
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["package_checks"][0]["status"], "partial")
        self.assertEqual(result["status"], "partial")

    def test_repeated_token_is_partial(self):
        result = self.collect(FixtureFetch([{"next_page_token": "next"}, {"next_page_token": "next"}]))
        self.assertEqual(result["package_checks"][0]["status"], "partial")

    def test_page_limit_is_partial(self):
        pages = [{"next_page_token": str(value)} for value in range(module.MAX_PAGES)]
        result = self.collect(FixtureFetch(pages))
        self.assertEqual(result["package_checks"][0]["status"], "partial")

    def test_incomplete_kev_feed_is_unknown(self):
        result = self.collect(FixtureFetch([{"vulns": [record(aliases=["CVE-2020-1234"])]}],
                                         kev={"count": 1, "vulnerabilities": []}))
        self.assertIsNone(result["candidates"][0]["known_exploited"])

    def test_kev_absence_only_after_complete_feed(self):
        result = self.collect(FixtureFetch([{"vulns": [record(aliases=["CVE-2020-1234"])]}]))
        self.assertFalse(result["candidates"][0]["known_exploited"])

    def test_caps_and_ranges_are_rejected_before_network(self):
        with self.assertRaises(ValueError):
            module.collect({"packages": [PUBLIC] * (module.MAX_PACKAGES + 1)})
        with self.assertRaises(ValueError):
            module.collect({"packages": [dict(PUBLIC, version="^1.0.0")]})

    def test_error_object_is_never_clean(self):
        result = self.collect(FixtureFetch([{"error": "upstream failure"}]))
        self.assertEqual(result["package_checks"][0]["status"], "failed")
        self.assertEqual(result["status"], "partial")

    def test_total_response_budget_records_source_gap(self):
        with patch.object(module, "MAX_TOTAL_BYTES", 1):
            result = self.collect(FixtureFetch([{}]))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["package_checks"][0]["status"], "failed")

    def test_output_never_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                module.write_report(path, {})
            self.assertEqual(path.read_text(), "keep")

    def test_bounded_response(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size):
                self.limit = size
                return b"x" * size
        response = Response()
        opener = unittest.mock.Mock()
        opener.open.return_value = response
        with patch.object(module.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(module.LookupError, "byte limit"):
                module.fetch_json(module.OSV_URL, {})
        self.assertEqual(response.limit, module.MAX_BYTES + 1)

    def test_arbitrary_source_and_redirect_are_refused(self):
        with self.assertRaises(module.LookupError):
            module.fetch_json("https://attacker.invalid")
        with self.assertRaises(module.LookupError):
            module.NoRedirect().redirect_request(None, None, 302, "", {}, "https://attacker.invalid")

    def test_online_flag_is_required(self):
        with patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit):
                module.main(["input.json", "--output", "output.json"])


if __name__ == "__main__":
    unittest.main()
