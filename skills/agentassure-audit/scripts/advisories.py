#!/usr/bin/env python3
"""Fetch advisory candidates for explicitly public package metadata."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_PACKAGES = 100
MAX_PAGES = 5
MAX_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
TIMEOUT = 25
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class LookupError(Exception):
    """A source did not return a complete, valid response."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LookupError("Source redirect was refused.")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fetch_json(url, payload=None):
    """Read one bounded response from a fixed source."""
    if url not in (OSV_URL, KEV_URL):
        raise LookupError("Source URL is not allowed.")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={
        "Accept": "application/json", "User-Agent": "AgentAssure-Advisory-Check/1",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    # Disable inherited proxies. Do not send credentials or ambient headers.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                raise LookupError("Source returned a non-200 status.")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise LookupError("Source response exceeds the byte limit.")
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        # Do not copy exception text. It can contain host paths or proxy details.
        raise LookupError("Source request failed: " + type(exc).__name__) from exc
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError("Source response is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise LookupError("Source response must be an object.")
    return parsed, {"url": url, "retrieved_at": utc_now(),
                    "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}


def validate_input(data):
    if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
        raise ValueError("Input must contain a packages array.")
    if len(data["packages"]) > MAX_PACKAGES:
        raise ValueError("Input exceeds the 100-package limit.")
    days = data.get("recent_days", 30)
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError("recent_days must be an integer from 1 through 365.")
    packages = []
    seen = set()
    for item in data["packages"]:
        if not isinstance(item, dict):
            raise ValueError("Each package must be an object.")
        for field in ("name", "ecosystem", "version"):
            value = item.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError("Each package needs a bounded name, ecosystem, and version.")
            if any(ord(char) < 32 for char in value):
                raise ValueError("Package fields must not contain control characters.")
        version = item["version"]
        if version.lower() in ("latest", "stable", "next", "canary") or any(
            token in version for token in ("*", "^", "~", ">", "<", "|", " ", "workspace:", "file:", "git+")
        ):
            raise ValueError("Use a resolved version, not a version range.")
        package = {key: item[key] for key in ("name", "ecosystem", "version")}
        package["public"] = item.get("public") is True
        identity = tuple(package[key] for key in ("name", "ecosystem", "version"))
        if identity not in seen:
            seen.add(identity)
            packages.append(package)
    return packages, days


def parse_date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except ValueError:
        return None


def query_package(package, fetch=fetch_json):
    records, pages, seen_tokens = [], [], set()
    token = None
    for _ in range(MAX_PAGES):
        query = {"package": {key: package[key] for key in ("name", "ecosystem")},
                 "version": package["version"]}
        if token is not None:
            query["page_token"] = token
        try:
            page, provenance = fetch(OSV_URL, query)
            if any(key in page for key in ("error", "message", "code")):
                raise LookupError("OSV returned an error object.")
            vulns = page.get("vulns", [])
            if not isinstance(vulns, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("id"), str)
                or not item["id"] for item in vulns
            ):
                raise LookupError("OSV returned invalid vulnerability records.")
            next_token = page.get("next_page_token")
            if next_token is not None and (not isinstance(next_token, str) or len(next_token) > 8192):
                raise LookupError("OSV returned an invalid page token.")
            pages.append({"provenance": provenance, "response": page})
            records.extend(vulns)
            if not next_token:
                return records, pages, "complete", None
            if next_token in seen_tokens:
                return records, pages, "partial", "OSV repeated a page token."
            seen_tokens.add(next_token)
            token = next_token
        except LookupError as exc:
            return records, pages, "partial" if pages else "failed", str(exc)
    return records, pages, "partial", "OSV reached the five-page limit."


def query_kev(fetch=fetch_json):
    try:
        raw, provenance = fetch(KEV_URL)
        entries = raw.get("vulnerabilities")
        count = raw.get("count")
        if not isinstance(entries, list) or type(count) is not int or count != len(entries):
            raise LookupError("KEV count does not match the complete feed.")
        if any(not isinstance(item, dict) or not CVE_RE.fullmatch(str(item.get("cveID", "")))
               for item in entries):
            raise LookupError("KEV contains invalid CVE records.")
        return {item["cveID"]: item for item in entries}, {
            "status": "complete", "provenance": provenance,
            "catalog_version": raw.get("catalogVersion"),
            "date_released": raw.get("dateReleased"), "count": count,
        }, {"provenance": provenance, "response": raw}
    except LookupError as exc:
        return {}, {"status": "failed", "error": str(exc)}, None


def merge_records(records):
    """Group explicit aliases only. Call this once per package and version."""
    groups = []
    for record in records:
        raw_aliases = record.get("aliases", [])
        aliases = raw_aliases if isinstance(raw_aliases, list) else []
        ids = {record["id"], *(value for value in aliases if isinstance(value, str) and value)}
        overlaps = [group for group in groups if group["ids"] & ids]
        group = {"ids": set(ids), "records": [record]}
        for old in overlaps:
            group["ids"].update(old["ids"])
            group["records"].extend(old["records"])
            groups.remove(old)
        # Keep each distinct source record. Do not merge severity or affected ranges.
        unique = {}
        for value in group["records"]:
            unique[json.dumps(value, sort_keys=True)] = value
        group["records"] = list(unique.values())
        groups.append(group)
    return groups


def collect(data, fetch=fetch_json, now=None):
    packages, days = validate_input(data)
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    total_bytes = 0
    source_fetch = fetch

    def bounded_fetch(url, payload=None):
        nonlocal total_bytes
        if total_bytes >= MAX_TOTAL_BYTES:
            raise LookupError("Lookup reached the total response byte limit.")
        response, provenance = source_fetch(url, payload)
        # Count retained JSON as well as transport bytes. This also bounds test adapters.
        size = max(provenance.get("bytes", 0), len(json.dumps(response).encode("utf-8")))
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise LookupError("Lookup reached the total response byte limit.")
        return response, provenance

    fetch = bounded_fetch
    report = {
        "schema_version": 1, "generated_at": now.isoformat().replace("+00:00", "Z"),
        "recent_days": days, "status": "complete", "sources": {},
        "package_checks": [], "candidates": [], "raw_osv_pages": [], "raw_kev": None,
        "limitations": [
            "OSV version queries can use fuzzy version matching. Review the affected ranges and vendor advice.",
            "An advisory match does not prove reachability or exploitation in this application.",
            "Recent means published or modified within the chosen window. Older matches remain in this report.",
            "This lookup does not cover products or advisories that OSV does not index.",
            "Private packages and packages with unknown publication status are not sent to a source.",
        ],
    }
    # No network is needed when there is no approved public metadata.
    if any(package["public"] for package in packages):
        kev, kev_status, kev_raw = query_kev(fetch)
    else:
        kev, kev_status, kev_raw = {}, {"status": "not_checked"}, None
    report["sources"]["cisa_kev"] = kev_status
    report["raw_kev"] = kev_raw
    if kev_status["status"] == "failed":
        report["status"] = "partial"
    osv_status = "complete"
    checked = 0
    for package in packages:
        identity = {key: package[key] for key in ("name", "ecosystem", "version")}
        if not package["public"]:
            report["package_checks"].append({"package": identity, "status": "not_checked",
                "reason": "Package publication status is private or unknown."})
            report["status"] = "partial"
            continue
        checked += 1
        records, pages, status, error = query_package(package, fetch)
        check = {"package": identity, "status": status, "pages": len(pages), "records": len(records)}
        if error:
            check["error"] = error
            report["status"] = "partial"
            osv_status = "partial"
        report["package_checks"].append(check)
        report["raw_osv_pages"].append({"package": identity, "pages": pages})
        for group in merge_records(records):
            ids = sorted(group["ids"])
            cves = [value for value in ids if CVE_RE.fullmatch(value)]
            matched_kev = [kev[value] for value in cves if value in kev]
            recent_dates = [parse_date(record.get(field)) for record in group["records"]
                            for field in ("published", "modified")]
            recent = any(value is not None and cutoff <= value <= now for value in recent_dates)
            withdrawal = [bool(record.get("withdrawn")) for record in group["records"]]
            candidate = {
                "package": identity, "ids": ids, "cves": cves,
                "assessment": "advisory_candidate", "application_status": "needs_validation",
                "match_basis": "OSV package and version query", "recent": recent,
                "date_status": "known" if any(recent_dates) else "unknown",
                "withdrawal_status": "withdrawn" if all(withdrawal) else
                                     "mixed" if any(withdrawal) else "not_withdrawn",
                "known_exploited": bool(matched_kev) if kev_status["status"] == "complete" and cves else None,
                "kev_records": matched_kev, "source_records": group["records"],
            }
            report["candidates"].append(candidate)
    report["response_bytes"] = total_bytes
    report["sources"]["osv"] = {"status": osv_status if checked else "not_checked",
                                  "packages_queried": checked, "url": OSV_URL}
    return report


def write_report(path, report):
    """Create a new file. Refuse an existing file or a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Read reviewed public package metadata from this JSON file.")
    parser.add_argument("--online", action="store_true", help="Permit lookup of public package metadata.")
    parser.add_argument("--output", type=Path, required=True, help="Create a new report at this path.")
    args = parser.parse_args(argv)
    if not args.online:
        parser.error("Pass --online to permit source requests.")
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("The output path already exists.")
        if args.input.stat().st_size > MAX_BYTES:
            raise ValueError("Input exceeds the byte limit.")
        data = json.loads(args.input.read_text(encoding="utf-8"))
        report = collect(data)
        write_report(args.output, report)
    except (OSError, ValueError) as exc:
        print("Advisory lookup failed: " + type(exc).__name__ + ". No existing report was replaced.", file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "candidates": len(report["candidates"]),
                      "output": str(args.output)}))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main())
