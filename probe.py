"""One bounded real-download replay of public earnings documents; never a release SLA."""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import gzip
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from pdf_tables import prewarm_pdf_pool
from sources import discover, validate

BASE = Path(__file__).resolve().parent
HEADERS = {"User-Agent": "EarningsWatch/1.0 automated-public-filings-research",
           "Accept": "*/*", "Cache-Control": "no-cache"}
METRICS_SCOPES = ("metrics-production", "metrics-alternate-sources", "metrics-exchange-targets", "metrics-22-coverage", "metrics-unresolved-paths", "metrics-ncmi-issuer", "metrics-all-supported")


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def execution_hardware():
    """Record only measured CPU properties, never host identity or environment."""
    result = {"machine": platform.machine(), "logical_cpus": os.cpu_count(), "cpu_model": None}
    if platform.system() == "Linux":
        try:
            output = subprocess.run(["lscpu", "--json"], capture_output=True, text=True, check=True, timeout=3)
            fields = json.loads(output.stdout)["lscpu"]
            result["cpu_model"] = next((row["data"] for row in fields if row["field"] == "Model name:"), None)
            result["cpu_model_source"] = "lscpu Model name"
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            result["cpu_identification_error"] = type(exc).__name__
    else:
        result["cpu_model"] = platform.processor() or None
        result["cpu_model_source"] = "platform.processor"
    return result


def safe_error_message(exc):
    message = str(exc)
    identity = os.environ.get("SEC_USER_AGENT", "")
    if identity:
        message = message.replace(identity, "[redacted identity]")
    message = re.sub(r"https?://[^\s\"'<>]+", lambda match: "https://" + (urlsplit(match[0]).hostname or "[host]"), message)
    message = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b", "[IP]", message)
    message = re.sub(r"(?i)(authorization|cookie|token|api[-_]key|password)\s*[:=]\s*[^\s,;]+", r"\1=[redacted]", message)
    message = re.sub(r"[^\s@]+@[^\s@]+", "[redacted email]", message)
    return message[:500]


def host_key(url):
    host = urlsplit(url).hostname
    return "sec.gov" if host == "sec.gov" or host.endswith(".sec.gov") else host


async def pace(url, recent, blocked, *, sec_rps=8):
    host, path = host_key(url), urlsplit(url).path
    limit = sec_rps if host == "sec.gov" else 4  # The bounded transport pair uses 2; existing scopes retain 8.
    history = recent.setdefault(host, deque())
    while True:
        now = time.perf_counter()
        while history and history[0] <= now - 1:
            history.popleft()
        until = max(blocked.get((host, ""), 0), blocked.get((host, path), 0),
                    history[0] + 1 if len(history) >= limit else 0)
        if until <= now:
            history.append(now)
            return
        await asyncio.sleep(until - now)


async def identify_node(client):
    """Keep only the two public region fields; never retain the trace body or IP."""
    try:
        response = await client.get("https://www.cloudflare.com/cdn-cgi/trace", headers=HEADERS)
        fields = dict(line.split("=", 1) for line in response.text.splitlines()
                      if line.startswith(("loc=", "colo="))) if response.status_code == 200 else {}
        return {"loc": fields.get("loc"), "colo": fields.get("colo"),
                "is_us": fields.get("loc") == "US", "status": response.status_code}
    except httpx.HTTPError as exc:
        return {"loc": None, "colo": None, "is_us": False, "error_type": type(exc).__name__}


def select_targets(targets, scope):
    if scope in METRICS_SCOPES:
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        events = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        cases = ([(symbol, "official" if symbol == "SE" else "sec", symbol + "_METRICS_PRODUCTION")
                  for symbol in ("ONON", "SE", "TDG", "MRDN")] if scope == "metrics-production" else
                 [("SE", "sec", "SE_SEC_METRICS_PRODUCTION"), ("TDG", "sec", "TDG_METRICS_PRODUCTION"),
                  ("MRDN", "sec", "MRDN_RELEASE_METRICS_PRODUCTION")])
        if scope == "metrics-exchange-targets":
            cases = [(symbol, references[symbol + "_EXCHANGE_METRICS_PRODUCTION"]["channel"],
                      symbol + "_EXCHANGE_METRICS_PRODUCTION") for symbol in ("CSCO", "NBIS", "CBRS")]
        if scope == "metrics-22-coverage":
            coverage_symbols = [key.removesuffix("_COVERAGE_METRICS_PRODUCTION")
                     for key in references
                     if key.endswith("_COVERAGE_METRICS_PRODUCTION")
                     and not key.endswith("_REPAIRED_COVERAGE_METRICS_PRODUCTION")]
            keys = [(symbol, symbol + ("_REPAIRED_COVERAGE_METRICS_PRODUCTION"
                     if symbol + "_REPAIRED_COVERAGE_METRICS_PRODUCTION" in references
                     else "_COVERAGE_METRICS_PRODUCTION")) for symbol in coverage_symbols]
            cases = [(symbol, references[key]["channel"], key) for symbol, key in keys]
        if scope == "metrics-unresolved-paths":
            cases = [(symbol, references[symbol + "_REPAIRED_COVERAGE_METRICS_PRODUCTION"]["channel"],
                      symbol + "_REPAIRED_COVERAGE_METRICS_PRODUCTION") for symbol in ("SE", "NCMI", "RGTI", "CBRS", "BIDU")]
        if scope == "metrics-ncmi-issuer":
            cases = [("NCMI", "official", "NCMI_ISSUER_METRICS_PRODUCTION")]
        if scope == "metrics-all-supported":
            cases = []
            for symbol in events:
                key = next(key for key in (
                    symbol + "_CURRENT_SEC_METRICS_PRODUCTION", symbol + "_CURRENT_V2_METRICS_PRODUCTION",
                    symbol + "_CURRENT_METRICS_PRODUCTION",
                    symbol + "_ISSUER_METRICS_PRODUCTION",
                    symbol + "_EXTENSION_METRICS_PRODUCTION",
                    symbol + "_REPAIRED_COVERAGE_METRICS_PRODUCTION", symbol + "_COVERAGE_METRICS_PRODUCTION")
                    if key in references)
                cases.append((symbol, references[key]["channel"], key))
        return [{"target_id": key.replace("_METRICS_PRODUCTION", "") + "_metrics_full_chain", "channel": channel,
                 "url": references[key]["url"],
                 "reference": references[key],
                 "event": {**events[symbol], **references[key].get("event_override", {})}, "cache_profile": "ordinary", "pipeline": "production_watch_list_seed",
                 "metrics_mode": "synthetic", "require_raw_reference_match": references[key].get("require_raw_reference_match", channel == "official"),
                 **{name: references[key][name] for name in ("filing_index_url", "filing_form") if name in references[key]}}
                for symbol, channel, key in cases]
    if scope == "kkr-complete":
        return [target for target in select_targets(targets, "backlog-production") if target["event"]["symbol"] == "KKR"]
    if scope == "skyd-complete":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        event = next(event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))
                     if event["symbol"] == "SKYD")
        return [{"target_id": "SKYD_" + role + "_complete", "channel": "official", "event": event,
                 "url": references[key]["url"], "reference": references[key],
                 "listing_url": "https://ir.skydance.com/financials/quarterly-results",
                 "require_seed_candidate": True, "require_raw_reference_match": True,
                 "cache_profile": "ordinary", "pipeline": "production_watch_list_seed"}
                for role, key in (("shareholder_letter", "SKYD_PDF"), ("trending_schedules", "SKYD_XLSX"))]
    if scope == "skyd-http1-material":
        return [{**select_targets(targets, "skyd-materials")[1],
                 "target_id": "SKYD_trending_schedules_http1_material", "protocol_profile": "chrome_h1"}]
    if scope == "skyd-range":
        return [{**select_targets(targets, "skyd-materials")[1],
                 "target_id": "SKYD_trending_schedules_range_material", "reference_bytes": 11841890,
                 "reference_sha256": "824cd6a60c98b4a1f6668452f3c24b29b46ec58fa3987d7374b6b2195d497bf4"}]
    if scope == "skyd-materials":
        event = next(event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))
                     if event["symbol"] == "SKYD")
        return [{"target_id": "SKYD_" + role + "_material", "channel": "official", "event": event,
                 "url": "https://ir.skydance.com/static-files/" + document,
                 "listing_url": "https://ir.skydance.com/financials/quarterly-results",
                 "purpose": "material_download", "material_format": kind,
                 "transport": "curl_cffi_chrome", "cache_profile": "ordinary"}
                for role, document, kind in (("shareholder_letter", "af510edc-00d2-44ca-8e8c-b73466e99694", "pdf"),
                                             ("trending_schedules", "ce71d9f0-8c13-4a67-9259-576b602305da", "xlsx"))]
    if scope == "lcid-chrome-protocols":
        return [{**target, "target_id": "LCID_pdf_" + profile, "protocol_profile": profile,
                 "transport": "curl_cffi_chrome", "cache_profile": "ordinary"}
                for target, profile in zip(select_targets(targets, "lcid-http-protocols"), ("chrome_h1", "chrome_h2"))]
    if scope == "b-sec-transports":
        target = next(row for row in select_targets(targets, "repaired-paths") if row["event"]["symbol"] == "B")
        target = {key: value for key, value in target.items() if key != "pipeline"}
        return [{**target, "target_id": "B_sec_" + profile, "protocol_profile": profile, "sec_rps": 2,
                 "warmup_url": target["reference"]["connection_warmup_url"],
                 **({"transport": "curl_cffi_chrome"} if profile == "curl_chrome" else {})}
                for profile in ("httpx_h2", "curl_chrome")]
    if scope == "lcid-http-protocols":
        target = next(row for row in select_targets(targets, "repaired-paths") if row["event"]["symbol"] == "LCID")
        target = {key: value for key, value in target.items() if key != "pipeline"}
        listing = next(source["url"] for source in target["event"]["sources"] if source["channel"] == "official")
        return [{**target, "target_id": "LCID_pdf_" + profile, "protocol_profile": profile,
                 "http1": profile == "h1_only", "warmup_url": listing, "require_raw_reference_match": True}
                for profile in ("h1_only", "h2_enabled")]
    if scope == "sec-quarterly":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        events = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        return [{"target_id": symbol + "_sec_quarterly", "channel": "sec",
                 "url": references[symbol + "_SEC_QUARTERLY"]["url"], "reference": references[symbol + "_SEC_QUARTERLY"],
                 "event": events[symbol], "cache_profile": "ordinary", "pipeline": "production_watch_list_seed"}
                for symbol in ("TTWO", "XENE", "LCID", "HIMS", "RKLB", "OXY")]
    if scope == "backlog-production":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        events = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        return [{"target_id": symbol + "_backlog_full_report", "channel": "sec" if symbol in ("KKR", "CECO") else "official",
                 "url": references[symbol + "_BACKLOG_PRODUCTION"]["url"], "reference": references[symbol + "_BACKLOG_PRODUCTION"],
                 "event": events[symbol], "cache_profile": "ordinary", "pipeline": "production_watch_list_seed"}
                for symbol in ("TTD", "KKR", "TTWO", "RKLB", "CECO")]
    if scope == "repaired-paths":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        events = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        return [{"target_id": symbol + "_repaired_full_report", "channel": "sec" if symbol == "B" else "newswire" if symbol == "FNV" else "official",
                 "url": references[symbol + "_REPAIR"]["url"], "reference": references[symbol + "_REPAIR"],
                 "event": {**events[symbol], **references[symbol + "_REPAIR"].get("event_override", {})},
                 "cache_profile": "ordinary", "pipeline": "production_watch_list_seed"}
                for symbol in ("LCID", "FNV", "ACHR", "HIMS", "B")]
    if scope == "all":
        return targets
    if scope == "msgk-production-issuer":
        return [{**select_targets(targets, "msgk-issuer-cold")[0], "pipeline": "production_watch_list_seed",
                 "discovery_route": "actual_issuer_rss"}]
    if scope == "msgk-browser-transport":
        wire = select_targets(targets, "msgk-cache-control")[1]
        issuer = select_targets(targets, "msgk-issuer-cold")[0]
        return [{**target, "target_id": target["target_id"] + "_chrome", "transport": "curl_cffi_chrome"}
                for target in (wire, issuer)]
    if scope == "msgk-issuer-cold":
        target = {key: value for key, value in select_targets(targets, "alternate-routes")[1].items() if key != "warmup_url"}
        return [{**target, "http1": True}]
    if scope == "alternate-routes":
        bam = select_targets(targets, "bam-pdf")[0]
        wire = next(row for row in targets if row["event"]["symbol"] == "MSGK" and row["channel"] == "newswire")
        reference = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))["MSGK_ISSUER"]
        issuer = {**wire, "target_id": "MSGK_official_issuer_copy", "channel": "official", "url": reference["url"],
                  "canonical_url": wire["url"], "canonical_channel": "newswire", "document_variant": "issuer_copy",
                  "route_note": "公司官网副本", "reference": reference, "cache_profile": "ordinary"}
        return [{**target, "warmup_url": urlsplit(target["url"])._replace(path="/", query="", fragment="").geturl()}
                for target in (bam, issuer)]
    if scope == "bam-pdf":
        target = next(row for row in targets if row["event"]["symbol"] == "BAM" and row["channel"] == "newswire")
        reference = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))["BAM_PDF"]
        return [{**target, "target_id": target["target_id"] + "_official_pdf", "url": reference["url"],
                 "canonical_url": target["url"], "canonical_channel": "newswire", "canonical_previous_status": 403, "canonical_previous_run": "42573904389",
                 "document_variant": "official_pdf_alternative", "route_note": "财经稿（官方PDF备用）",
                 "cache_profile": "ordinary", "reference": reference}]
    if scope == "msgk-cache-control-reverse":
        return list(reversed(select_targets(targets, "msgk-cache-control")))
    if scope == "msgk-cache-control":
        target = next(row for row in targets if row["event"]["symbol"] == "MSGK" and row["channel"] == "newswire")
        reference = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))["MSGK"]
        return [{**target, "target_id": target["target_id"] + "_" + profile,
                 "cache_profile": profile, "reference": reference} for profile in ("no_cache", "ordinary")]
    if scope == "remaining-paths":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        selected = []
        for row in targets:
            symbol = row["event"]["symbol"]
            if row["channel"] != "newswire" or symbol not in ("BAM", "MSGK"):
                continue
            target = {**row, "reference": references[symbol]}
            if symbol == "BAM":
                target.update(canonical_url=row["url"], url=references[symbol]["print_url"],
                              target_id=row["target_id"] + "_print",
                              canonical_previous_status=403,
                              canonical_previous_run="42573904389")
            else:
                target["pipeline"] = "production_watch_list_seed"
            selected.append(target)
        return selected
    return [row for row in targets if row["channel"] == "sec" or
            scope == "sec-businesswire" and urlsplit(row["url"]).hostname == "www.businesswire.com"]


def content_hashes(parsed):
    return {"text_sha256": digest(parsed["text"].encode()),
            "table_sha256": [digest(json.dumps(table, ensure_ascii=False, separators=(",", ":")).encode())
                             for table in parsed["tables"]]}


def financial_row_hashes(tables):
    hashes = []
    for table in tables:
        rows = []
        for row in table:
            label = re.sub(r"[^a-z]", "", unicodedata.normalize("NFKC", row[0]).lower())
            cells = " ".join(str(cell or "") for cell in row[1:])
            cells = re.sub(r"\s+\)", ")", re.sub(r"\(\s+", "(", cells))
            rows.append([label, *re.findall(r"\(?[+\-\u2212]?\d[\d,]*(?:\.\d+)?\)?|[\u2014\u2013]", cells)])
        hashes.append(digest(json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()))
    return hashes


def reference_match(parsed, reference):
    actual = content_hashes(parsed)
    result = {**actual, "reference_text_matches": actual["text_sha256"] in (reference["text_sha256"], *reference.get("text_sha256_variants", ())),
            "reference_tables_match": actual["table_sha256"] == reference.get("table_sha256"),
            "reference_raw_sha256": reference["raw_sha256"], "reference_url": reference["url"]}
    if "pdf_pages_total" in reference:
        result["reference_pages_match"] = parsed.get("pdf_pages_total") == parsed.get("pdf_pages_processed") == reference["pdf_pages_total"]
    if "financial_row_sha256" in reference:
        actual_rows = financial_row_hashes([table["data_rows"] for table in parsed.get("table_details", [])])
        result.update(financial_row_sha256=actual_rows, reference_tables_match=actual_rows == reference["financial_row_sha256"],
                      reference_tables_basis="all 79 financial data rows; normalized labels and exact numeric tokens; headers retained and checked by native PDF structure gates")
    if "table_spans_sha256" in reference:
        result["reference_spans_match"] = digest(json.dumps(parsed.get("table_spans"), ensure_ascii=False,
            separators=(",", ":")).encode()) == reference["table_spans_sha256"]
    if "structure_sha256" in reference:
        structure = ({key: value for key, value in parsed.get("spreadsheet", {}).items() if key != "parse_ms"}
                     if reference.get("format") == "xlsx" else
                     {key: parsed.get(key) for key in ("table_details", "page_diagnostics", "pdf_metadata")})
        result["reference_structure_matches"] = digest(json.dumps(structure, ensure_ascii=False,
            sort_keys=True, separators=(",", ":")).encode()) == reference["structure_sha256"]
    return result


async def collect_one(client, target, output, node, recent, blocked):
    started = time.perf_counter_ns()
    row = {"target_id": target["target_id"], "symbol": target["event"]["symbol"],
           "channel": target["channel"], "url": target["url"], "mode": "replay", "node": node,
           "started_utc": utc(), "parsed_utc": None, "status": None, "attempts": 1,
           "discovery_to_parsed_ms": None, "budget_passed": False, "complete": False,
           "headers_ms": None, "body_ms": None, "parse_ms": None, "request_total_ms": None,
           "http_response_complete": False, "archived": False, "artifacts": [],
           "timing_scope": "known URL invocation through rate queue, real network download, hash and full parse; excludes subsequent artifact writes",
           "new_release_evidence": False}
    row.update({key: target[key] for key in ("canonical_url", "canonical_channel", "canonical_previous_status", "canonical_previous_run", "document_variant", "route_note") if key in target})
    if target.get("document_variant"):
        row["actual_source_url"] = target["url"]
    row.update({key: target[key] for key in ("cache_profile", "purpose", "protocol_profile") if key in target})
    material = target.get("purpose") == "material_download"
    if material:
        row.update(mode="download_only", accepted=False, tables_complete=False, material_download_complete=False,
                   timing_scope="Public material download through HTTP EOF and raw archive only; no financial parsing, capture or 300ms SLA")
    row["request_method"] = target.get("method", "GET")
    body, parsed = bytearray(), None
    browser = target.get("transport") == "curl_cffi_chrome"
    if browser:
        row["transport"] = "curl_cffi_chrome"
    trace_started, trace_ms, trace_count, connections = {}, {}, 0, 0
    async def trace(name, info):
        nonlocal trace_count, connections
        trace_count += 1
        stage, event = name.rsplit(".", 1)
        if name.endswith("connect_tcp.started"):
            connections += 1
        if event == "started":
            trace_started[stage] = time.perf_counter_ns()
        elif event in ("complete", "failed") and stage in trace_started:
            trace_ms[stage] = trace_ms.get(stage, 0) + (time.perf_counter_ns() - trace_started.pop(stage)) / 1e6
    try:
        row["queue_ms"] = 0
        headers = dict(HEADERS)
        if target.get("cache_profile") == "ordinary":
            headers.pop("Cache-Control")
        if host_key(target["url"]) == "sec.gov":
            identity = os.environ.get("SEC_USER_AGENT", "").strip()
            if not identity:
                row.update(error_type="identity_missing", request_skipped=True, attempts=0)
                return row
            headers["User-Agent"] = identity

        async def limited_request(request):
            queued = time.perf_counter_ns()
            await pace(str(request.url), recent, blocked, sec_rps=target.get("sec_rps", 8))
            row["queue_ms"] += (time.perf_counter_ns() - queued) / 1e6

        # HTTPX invokes this for redirects too, preserving the per-host request budget.
        request_start = time.perf_counter_ns()
        if browser:
            from browser_transport import browser_response, browser_timing
            await limited_request(httpx.Request(row["request_method"], target["url"]))
            transfer = browser_response(client, row["request_method"], target["url"], headers)
        else:
            client.event_hooks["request"] = [limited_request]
            transfer = client.stream(row["request_method"], target["url"], headers=headers, extensions={"trace": trace})
        async with transfer as response:
            headers_at = time.perf_counter_ns()
            row.update(status=response.status_code, final_url=str(response.url), http_version=response.http_version,
                       headers_ms=None if browser else (headers_at - request_start) / 1e6,
                       content_type=response.headers.get("content-type", ""))
            if browser:
                row.update(browser_timing(response))
            if target.get("document_variant"):
                row["actual_source_url"] = str(response.url)
            cache_header_names = ("cache-control", "age", "x-cache", "x-cache-hits", "cf-cache-status", "date", "etag", "last-modified", "connection")
            if target.get("protocol_profile"):
                cache_header_names += ("server", "via", "content-encoding", "content-length", "x-served-by")
            row["response_cache_headers"] = {key: response.headers[key] for key in cache_header_names if key in response.headers}
            if response.status_code in (403, 429):
                retry_after = response.headers.get("retry-after", "")
                seconds = 120
                try:
                    seconds = max(seconds, int(retry_after) if retry_after.isdigit() else
                                  parsedate_to_datetime(retry_after).timestamp() - time.time())
                except (ValueError, TypeError, OverflowError):
                    pass
                path = urlsplit(str(response.url)).path if response.status_code == 403 else ""
                blocked[(host_key(str(response.url)), path)] = time.perf_counter() + seconds
                row.update(cooldown_seconds=seconds, cooldown_scope="path" if path else "host")
            if browser:
                body.extend(response.content)
            else:
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
        body_at = time.perf_counter_ns()
        row.update(http_response_complete=True, body_complete_utc=utc(),
                   body_ms=None if browser else (body_at - headers_at) / 1e6,
                   request_total_ms=(body_at - request_start) / 1e6,
                   discovery_to_body_ms=(body_at - started) / 1e6)
        raw = bytes(body)
        row.update(bytes=len(raw), sha256=digest(raw))
        if material:
            kind = ("pdf" if raw.startswith(b"%PDF") else "xlsx" if raw.startswith(b"PK\x03\x04")
                    and (target["material_format"] == "xlsx" or "spreadsheetml" in row["content_type"]) else None)
            row["material_format"] = kind
            if row["status"] == 200 and kind != target["material_format"]:
                row["error_type"] = "UnexpectedMaterialType"
        if row["status"] == 200 and target.get("purpose") not in ("connection_warmup", "material_download"):
            parse_queued = time.perf_counter_ns()

            def parse():
                began = time.perf_counter_ns()
                result = validate(raw, row["final_url"], row["content_type"], target["event"])
                tables_sha = digest(json.dumps(result["tables"], ensure_ascii=False, separators=(",", ":")).encode())
                comparison = reference_match(result, target["reference"]) if "reference" in target else {}
                ended = time.perf_counter_ns()
                return result, tables_sha, comparison, began, ended, utc()

            parsed, tables_sha, comparison, parse_start, parse_end, parsed_utc = await asyncio.to_thread(parse)
            total = (parse_end - started) / 1e6
            complete = parsed.get("accepted") is True and parsed.get("tables_complete") is True
            if comparison:
                complete = complete and comparison["reference_text_matches"] and comparison["reference_tables_match"] and comparison.get("reference_pages_match", True)
                if target.get("require_raw_reference_match"):
                    comparison["reference_raw_matches"] = row["sha256"] == comparison["reference_raw_sha256"]
                    complete = complete and comparison["reference_raw_matches"]
                row.update(comparison)
            row.update(parsed_utc=parsed_utc, parse_ms=(parse_end - parse_start) / 1e6,
                       validation_queue_ms=(parse_start - parse_queued) / 1e6,
                       discovery_to_parsed_ms=total, complete=complete,
                       budget_passed=complete and total <= 300,
                       table_count=len(parsed["tables"]), text_characters=len(parsed["text"]),
                       tables_sha256=tables_sha,
                       checks=parsed.get("checks"), quality_reason=parsed.get("quality_reason") or parsed.get("reason"),
                       pdf_pages_total=parsed.get("pdf_pages_total"), pdf_pages_processed=parsed.get("pdf_pages_processed"),
                       pdf_structure_checks=parsed.get("pdf_structure_checks"))
        elif row["status"] != 200:
            row["error_type"] = "HTTP_" + str(row["status"])
    except Exception as exc:
        row["error_type"] = type(exc).__name__
        row["error_message"] = safe_error_message(exc)
    finally:
        if not browser:
            row.update(transport_trace_ms=trace_ms, new_tcp_connections=connections,
                       connection_reused=connections == 0 if trace_count else None)
        row["ended_utc"] = utc()
        row["invocation_to_end_ms"] = (time.perf_counter_ns() - started) / 1e6
        try:
            if body:
                suffix = ".xlsx" if material and row.get("material_format") == "xlsx" else ".pdf" if body.startswith(b"%PDF") else ".html"
                name = target["target_id"] + suffix
                (output / "raw" / name).write_bytes(body)
                row["artifacts"].append("raw/" + name)
                row["raw_document_artifact"] = "raw/" + name
                row.setdefault("bytes", len(body))
                row.setdefault("sha256", digest(body))
            if parsed is not None:
                name = target["target_id"] + ".json"
                (output / "parsed" / name).write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
                row["artifacts"].append("parsed/" + name)
            row["archived"] = bool(body)
        except OSError as exc:
            row["archive_error_type"] = type(exc).__name__
        row["invocation_to_archived_ms"] = (time.perf_counter_ns() - started) / 1e6
        if material:
            row["material_download_complete"] = bool(row["status"] == 200 and row["http_response_complete"]
                and row["archived"] and row.get("material_format") == target["material_format"]
                and not row.get("error_type") and not row.get("archive_error_type"))
        log_name = "materials.ndjson" if material else "warmup.ndjson" if target.get("purpose") == "connection_warmup" else "results.ndjson"
        with (output / log_name).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(json.dumps({key: row.get(key) for key in ("target_id", "symbol", "status", "discovery_to_parsed_ms", "complete", "budget_passed", "error_type")}), flush=True)
    return row


async def collect_material_ranges(client, target, output, node, recent, blocked):
    """One exact three-part old-file download; financial acceptance stays false."""
    started = time.perf_counter_ns()
    size = target["reference_bytes"]
    row = {"target_id": target["target_id"], "symbol": target["event"]["symbol"], "channel": target["channel"],
           "url": target["url"], "node": node, "purpose": "material_download", "mode": "download_only",
           "started_utc": utc(), "parsed_utc": None, "discovery_to_parsed_ms": None,
           "complete": False, "accepted": False, "tables_complete": False, "budget_passed": False,
           "new_release_evidence": False, "material_download_complete": False, "archived": False,
           "http_response_complete": False, "artifacts": [], "reference_bytes": size,
           "reference_sha256": target["reference_sha256"], "attempts": 1,
           "timing_scope": "Three parallel ranges from group invocation before rate queues through all HTTP EOFs, ordered assembly and complete SHA256; excludes listing and subsequent archives. Old-material download only, not full parsing or 300ms SLA."}

    async def part(index):
        first, last = index * size // 3, (index + 1) * size // 3 - 1
        queued = time.perf_counter_ns()
        record = {"part": index, "purpose": "material_download", "url": target["url"],
                  "requested_range": f"bytes={first}-{last}", "expected_bytes": last - first + 1,
                  "expected_total_bytes": size, "started_utc": utc(), "attempts": 1,
                  "status": None, "http_response_complete": False, "stopped_on_headers": False}
        body = bytearray()
        request_started = None
        try:
            await pace(target["url"], recent, blocked)
            request_started = time.perf_counter_ns()
            record.update(queue_ms=(request_started - queued) / 1e6, request_start_utc=utc())
            async with client.stream("GET", target["url"], headers={"Range": record["requested_range"], "Accept-Encoding": "identity"}) as response:
                record.update(status=response.status_code, final_url=str(response.url),
                              content_range=response.headers.get("content-range"),
                              content_length=response.headers.get("content-length"),
                              content_type=response.headers.get("content-type"),
                              content_encoding=response.headers.get("content-encoding"),
                              stream_response_ready_ms=(time.perf_counter_ns() - request_started) / 1e6)
                expected_range = f"bytes {first}-{last}/{size}"
                if (response.status_code != 206 or (record["content_range"] or "").strip().lower() != expected_range
                        or (record["content_length"] is not None and record["content_length"] != str(last - first + 1))
                        or (record["content_encoding"] or "identity").lower() != "identity"):
                    # Pinned curl_cffi 0.16.0 ac lose only waits. Its stream qput
                    # aborts the next write when quit_now is set; do not drain a 200 body.
                    response.quit_now.set()
                    record["stopped_on_headers"] = True
                    raise ValueError("Range response must be 206 with exact unencoded Content-Range and length")
                async for chunk in response.aiter_content():
                    body.extend(chunk)
                    if len(body) > last - first + 1:
                        response.quit_now.set()
                        raise ValueError("Range response exceeded the requested bytes")
                if len(body) != last - first + 1:
                    raise ValueError("Range HTTP EOF arrived without all requested bytes")
                record.update(http_response_complete=True, body_complete_utc=utc())
        except Exception as exc:
            record.update(error_type=type(exc).__name__, error_message=safe_error_message(exc))
        ended = time.perf_counter_ns()
        record.update(ended_utc=utc(), bytes=len(body), sha256=digest(body),
                      request_total_ms=(ended - request_started) / 1e6 if request_started is not None else None,
                      invocation_to_end_ms=(ended - queued) / 1e6,
                      header_timing_semantics="Stream response returns after the first libcurl body callback; not pure header arrival")
        return record, bytes(body)

    pieces = await asyncio.gather(*(part(index) for index in range(3)))
    row["parts"] = [record for record, _ in pieces]
    raw = b""
    if all(record["http_response_complete"] for record, _ in pieces):
        raw = b"".join(body for _, body in pieces)
        row.update(http_response_complete=True, bytes=len(raw), sha256=digest(raw), material_format="xlsx")
        row["reference_sha256_matches"] = len(raw) == size and row["sha256"] == target["reference_sha256"]
        row.update(download_hash_completed_utc=utc(), invocation_to_hashed_download_ms=(time.perf_counter_ns() - started) / 1e6)
        if not row["reference_sha256_matches"]:
            row["error_type"] = "ReferenceSha256Mismatch"
    else:
        row["error_type"] = "RangeDownloadIncomplete"
    row.update(ended_utc=utc(), invocation_to_end_ms=(time.perf_counter_ns() - started) / 1e6)
    try:
        if raw:
            name = "raw/" + target["target_id"] + ".xlsx"
            (output / name).write_bytes(raw)
            row.update(raw_document_artifact=name, archived=True)
            row["artifacts"].append(name)
        if row.get("error_type"):
            for record, body in pieces:
                if body:
                    name = f"raw/{target['target_id']}_part{record['part']}.bin"
                    (output / name).write_bytes(body)
                    record["raw_document_artifact"] = name
                    row["artifacts"].append(name)
    except OSError as exc:
        row["archive_error_type"] = type(exc).__name__
    row["material_download_complete"] = bool(row["archived"] and row.get("reference_sha256_matches") and not row.get("archive_error_type"))
    row["invocation_to_archived_ms"] = (time.perf_counter_ns() - started) / 1e6
    with (output / "range_parts.ndjson").open("a", encoding="utf-8") as stream:
        for record, _ in pieces:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    with (output / "materials.ndjson").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({key: row.get(key) for key in ("target_id", "material_download_complete", "invocation_to_hashed_download_ms", "error_type")}), flush=True)
    return row


async def collect_watch_case(target, output, node):
    """One production probe; the listing request is real, the supplied URL is a replay."""
    row = {"target_id": target["target_id"], "symbol": target["event"]["symbol"],
           "channel": target["channel"], "url": target["url"], "mode": "replay", "node": node,
           "started_utc": utc(), "parsed_utc": None, "status": None, "attempts": 1,
           "discovery_to_parsed_ms": None, "budget_passed": False, "complete": False,
           "http_response_complete": False,
           "archived": False, "artifacts": [], "new_release_evidence": False,
           "pipeline": "production_watch_list_seed",
           "timing_scope": "Known old URL invocation after one real listing request; production queue/download/full parse. Listing request and CLI startup reported separately. Reference hash comparison is a post-capture audit.",
           "discovery_timestamp_semantics": "replay_invocation_not_live_discovery"}
    row.update({key: target[key] for key in ("canonical_url", "canonical_channel", "document_variant", "route_note") if key in target})
    if target.get("document_variant"):
        row["actual_source_url"] = target["url"]
    actual_discovery = target.get("discovery_route") == "actual_issuer_rss"
    if actual_discovery:
        row.update(discovery_route="actual_issuer_rss", discovery_timestamp_semantics="listing_response_complete_not_earliest_candidate_byte",
                   timing_scope="Production RSS discovery to full parse; original listing-complete monotonic clock includes candidate queue/download/parse. RSS request to parse is separately retained.")
    started = time.perf_counter_ns()
    try:
        with tempfile.TemporaryDirectory(prefix="earnings-production-probe-") as directory:
            runtime = Path(directory)
            command = [sys.executable, str(BASE / "live/watch.py"), "probe", "--manifest", str(BASE / "live/watchlist.json"),
                       "--output", str(runtime), "--symbols", target["event"]["symbol"], "--channel", target["channel"],
                       "--samples", "1",
                       "--node", "github-actions-" + str(node.get("loc")) + "-" + str(node.get("colo"))]
            if target.get("metrics_mode") == "synthetic":
                command.extend(["--metrics-mode", "synthetic", "--metrics-rules",
                                str(BASE / "live/earnings_metrics_rules.json")])
            discovery_event = target["event"]
            if actual_discovery:
                discovery_event = next(event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))
                                       if event["symbol"] == target["event"]["symbol"])
                discovery_event = {**discovery_event, "sources": [source for source in discovery_event["sources"] if source["channel"] == target["channel"]]}
                manifest = runtime / "public_probe_manifest.json"
                manifest.write_text(json.dumps([discovery_event], ensure_ascii=False), encoding="utf-8")
                command[command.index("--manifest") + 1] = str(manifest)
            else:
                command.extend(["--candidate-url", target.get("filing_index_url", target["url"])])
                if target.get("filing_form"):
                    command.extend(["--candidate-filing-form", target["filing_form"]])
                if target["reference"].get("event_override"):
                    manifest = runtime / "public_probe_manifest.json"
                    manifest.write_text(json.dumps([target["event"]], ensure_ascii=False), encoding="utf-8")
                    command[command.index("--manifest") + 1] = str(manifest)
            child_env = {key: value for key, value in os.environ.items()
                         if key not in ("GITHUB_TOKEN", "GH_TOKEN", "SEC_USER_AGENT", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")}
            if target["channel"] == "sec":
                child_env["SEC_USER_AGENT"] = os.environ.get("SEC_USER_AGENT", "")
                command.extend(["--sec-rps", "2"])
                if target["reference"].get("connection_warmup_url"):
                    command.extend(["--sec-warmup-url", target["reference"]["connection_warmup_url"]])
            elif target["reference"].get("connection_warmup_url"):
                command.extend(["--origin-warmup-url", target["reference"]["connection_warmup_url"]])
            result = await asyncio.to_thread(subprocess.run, command, cwd=BASE / "live", env=child_env,
                                             capture_output=True, timeout=180)
            row["collector_exit_code"] = result.returncode
            connection = sqlite3.connect((runtime / "observations.sqlite3").as_uri() + "?mode=ro", uri=True)
            try:
                requests = [json.loads(payload) for (payload,) in connection.execute("select payload from log where kind='request' order by id")]
                captures = [json.loads(payload) for (payload,) in connection.execute("select payload from log where kind='capture' order by id")]
                metric_records = [json.loads(payload) for (payload,) in connection.execute("select payload from log where kind='metric_extraction' order by id")]
            finally:
                connection.close()
            public_requests = []
            request_keys = ("id", "run_id", "symbol", "channel", "purpose", "method", "url", "final_url", "status", "http_version",
                            "request_start_utc", "request_end_utc", "body_complete_utc", "first_body_byte_utc",
                            "queued_mono_ns", "request_start_mono_ns", "request_end_mono_ns", "body_complete_mono_ns",
                            "queue_ms", "queue_reasons", "request_total_ms", "response_headers_received_ms", "body_download_ms",
                            "first_body_callback_ms", "connection_reused", "new_tcp_connections", "sha256", "body_bytes",
                            "cooldown_seconds", "cooldown_scope", "transport", "transport_version", "curl_cumulative_ms",
                            "header_timing_semantics", "body_timing_semantics", "http_response_complete",
                            "html_stream_parse_ms", "download_includes_html_tree_build", "sec_stream_attempt",
                            "target_document_complete", "target_document_url", "extracted_form", "body_complete_semantics")
            for index, request in enumerate(requests):
                safe = {key: request[key] for key in request_keys if key in request}
                if request.get("error"):
                    safe["error"] = safe_error_message(request["error"])
                raw = gzip.open(runtime / request["raw_path"], "rb").read() if request.get("raw_path") else b""
                if raw:
                    suffix = ".xlsx" if raw.startswith(b"PK\x03\x04") else ".pdf" if raw.startswith(b"%PDF") else ".html"
                    name = "raw/" + target["target_id"] + "_" + str(index) + "_" + request["purpose"] + suffix
                    (output / name).write_bytes(raw)
                    safe["artifact"] = name
                    row["artifacts"].append(name)
                if request["purpose"] == "discovery":
                    row["seed"] = safe
                    row["seed_listing_contains_candidate"] = any(item["url"].rstrip("/") == target["url"].rstrip("/")
                         for item in discover(raw, request.get("final_url", request["url"]), "text/html", discovery_event)) if raw and request.get("status") == 200 else False
                elif request["purpose"] == "warmup":
                    row.setdefault("connection_warmups", []).append(safe)
                else:
                    if (captures and captures[0].get("sha256")
                            and request.get("sha256") != captures[0]["sha256"]):
                        public_requests.append(safe)
                        continue
                    row.update(status=request.get("status"), queue_ms=request.get("queue_ms"),
                               headers_ms=request.get("response_headers_received_ms"), request_total_ms=request.get("request_total_ms"),
                               http_version=request.get("http_version"), connection_reused=request.get("connection_reused"))
                    row.update({key: request[key] for key in ("transport", "transport_version", "curl_cumulative_ms", "header_timing_semantics", "body_timing_semantics",
                        "html_stream_parse_ms", "download_includes_html_tree_build") if key in request})
                    if target.get("document_variant"):
                        row["actual_source_url"] = request.get("final_url", target["url"])
                    body_verified = bool(raw) and len(raw) == request.get("body_bytes") and digest(raw) == request.get("sha256")
                    verified_body_end = (body_verified and request.get("body_complete_mono_ns") is not None
                        and request.get("request_end_mono_ns") == request["body_complete_mono_ns"] and not request.get("error"))
                    row["http_response_complete"] = verified_body_end and not request.get("sec_stream_attempt")
                    row["target_document_complete"] = bool(verified_body_end and request.get("target_document_complete"))
                    row["body_completion_scope"] = ("complete_exhibit_at_sgml_closing_markers" if row["target_document_complete"]
                                                     else "whole_http_response" if row["http_response_complete"] else "unproven")
                    if body_verified:
                        canonical = "raw/" + target["target_id"] + suffix
                        (output / canonical).write_bytes(raw)
                        row["artifacts"].append(canonical)
                        row.update(raw_document_artifact=canonical, bytes=len(raw), sha256=digest(raw))
                public_requests.append(safe)
            request_log = "requests_" + target["target_id"] + ".ndjson"
            (output / request_log).write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in public_requests), encoding="utf-8")
            row["artifacts"].append(request_log)
            if captures:
                capture = captures[0]
                stem = Path(capture["original_document_path"]).with_suffix("")
                saved = json.loads((runtime / stem.with_suffix(".json")).read_text(encoding="utf-8"))
                parsed = {"text": (runtime / stem.with_suffix(".txt")).read_text(encoding="utf-8"), "tables": saved["tables"]}
                parsed.update({key: saved[key] for key in ("table_spans", "table_details", "page_diagnostics", "spreadsheet") if key in saved})
                verdict = capture["validation"]
                parsed.update({key: verdict[key] for key in ("accepted", "tables_complete", "checks", "reason", "title",
                    "pdf_pages_total", "pdf_pages_processed", "pdf_pages_text_extracted", "pdf_structure_checks",
                    "tables_extraction_scope", "pdf_metadata", "document_format", "document_facts",
                    "xlsx_sheets_total", "xlsx_sheets_processed", "explicit_cell_count", "formula_count", "merge_count", "display_complete") if key in verdict})
                comparison = reference_match(parsed, target["reference"])
                complete = ((row["http_response_complete"] or row.get("target_document_complete"))
                            and verdict.get("accepted") is True and verdict.get("tables_complete") is True
                            and comparison["reference_text_matches"] and comparison["reference_tables_match"]
                            and comparison.get("reference_pages_match", True)
                            and comparison.get("reference_spans_match", True)
                            and comparison.get("reference_structure_matches", True))
                if target["reference"].get("raw_sha256"):
                    row["reference_raw_matches"] = row.get("sha256") == target["reference"]["raw_sha256"]
                if target.get("require_raw_reference_match"):
                    complete = complete and row["reference_raw_matches"]
                if target.get("require_seed_candidate"):
                    complete = (complete and row.get("seed_listing_contains_candidate") is True
                                and row.get("seed", {}).get("status") == 200
                                and row.get("seed", {}).get("url") == target["listing_url"])
                if actual_discovery:
                    row["discovery_clock_preserved"] = (capture.get("listing_request_id") == row.get("seed", {}).get("id")
                        and capture.get("discovered_mono_ns") is not None
                        and capture["discovered_mono_ns"] == row.get("seed", {}).get("body_complete_mono_ns"))
                    complete = complete and row["discovery_clock_preserved"] and row.get("seed_listing_contains_candidate") is True
                elapsed = capture.get("discovery_to_parsed_ms")
                row.update(**comparison, complete=complete, discovery_to_parsed_ms=elapsed,
                           budget_passed=complete and elapsed is not None and elapsed <= 300,
                           started_utc=capture["discovered_utc"], parsed_utc=capture["validated_utc"],
                           parse_ms=capture.get("parse_ms"), validation_queue_ms=capture.get("validation_queue_ms"),
                           table_count=len(parsed["tables"]), text_characters=len(parsed["text"]), sha256=capture["sha256"],
                           bytes=capture["body_bytes"], tables_sha256=digest(json.dumps(parsed["tables"], ensure_ascii=False, separators=(",", ":")).encode()),
                           candidate_attempt=capture.get("candidate_attempt"), retry=capture.get("retry"),
                           discovered_mono_ns=capture.get("discovered_mono_ns"), validated_mono_ns=capture.get("validated_mono_ns"),
                           listing_request_id=capture.get("listing_request_id"),
                           discovery_to_archive_ms=None, archive_timing_note="Production archive completion has no recorded continuous timestamp; CLI end is only an upper bound")
                if requests:
                    row["seed_request_to_parsed_ms"] = (capture["validated_mono_ns"] - row["seed"]["queued_mono_ns"]) / 1e6
                name = "parsed/" + target["target_id"] + ".json"
                (output / name).write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
                row["artifacts"].append(name)
                row["archived"] = True
                if target.get("metrics_mode") == "synthetic":
                    sys.path.insert(0, str(BASE / "live"))
                    from metrics_pipeline import public_synthetic_extraction
                    public_metrics = [safe for record in metric_records
                        if record.get("document_hash") == capture["sha256"]
                        and (safe := public_synthetic_extraction(record)) is not None]
                    row["metric_extractions"] = public_metrics
                    row["metrics_pipeline_completed"] = bool(public_metrics) and all(
                        record.get("status") == "completed" for record in public_metrics)
                    row["decision_budget_ms"] = 500
                    row["decision_budget_passed"] = complete and bool(public_metrics) and all(
                        record.get("decision_budget_passed") is True for record in public_metrics)
                    if not row["metrics_pipeline_completed"]:
                        row["error_type"] = "metrics_pipeline_not_completed"
            else:
                row["error_type"] = ("HTTP_" + str(row["status"]) if row["status"] is not None and row["status"] != 200
                                     else "production_capture_missing")
    except Exception as exc:
        row.update(error_type=type(exc).__name__)
    row.update(ended_utc=utc(), cli_start_to_archived_upper_ms=(time.perf_counter_ns()-started)/1e6)
    with (output / "results.ndjson").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({key: row.get(key) for key in ("target_id", "symbol", "status", "discovery_to_parsed_ms", "complete", "budget_passed", "error_type")}), flush=True)
    return row


async def collect_bw_browser_access(output, *, http1=False):
    """One anonymous browser/UI observation, isolated from all financial results."""
    from importlib.metadata import version

    output.mkdir(parents=True, exist_ok=False)
    (output / "raw").mkdir()
    started = time.perf_counter_ns()
    summary = {"scope": "bw-browser-http1-access" if http1 else "bw-browser-access", "mode": "diagnostic_only", "diagnostic_only": True,
               "sla_applicable": False, "new_release_evidence": False, "started_utc": utc(),
               "started_mono_ns": started, "url": "https://www.businesswire.com/newsroom",
               "company_query": "D-Wave Quantum", "symbol": "QBTS", "navigation_attempts": 0,
               "navigation_status": None, "network_events": 0, "evidence_errors": [],
               "search": {"attempted": False}, "artifacts": [], "cooldown_seconds_on_denial": 120,
                "browser_http2_disabled": http1, "execution_environment": execution_hardware(),
                "node_semantics": "Cloudflare loc/colo identify observed egress country/responding edge, not the runner data-center"}
    phase, request_ids = "entry", {}
    denied = asyncio.Event()
    public_query_keys = {"q", "query", "keywords", "keyword", "search", "term", "page", "pagesize",
                         "pageSize", "size", "sort", "sortBy", "language", "locale"}

    def public_url(url):
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.hostname or "", parsed.path,
                           urlencode([(key, value) for key, value in parse_qsl(parsed.query)
                                      if key in public_query_keys]), ""))

    def append(kind, **fields):
        now = time.perf_counter_ns()
        row = {"kind": kind, "phase": phase, "at_utc": utc(), "mono_ns": now,
               "elapsed_ms": (now - started) / 1e6, **fields}
        # Flush each event before any DOM/screenshot work can fail or navigate.
        with (output / "browser_network.ndjson").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
        summary["network_events"] += 1

    def request_id(request):
        return request_ids.setdefault(request, len(request_ids) + 1)

    def on_request(request):
        fields = {"request_id": request_id(request), "url": public_url(request.url),
                  "method": request.method, "resource_type": request.resource_type,
                  "is_navigation": request.is_navigation_request()}
        if request.resource_type in ("xhr", "fetch") and request.post_data:
            try:
                payload = json.loads(request.post_data)
                if isinstance(payload, dict):
                    fields["public_search_fields"] = {key: value for key, value in payload.items()
                        if key in public_query_keys and isinstance(value, (str, int, float, bool, type(None)))}
            except (ValueError, TypeError):
                pass
        append("request", **fields)

    def on_response(response):
        append("response", request_id=request_id(response.request), url=public_url(response.url),
               status=response.status, resource_type=response.request.resource_type)
        if response.status in (403, 429):
            summary.setdefault("first_denial", {"url": public_url(response.url), "status": response.status,
                                                "at_utc": utc(), "mono_ns": time.perf_counter_ns()})
            denied.set()

    def on_failure(request):
        append("request_failed", request_id=request_id(request), url=public_url(request.url),
               resource_type=request.resource_type, error=safe_error_message(request.failure or "unknown"))

    async def snapshot(page, label):
        result = {"phase": label, "at_utc": utc()}
        for kind, operation in (("html", lambda: page.content()), ("title", lambda: page.title()),
                                ("png", lambda: page.screenshot(full_page=True, timeout=10000))):
            try:
                value = await asyncio.wait_for(operation(), timeout=10)
                if kind == "title":
                    result["title"] = value
                    continue
                path = "raw/browser_" + label + "." + kind
                body = value.encode("utf-8") if isinstance(value, str) else value
                (output / path).write_bytes(body)
                summary["artifacts"].append({"path": path, "bytes": len(body), "sha256": digest(body)})
                result[kind] = path
            except Exception as exc:
                summary["evidence_errors"].append({"phase": label, "artifact": kind,
                    "error_type": type(exc).__name__, "error": safe_error_message(exc), "at_utc": utc()})
        summary.setdefault("page_snapshots", []).append(result)

    async def observe_page_network():
        try:
            await asyncio.wait_for(denied.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass

    try:
        from playwright.async_api import async_playwright

        executable = shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        if not executable:
            if summary["execution_environment"]["machine"].lower() in ("aarch64", "arm64"):
                summary.update(outcome="skipped_no_installed_chrome", skipped=True)
                (output / "run.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
                return 0
            raise RuntimeError("Runner-installed Google Chrome executable not found")
        summary["playwright_version"] = version("playwright")
        summary["browser_executable"] = Path(executable).name
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=10) as client:
            summary["node"] = await identify_node(client)
        (output / "run.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(executable_path=executable, headless=True,
                                                       args=["--disable-http2"] if http1 else [])
            try:
                summary["browser_version"] = browser.version
                context = await browser.new_context()
                async def route_request(route):
                    if denied.is_set():
                        append("request_blocked_after_denial", url=public_url(route.request.url),
                               resource_type=route.request.resource_type)
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()
                await context.route("**/*", route_request)
                summary["browser_cache_policy"] = "fresh context; Playwright route instrumentation disables browser HTTP cache"
                page = await context.new_page()
                page.on("request", on_request)
                page.on("response", on_response)
                page.on("requestfailed", on_failure)
                summary["navigation_attempts"] = 1
                try:
                    response = await page.goto(summary["url"], wait_until="domcontentloaded", timeout=45000)
                    summary["navigation_status"] = response.status if response else None
                except Exception as exc:
                    summary["navigation_error"] = {"error_type": type(exc).__name__, "error": safe_error_message(exc)}
                if summary["navigation_status"] == 200 and not denied.is_set():
                    await observe_page_network()
                await snapshot(page, "entry")
                if denied.is_set():
                    summary["outcome"] = "http_denial_stop_no_retry"
                elif summary["navigation_status"] != 200:
                    summary["outcome"] = "navigation_not_readable_no_search"
                else:
                    body_text = await page.locator("body").inner_text(timeout=5000)
                    if re.search(r"captcha|verify (?:that )?you are human|checking your browser|page unavailable|access denied", body_text, re.I):
                        summary["outcome"] = "challenge_or_denial_page_no_interaction"
                    else:
                        # The current public BW help documents this exact UI action.
                        button = page.get_by_role("button", name="Add Keyword", exact=True)
                        if await button.count() == 1 and await button.is_visible():
                            region = button.locator("xpath=ancestor::*[.//input][1]")
                            inputs = region.locator("input:visible:not([type=hidden]):not([type=password]):not([type=checkbox]):not([type=radio])")
                            summary["search"]["visible_inputs"] = await inputs.evaluate_all(
                                "xs => xs.map(x => ({type:x.type,placeholder:x.placeholder,label:x.getAttribute('aria-label')}))")
                            if await inputs.count() == 1 and await inputs.first.is_editable() and not denied.is_set():
                                phase = "company_search"
                                summary["search"].update(attempted=True, at_utc=utc(), mono_ns=time.perf_counter_ns(),
                                                         action="Fill visible keyword field then click Add Keyword once")
                                await inputs.first.fill(summary["company_query"])
                                if not denied.is_set():
                                    await button.click(timeout=10000)
                                    await observe_page_network()
                                await snapshot(page, "company_search")
                                summary["outcome"] = "http_denial_stop_no_retry" if denied.is_set() else "public_ui_search_observed"
                            else:
                                summary["outcome"] = "keyword_input_not_unambiguous_no_search"
                        else:
                            summary["outcome"] = "documented_keyword_control_not_available_no_search"
            finally:
                await browser.close()
    except Exception as exc:
        summary["diagnostic_error"] = {"error_type": type(exc).__name__, "error": safe_error_message(exc)}
        summary.setdefault("outcome", "diagnostic_error")
    finally:
        ended = time.perf_counter_ns()
        summary.update(finished_utc=utc(), ended_mono_ns=ended, diagnostic_elapsed_ms=(ended - started) / 1e6)
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if "diagnostic_error" in summary else 0


async def run(args):
    if args.scope in ("bw-browser-access", "bw-browser-http1-access"):
        return await collect_bw_browser_access(args.output, http1=args.scope == "bw-browser-http1-access")
    targets = select_targets(json.loads(args.targets.read_text(encoding="utf-8")), args.scope)
    repeated_target_pair = args.scope.startswith("msgk-cache-control") or args.scope in ("lcid-http-protocols", "lcid-chrome-protocols", "b-sec-transports")
    if not targets or not repeated_target_pair and len({row["url"] for row in targets}) != len(targets):
        raise ValueError("Expected a nonempty set of distinct public report URLs")
    source_manifest = json.loads((BASE / "parser_sources.json").read_text(encoding="utf-8"))
    for name, entry in source_manifest.items():
        if digest((BASE / name).read_bytes()) != entry["sha256"]:
            raise ValueError("Parser source hash mismatch: " + name)
    collector_sources = None
    if any(target.get("pipeline") == "production_watch_list_seed" for target in targets):
        collector_sources = json.loads((BASE / "live/source_manifest.json").read_text(encoding="utf-8"))
        for name, entry in collector_sources.items():
            if digest((BASE / "live" / name).read_bytes()) != entry["sha256"]:
                raise ValueError("Collector source hash mismatch: " + name)
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("raw", "parsed"):
        (args.output / name).mkdir()
    material_scope = args.scope in ("skyd-materials", "skyd-range", "skyd-http1-material")
    warmup = {"skipped": "download_only"} if material_scope else await asyncio.to_thread(prewarm_pdf_pool)
    recent, blocked = {}, {}
    async with AsyncExitStack() as stack, httpx.AsyncClient(http2=True, trust_env=False, follow_redirects=True, max_redirects=5,
                                timeout=httpx.Timeout(12, connect=5),
                                limits=httpx.Limits(max_connections=8, max_keepalive_connections=8, keepalive_expiry=60)) as client, \
               httpx.AsyncClient(http2=False, trust_env=False, follow_redirects=True, max_redirects=5,
                                 timeout=httpx.Timeout(12, connect=5),
                                 limits=httpx.Limits(max_connections=2, max_keepalive_connections=2, keepalive_expiry=60)) as businesswire_client:
        browser_client = None
        if any(target.get("transport") == "curl_cffi_chrome" for target in targets):
            from browser_transport import browser_session
            browser_client = await stack.enter_async_context(browser_session())
            if args.scope == "skyd-http1-material":
                from curl_cffi.const import CurlHttpVersion, CurlOpt
                browser_client.curl_options[CurlOpt.HTTP_VERSION] = CurlHttpVersion.V1_1
        try:
            node = await identify_node(browser_client or client)
        except Exception as exc:
            if browser_client is None:
                raise
            node = {"loc": None, "colo": None, "is_us": False, "error_type": type(exc).__name__}
        metadata = {"scope": "old_public_document_real_download_replay_not_new_release", "node": node,
                    "execution_environment": execution_hardware(),
                    "node_semantics": "Cloudflare loc/colo identify observed egress country/responding edge, not the runner data-center",
                    "started_utc": utc(), "parser_sources": source_manifest,
                    "collector_sources": collector_sources,
                    "pdf_pool": warmup, "target_document_preparsed": False, "targets": len(targets),
                    "requests_per_second": {"parent_direct_sec": 2 if args.scope == "b-sec-transports" else 8,
                                             "production_child_sec": 2, "other_hosts_shared": 4},
                    "transport_policy": {"businesswire.com": "HTTP/1.1 persistent client after observed HTTP/2 StreamReset error_code=2", "msgk-issuer-cold": "HTTP/1.1 cold client matching the production official collector", "default": "HTTP/2 enabled"}}
        if args.scope in METRICS_SCOPES:
            metadata["requests_per_second"]["parent_direct_sec"] = 0
            metadata["metrics_mode"] = "synthetic"
            metadata["decision_budget_ms"] = 500
        if args.scope == "skyd-http1-material":
            metadata["transport_policy"]["default"] = "Chrome HTTP/1.1 forced before listing warmup"
        if material_scope:
            metadata.update(scope=args.scope.replace("-", "_") + "_download_only_not_financial_capture_or_sla", sla_applicable=False,
                            success_criterion=("Three US HTTP206 ranges exactly covering the known XLSX through EOF and assembled original SHA256 archive; financial completeness remains false" if args.scope == "skyd-range" else
                                               "One Chrome HTTP/1.1 US HTTP200 XLSX through EOF and complete raw SHA256 archive after separate verified listing warmup; financial completeness remains false" if args.scope == "skyd-http1-material" else
                                               "Two US HTTP200 responses through EOF with expected file magic and SHA256 raw archives; financial completeness remains false"),
                            requests_per_second={"parent_direct_sec": 0, "production_child_sec": 0, "other_hosts_shared": 4})
        (args.output / "run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        results = []
        if material_scope:
            listing = await collect_one(browser_client,
                {**targets[0], "url": targets[0]["listing_url"], "target_id": "SKYD_verified_quarterly_listing",
                 "purpose": "connection_warmup"}, args.output, node, recent, blocked)
            path = listing.get("raw_document_artifact")
            raw = (args.output / path).read_bytes() if path else b""
            linked = {item["url"] for item in discover(raw, targets[0]["listing_url"], listing.get("content_type", "text/html"), targets[0]["event"])}
            listing["listing_contains_all_targets"] = all(target["url"] in linked for target in targets)
            metadata["listing_verification"] = listing
            if not (listing.get("status") == 200 and listing.get("http_response_complete") and listing["listing_contains_all_targets"]):
                metadata["comparison_stopped"] = "quarterly_listing_not_verified_no_material_requests"
                metadata["skipped_targets_after_warmup"] = [target["target_id"] for target in targets]
                targets = []
            if args.scope == "skyd-range" and targets:
                results.append(await collect_material_ranges(browser_client, targets[0], args.output, node, recent, blocked))
                targets = []
        if args.scope == "b-sec-transports":
            # browser_response filters request-level UA. This dedicated session
            # is now SEC-only; node identification above used the public UA.
            browser_client.headers["User-Agent"] = os.environ.get("SEC_USER_AGENT", "").strip()
            pairs = ((client, targets[0]), (browser_client, targets[1]))
            warmups = await asyncio.gather(*(collect_one(connection,
                {**target, "url": target["warmup_url"], "target_id": target["target_id"] + "_head",
                 "method": "HEAD", "purpose": "connection_warmup"},
                args.output, node, recent, blocked) for connection, target in pairs))
            metadata.update(connection_warmups=warmups,
                comparison_scope="Same-node old B filing: HTTPX H2 and curl Chrome each HEAD a different previously verified SEC directory, then one complete target GET. Both use the declared SEC contact identity and one shared 2 rps budget. Curl eager transfer and this full-body validator differ from production incremental HTML parsing; shared parser contention remains timed. Not new-release SLA or a causal estimate.",
                protocol_profiles=[target["protocol_profile"] for target in targets])
            if all(warm.get("status") == 200 and warm.get("http_response_complete") for warm in warmups):
                wait_started = time.perf_counter_ns()
                await asyncio.sleep(1.1)
                metadata["pre_target_budget_window_wait_ms"] = (time.perf_counter_ns() - wait_started) / 1e6
                results.extend(await asyncio.gather(*(collect_one(connection, target, args.output, node, recent, blocked)
                                                     for connection, target in pairs)))
            else:
                metadata["comparison_stopped"] = "sec_head_warmup_not_successful_no_target_requests"
                metadata["skipped_targets_after_warmup"] = [target["target_id"] for target in targets]
            targets = []
        if args.scope in ("lcid-http-protocols", "lcid-chrome-protocols"):
            if args.scope == "lcid-chrome-protocols":
                from curl_cffi.const import CurlHttpVersion, CurlOpt
                chrome_h2 = await stack.enter_async_context(browser_session())
                browser_client.curl_options[CurlOpt.HTTP_VERSION] = CurlHttpVersion.V1_1
                chrome_h2.curl_options[CurlOpt.HTTP_VERSION] = CurlHttpVersion.V2TLS
                pairs = ((browser_client, targets[0]), (chrome_h2, targets[1]))
            else:
                pairs = ((businesswire_client, targets[0]), (client, targets[1]))
            warmups = await asyncio.gather(*(collect_one(connection,
                {**target, "url": target["warmup_url"], "target_id": target["target_id"] + "_listing",
                 "method": "GET", "purpose": "connection_warmup", "cache_profile": "no_cache"},
                args.output, node, recent, blocked) for connection, target in pairs))
            for warm, (_, target) in zip(warmups, pairs):
                raw_path = warm.get("raw_document_artifact")
                raw = (args.output / raw_path).read_bytes() if raw_path else b""
                warm["listing_contains_target"] = (warm.get("status") == 200 and any(
                    found["url"].rstrip("/") == target["url"].rstrip("/") for found in
                    discover(raw, warm.get("final_url", target["warmup_url"]), warm.get("content_type", "text/html"), target["event"])))
            metadata.update(connection_warmups=warmups,
                comparison_scope=("Chrome TLS; H2 may fall back, so only actual response protocols establish the pair. " if args.scope == "lcid-chrome-protocols" else "") + "Same-node H1-only/H2-enabled clients each read the verified listing before one complete PDF GET. Target GETs start together; actual negotiated protocols are recorded. Shared parser-pool contention remains in full elapsed time. One pair is not a causal estimate or new-release SLA.",
                protocol_profiles=[target["protocol_profile"] for target in targets])
            if all(warm.get("status") == 200 and warm.get("http_response_complete") and warm.get("listing_contains_target") for warm in warmups):
                results.extend(await asyncio.gather(*(collect_one(connection, target, args.output, node, recent, blocked)
                                                     for connection, target in pairs)))
            else:
                metadata["comparison_stopped"] = "listing_warmup_not_verified_no_target_requests"
                metadata["skipped_targets_after_warmup"] = [target["target_id"] for target in targets]
            if args.scope == "lcid-chrome-protocols":
                metadata["actual_target_protocols_match_profiles"] = [row.get("http_version") for row in results] == ["HTTP/1.1", "HTTP/2"]
            targets = []
        if args.scope.startswith("msgk-cache-control"):
            warmup_target = {**targets[0], "url": "https://www.businesswire.com/", "target_id": "MSGK_businesswire_homepage_warmup",
                             "cache_profile": "ordinary", "purpose": "connection_warmup"}
            warmup_result = await collect_one(businesswire_client, warmup_target, args.output, node, recent, blocked)
            metadata["connection_warmup"] = {key: warmup_result.get(key) for key in
                ("status", "http_response_complete", "request_total_ms", "queue_ms", "transport_trace_ms", "error_type", "raw_document_artifact")}
            metadata["profile_order"] = [target["cache_profile"] for target in targets]
            metadata["comparison_scope"] = "Sequential old-document replay in profile_order; second request may benefit from the first CDN fetch. Not a causal estimate or new-release evidence."
            if warmup_result["status"] != 200 or not warmup_result["http_response_complete"]:
                metadata["comparison_stopped"] = "homepage_preconnect_not_successful"
                targets = []
        for target in targets:
            if target.get("pipeline") == "production_watch_list_seed":
                results.append(await collect_watch_case(target, args.output, node))
                continue
            host = urlsplit(target["url"]).hostname
            selected = browser_client if target.get("transport") == "curl_cffi_chrome" else businesswire_client if target.get("http1") or host == "businesswire.com" or host.endswith(".businesswire.com") else client
            if target.get("warmup_url"):
                warmup_target = {**target, "url": target["warmup_url"], "target_id": target["target_id"] + "_head_warmup",
                                 "method": "HEAD", "purpose": "connection_warmup"}
                warmup_result = await collect_one(selected, warmup_target, args.output, node, recent, blocked)
                metadata.setdefault("connection_warmups", []).append(warmup_result)
                if not warmup_result["http_response_complete"] or warmup_result["status"] in (401, 403, 429) or warmup_result["status"] >= 500:
                    metadata.setdefault("skipped_targets_after_warmup", []).append(target["target_id"])
                    continue
            results.append(await collect_one(selected, target, args.output, node, recent, blocked))
            if args.scope.startswith("msgk-cache-control") and (results[-1]["status"] != 200 or not results[-1]["http_response_complete"]):
                metadata["comparison_stopped"] = "target_request_not_successful"
                break
    metadata.update(finished_utc=utc(), attempted=len(results),
                    complete=sum(row["complete"] for row in results),
                    passed=sum(row["budget_passed"] for row in results),
                    failures=sum(bool(row.get("error_type")) for row in results))
    if args.scope in METRICS_SCOPES:
        metadata.update(passed_semantics="Legacy full-parse 300ms count; see passed_decision_500 for the current goal",
                        passed_decision_500=sum(row.get("decision_budget_passed") is True for row in results),
                        decision_endpoint="Same-process discovery through complete parse, metrics, comparison and event-loop delivery; local simulation only")
    if material_scope:
        metadata["material_downloaded"] = sum(row.get("material_download_complete") is True for row in results)
        if args.scope == "skyd-http1-material":
            metadata["actual_target_protocols_match_profiles"] = [row.get("http_version") for row in results] == ["HTTP/1.1"]
    (args.output / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    if material_scope:
        return 0 if metadata["material_downloaded"] == (1 if args.scope in ("skyd-range", "skyd-http1-material") else 2) and node.get("loc") == "US" and node.get("is_us") is True and metadata.get("actual_target_protocols_match_profiles", True) else 1
    if args.scope in METRICS_SCOPES and (
            metadata["passed_decision_500"] != len(results) or node.get("is_us") is not True):
        return 1
    return 0 if results and all(row["complete"] and row["archived"] and not row.get("error_type") for row in results) and not metadata.get("comparison_stopped") and not metadata.get("skipped_targets_after_warmup") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=BASE / "targets.json")
    parser.add_argument("--output", type=Path, default=BASE / "outputs", help="New output directory; existing evidence is never overwritten")
    parser.add_argument("--scope", choices=("all", "sec", "sec-businesswire", "remaining-paths", "msgk-cache-control", "msgk-cache-control-reverse", "bam-pdf", "alternate-routes", "msgk-issuer-cold", "msgk-browser-transport", "msgk-production-issuer", "repaired-paths", "backlog-production", "kkr-complete", "sec-quarterly", "lcid-http-protocols", "lcid-chrome-protocols", "b-sec-transports", "skyd-materials", "skyd-range", "skyd-http1-material", "skyd-complete", "bw-browser-access", "bw-browser-http1-access", *METRICS_SCOPES), default="all")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
