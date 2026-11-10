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
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata
from urllib.parse import urlsplit

import httpx
from pdf_tables import prewarm_pdf_pool
from sources import discover, validate

BASE = Path(__file__).resolve().parent
HEADERS = {"User-Agent": "EarningsWatch/1.0 automated-public-filings-research",
           "Accept": "*/*", "Cache-Control": "no-cache"}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(value):
    return hashlib.sha256(value).hexdigest()


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


async def pace(url, recent, blocked):
    host, path = host_key(url), urlsplit(url).path
    limit = 8 if host == "sec.gov" else 4  # Shared SEC budget stays below its 10 requests/second ceiling.
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
    if scope == "repaired-paths":
        references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
        events = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        return [{"target_id": symbol + "_repaired_full_report", "channel": "sec" if symbol == "B" else "newswire" if symbol == "FNV" else "official",
                 "url": references[symbol + "_REPAIR"]["url"], "reference": references[symbol + "_REPAIR"],
                 "event": {**events[symbol], **references[symbol + "_REPAIR"].get("event_override", {})},
                 "cache_profile": "ordinary",
                 **({"pipeline": "production_watch_list_seed"} if symbol in ("LCID", "FNV", "B") else
                    {"transport": "curl_cffi_chrome"})} for symbol in ("LCID", "FNV", "ACHR", "HIMS", "B")]
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
    result = {**actual, "reference_text_matches": actual["text_sha256"] == reference["text_sha256"],
            "reference_tables_match": actual["table_sha256"] == reference.get("table_sha256"),
            "reference_raw_sha256": reference["raw_sha256"], "reference_url": reference["url"]}
    if "pdf_pages_total" in reference:
        result["reference_pages_match"] = parsed.get("pdf_pages_total") == parsed.get("pdf_pages_processed") == reference["pdf_pages_total"]
    if "financial_row_sha256" in reference:
        actual_rows = financial_row_hashes([table["data_rows"] for table in parsed.get("table_details", [])])
        result.update(financial_row_sha256=actual_rows, reference_tables_match=actual_rows == reference["financial_row_sha256"],
                      reference_tables_basis="all 79 financial data rows; normalized labels and exact numeric tokens; headers retained and checked by native PDF structure gates")
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
    row.update({key: target[key] for key in ("cache_profile", "purpose") if key in target})
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
            await pace(str(request.url), recent, blocked)
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
            row["response_cache_headers"] = {key: response.headers[key] for key in
                ("cache-control", "age", "x-cache", "x-cache-hits", "cf-cache-status", "date", "etag", "last-modified", "connection") if key in response.headers}
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
        if row["status"] == 200 and target.get("purpose") != "connection_warmup":
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
                suffix = ".pdf" if body.startswith(b"%PDF") else ".html"
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
        log_name = "warmup.ndjson" if target.get("purpose") == "connection_warmup" else "results.ndjson"
        with (output / log_name).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(json.dumps({key: row.get(key) for key in ("target_id", "symbol", "status", "discovery_to_parsed_ms", "complete", "budget_passed", "error_type")}), flush=True)
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
            discovery_event = target["event"]
            if actual_discovery:
                discovery_event = next(event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))
                                       if event["symbol"] == target["event"]["symbol"])
                discovery_event = {**discovery_event, "sources": [source for source in discovery_event["sources"] if source["channel"] == target["channel"]]}
                manifest = runtime / "public_probe_manifest.json"
                manifest.write_text(json.dumps([discovery_event], ensure_ascii=False), encoding="utf-8")
                command[command.index("--manifest") + 1] = str(manifest)
            else:
                command.extend(["--candidate-url", target["url"]])
                if target["reference"].get("event_override"):
                    manifest = runtime / "public_probe_manifest.json"
                    manifest.write_text(json.dumps([target["event"]], ensure_ascii=False), encoding="utf-8")
                    command[command.index("--manifest") + 1] = str(manifest)
            child_env = {key: value for key, value in os.environ.items()
                         if key not in ("GITHUB_TOKEN", "GH_TOKEN", "SEC_USER_AGENT", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")}
            if target["channel"] == "sec":
                child_env["SEC_USER_AGENT"] = os.environ.get("SEC_USER_AGENT", "")
                command.extend(["--sec-rps", "2"])
            result = await asyncio.to_thread(subprocess.run, command, cwd=BASE / "live", env=child_env,
                                             capture_output=True, timeout=180)
            row["collector_exit_code"] = result.returncode
            connection = sqlite3.connect((runtime / "observations.sqlite3").as_uri() + "?mode=ro", uri=True)
            try:
                requests = [json.loads(payload) for (payload,) in connection.execute("select payload from log where kind='request' order by id")]
                captures = [json.loads(payload) for (payload,) in connection.execute("select payload from log where kind='capture' order by id")]
            finally:
                connection.close()
            public_requests = []
            request_keys = ("id", "run_id", "symbol", "channel", "purpose", "url", "final_url", "status", "http_version",
                            "request_start_utc", "request_end_utc", "body_complete_utc", "first_body_byte_utc",
                            "queued_mono_ns", "request_start_mono_ns", "request_end_mono_ns", "body_complete_mono_ns",
                            "queue_ms", "queue_reasons", "request_total_ms", "response_headers_received_ms", "body_download_ms",
                            "first_body_callback_ms", "connection_reused", "new_tcp_connections", "sha256", "body_bytes",
                            "cooldown_seconds", "cooldown_scope", "transport", "transport_version", "curl_cumulative_ms",
                            "header_timing_semantics", "body_timing_semantics", "http_response_complete")
            for index, request in enumerate(requests):
                safe = {key: request[key] for key in request_keys if key in request}
                if request.get("error"):
                    safe["error"] = safe_error_message(request["error"])
                raw = gzip.open(runtime / request["raw_path"], "rb").read() if request.get("raw_path") else b""
                if raw:
                    suffix = ".pdf" if raw.startswith(b"%PDF") else ".html"
                    name = "raw/" + target["target_id"] + "_" + str(index) + "_" + request["purpose"] + suffix
                    (output / name).write_bytes(raw)
                    safe["artifact"] = name
                    row["artifacts"].append(name)
                if request["purpose"] == "discovery":
                    row["seed"] = safe
                    row["seed_listing_contains_candidate"] = any(item["url"].rstrip("/") == target["url"].rstrip("/")
                         for item in discover(raw, request.get("final_url", request["url"]), "text/html", discovery_event)) if raw and request.get("status") == 200 else False
                else:
                    row.update(status=request.get("status"), queue_ms=request.get("queue_ms"),
                               headers_ms=request.get("response_headers_received_ms"), request_total_ms=request.get("request_total_ms"),
                               http_version=request.get("http_version"), connection_reused=request.get("connection_reused"))
                    row.update({key: request[key] for key in ("transport", "transport_version", "curl_cumulative_ms", "header_timing_semantics", "body_timing_semantics") if key in request})
                    if target.get("document_variant"):
                        row["actual_source_url"] = request.get("final_url", target["url"])
                    body_verified = bool(raw) and len(raw) == request.get("body_bytes") and digest(raw) == request.get("sha256")
                    row["http_response_complete"] = (body_verified and request.get("body_complete_mono_ns") is not None
                        and request.get("request_end_mono_ns") == request["body_complete_mono_ns"] and not request.get("error"))
                    if body_verified:
                        canonical = "raw/" + target["target_id"] + (".pdf" if raw.startswith(b"%PDF") else ".html")
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
                parsed.update({key: saved[key] for key in ("table_spans", "table_details", "page_diagnostics") if key in saved})
                verdict = capture["validation"]
                parsed.update({key: verdict[key] for key in ("accepted", "tables_complete", "checks", "reason", "title",
                    "pdf_pages_total", "pdf_pages_processed", "pdf_pages_text_extracted", "pdf_structure_checks",
                    "tables_extraction_scope") if key in verdict})
                comparison = reference_match(parsed, target["reference"])
                complete = (row["http_response_complete"] and verdict.get("accepted") is True and verdict.get("tables_complete") is True
                            and comparison["reference_text_matches"] and comparison["reference_tables_match"]
                            and comparison.get("reference_pages_match", True))
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
                    row["seed_request_to_parsed_ms"] = (capture["validated_mono_ns"] - requests[0]["queued_mono_ns"]) / 1e6
                name = "parsed/" + target["target_id"] + ".json"
                (output / name).write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
                row["artifacts"].append(name)
                row["archived"] = True
            else:
                row["error_type"] = "HTTP_" + str(row["status"]) if row["status"] is not None else "production_capture_missing"
    except Exception as exc:
        row.update(error_type=type(exc).__name__)
    row.update(ended_utc=utc(), cli_start_to_archived_upper_ms=(time.perf_counter_ns()-started)/1e6)
    with (output / "results.ndjson").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({key: row.get(key) for key in ("target_id", "symbol", "status", "discovery_to_parsed_ms", "complete", "budget_passed", "error_type")}), flush=True)
    return row


async def run(args):
    targets = select_targets(json.loads(args.targets.read_text(encoding="utf-8")), args.scope)
    if not targets or not args.scope.startswith("msgk-cache-control") and len({row["url"] for row in targets}) != len(targets):
        raise ValueError("Expected a nonempty set of distinct public report URLs")
    source_manifest = json.loads((BASE / "parser_sources.json").read_text(encoding="utf-8"))
    for name, entry in source_manifest.items():
        if digest((BASE / name).read_bytes()) != entry["sha256"]:
            raise ValueError("Parser source hash mismatch: " + name)
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("raw", "parsed"):
        (args.output / name).mkdir()
    warmup = await asyncio.to_thread(prewarm_pdf_pool)
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
        try:
            node = await identify_node(browser_client or client)
        except Exception as exc:
            if browser_client is None:
                raise
            node = {"loc": None, "colo": None, "is_us": False, "error_type": type(exc).__name__}
        metadata = {"scope": "old_public_document_real_download_replay_not_new_release", "node": node,
                    "started_utc": utc(), "parser_sources": source_manifest,
                    "pdf_pool": warmup, "target_document_preparsed": False, "targets": len(targets),
                    "requests_per_second": {"sec.gov_shared": 8, "other_hosts": 4},
                    "transport_policy": {"businesswire.com": "HTTP/1.1 persistent client after observed HTTP/2 StreamReset error_code=2", "msgk-issuer-cold": "HTTP/1.1 cold client matching the production official collector", "default": "HTTP/2 enabled"}}
        (args.output / "run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        results = []
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
    (args.output / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return 0 if results and all(row["complete"] and row["archived"] for row in results) and not metadata.get("comparison_stopped") and not metadata.get("skipped_targets_after_warmup") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=BASE / "targets.json")
    parser.add_argument("--output", type=Path, default=BASE / "outputs", help="New output directory; existing evidence is never overwritten")
    parser.add_argument("--scope", choices=("all", "sec", "sec-businesswire", "remaining-paths", "msgk-cache-control", "msgk-cache-control-reverse", "bam-pdf", "alternate-routes", "msgk-issuer-cold", "msgk-browser-transport", "msgk-production-issuer", "repaired-paths"), default="all")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
