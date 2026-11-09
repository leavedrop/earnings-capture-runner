"""One bounded real-download replay of public earnings documents; never a release SLA."""
from __future__ import annotations

import argparse
import asyncio
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

import httpx
from pdf_tables import prewarm_pdf_pool
from sources import validate

BASE = Path(__file__).resolve().parent
HEADERS = {"User-Agent": "EarningsWatch/1.0 automated-public-filings-research",
           "Accept": "*/*", "Cache-Control": "no-cache"}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def host_key(url):
    host = urlsplit(url).hostname
    return "sec.gov" if host == "sec.gov" or host.endswith(".sec.gov") else host


async def pace(url, recent, blocked):
    host, path = host_key(url), urlsplit(url).path
    history = recent.setdefault(host, deque())
    while True:
        now = time.perf_counter()
        while history and history[0] <= now - 1:
            history.popleft()
        until = max(blocked.get((host, ""), 0), blocked.get((host, path), 0),
                    history[0] + 1 if len(history) >= 4 else 0)
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
    body, parsed = bytearray(), None
    try:
        row["queue_ms"] = 0

        async def limited_request(request):
            queued = time.perf_counter_ns()
            await pace(str(request.url), recent, blocked)
            row["queue_ms"] += (time.perf_counter_ns() - queued) / 1e6

        # HTTPX invokes this for redirects too, preserving the per-host request budget.
        client.event_hooks["request"] = [limited_request]
        request_start = time.perf_counter_ns()
        async with client.stream("GET", target["url"], headers=HEADERS) as response:
            headers_at = time.perf_counter_ns()
            row.update(status=response.status_code, final_url=str(response.url), http_version=response.http_version,
                       headers_ms=(headers_at - request_start) / 1e6,
                       content_type=response.headers.get("content-type", ""))
            if response.status_code in (403, 429):
                retry_after = response.headers.get("retry-after", "")
                seconds = 120
                try:
                    seconds = max(seconds, int(retry_after) if retry_after.isdigit() else
                                  parsedate_to_datetime(retry_after).timestamp() - time.time())
                except (ValueError, TypeError, OverflowError):
                    pass
                path = response.url.path if response.status_code == 403 else ""
                blocked[(host_key(str(response.url)), path)] = time.perf_counter() + seconds
                row.update(cooldown_seconds=seconds, cooldown_scope="path" if path else "host")
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
        body_at = time.perf_counter_ns()
        row.update(http_response_complete=True, body_complete_utc=utc(),
                   body_ms=(body_at - headers_at) / 1e6,
                   request_total_ms=(body_at - request_start) / 1e6,
                   discovery_to_body_ms=(body_at - started) / 1e6)
        raw = bytes(body)
        row.update(bytes=len(raw), sha256=digest(raw))
        if row["status"] == 200:
            parse_queued = time.perf_counter_ns()

            def parse():
                began = time.perf_counter_ns()
                result = validate(raw, row["final_url"], row["content_type"], target["event"])
                tables_sha = digest(json.dumps(result["tables"], ensure_ascii=False, separators=(",", ":")).encode())
                ended = time.perf_counter_ns()
                return result, tables_sha, began, ended, utc()

            parsed, tables_sha, parse_start, parse_end, parsed_utc = await asyncio.to_thread(parse)
            total = (parse_end - started) / 1e6
            complete = parsed.get("accepted") is True and parsed.get("tables_complete") is True
            row.update(parsed_utc=parsed_utc, parse_ms=(parse_end - parse_start) / 1e6,
                       validation_queue_ms=(parse_start - parse_queued) / 1e6,
                       discovery_to_parsed_ms=total, complete=complete,
                       budget_passed=complete and total <= 300,
                       table_count=len(parsed["tables"]), text_characters=len(parsed["text"]),
                       tables_sha256=tables_sha,
                       checks=parsed.get("checks"), quality_reason=parsed.get("quality_reason") or parsed.get("reason"),
                       pdf_pages_total=parsed.get("pdf_pages_total"), pdf_pages_processed=parsed.get("pdf_pages_processed"),
                       pdf_structure_checks=parsed.get("pdf_structure_checks"))
        else:
            row["error_type"] = "HTTP_" + str(row["status"])
    except Exception as exc:
        row["error_type"] = type(exc).__name__
    finally:
        row["ended_utc"] = utc()
        row["invocation_to_end_ms"] = (time.perf_counter_ns() - started) / 1e6
        try:
            if body:
                suffix = ".pdf" if body.startswith(b"%PDF") else ".html"
                name = target["target_id"] + suffix
                (output / "raw" / name).write_bytes(body)
                row["artifacts"].append("raw/" + name)
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
        with (output / "results.ndjson").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(json.dumps({key: row.get(key) for key in ("target_id", "symbol", "status", "discovery_to_parsed_ms", "complete", "budget_passed", "error_type")}), flush=True)
    return row


async def run(args):
    targets = json.loads(args.targets.read_text(encoding="utf-8"))
    if len(targets) != 19 or len({row["url"] for row in targets}) != 19:
        raise ValueError("Expected the approved 19 distinct public report URLs")
    source_manifest = json.loads((BASE / "parser_sources.json").read_text(encoding="utf-8"))
    for name, entry in source_manifest.items():
        if digest((BASE / name).read_bytes()) != entry["sha256"]:
            raise ValueError("Parser source hash mismatch: " + name)
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("raw", "parsed"):
        (args.output / name).mkdir()
    warmup = await asyncio.to_thread(prewarm_pdf_pool)
    recent, blocked = {}, {}
    async with httpx.AsyncClient(http2=True, trust_env=False, follow_redirects=True, max_redirects=5,
                                timeout=httpx.Timeout(12, connect=5),
                                limits=httpx.Limits(max_connections=8, max_keepalive_connections=8, keepalive_expiry=60)) as client:
        node = await identify_node(client)
        metadata = {"scope": "old_public_document_real_download_replay_not_new_release", "node": node,
                    "started_utc": utc(), "parser_sources": source_manifest,
                    "pdf_pool": warmup, "target_document_preparsed": False, "targets": len(targets)}
        (args.output / "run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        results = [await collect_one(client, target, args.output, node, recent, blocked) for target in targets]
    metadata.update(finished_utc=utc(), attempted=len(results),
                    complete=sum(row["complete"] for row in results),
                    passed=sum(row["budget_passed"] for row in results),
                    failures=sum(bool(row.get("error_type")) for row in results))
    (args.output / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return 0 if all(row["complete"] and row["archived"] for row in results) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=BASE / "targets.json")
    parser.add_argument("--output", type=Path, default=BASE / "outputs", help="New output directory; existing evidence is never overwritten")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
