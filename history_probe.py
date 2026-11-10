"""One bounded retrieval of static public historical documents; not a first-release or latency test."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

OUTPUT = Path("outputs/history")
HOSTS = {"www.sec.gov", "investors.cerebras.ai", "www.prnewswire.com", "ir.hworld.com", "ir.tyson.com"}
PUBLIC_UA = "EarningsWatch/1.0 historical-public-document-research"


def utc():
    return datetime.now(timezone.utc).isoformat()


def collect_one(client, target, output, node, identity):
    key = hashlib.sha256(target["url"].encode()).hexdigest()[:16]
    record = {**target, "target_key": key, "scope": "historical_development_document_retrieval",
              "node": node, "run_id": os.environ.get("GITHUB_RUN_ID"), "started_utc": utc(),
              "http_status": None, "status": "request_error", "http_response_complete": False,
              "raw_path": None, "bytes": 0, "sha256": None, "request_start_events": [],
              "timing_scope": "invocation_including_rate_wait_to_complete_response; not_300ms_acceptance"}
    client.history_active_record = record
    partial = output / "raw" / f"{target['symbol']}_{key}.partial"
    digest = hashlib.sha256()
    prefix = b""
    started = time.perf_counter_ns()
    try:
        with client.stream("GET", target["url"], headers={"Accept": "*/*"}) as response:
            record.update(http_status=response.status_code, final_url=str(response.url),
                          http_version=response.http_version, content_type=response.headers.get("content-type"),
                          content_encoding=response.headers.get("content-encoding"),
                          declared_content_length=response.headers.get("content-length"),
                          redirects=[{"url": str(item.url), "status": item.status_code} for item in response.history])
            with partial.open("wb") as stream:
                for chunk in response.iter_bytes():
                    stream.write(chunk)
                    digest.update(chunk)
                    record["bytes"] += len(chunk)
                    if len(prefix) < 4096:
                        prefix = (prefix + chunk)[:4096]
            record.update(http_response_complete=True, received_at_utc=utc(),
                          body_complete_mono_ns=time.perf_counter_ns(), sha256=digest.hexdigest())
            suffix = ".pdf" if prefix.startswith(b"%PDF-") else ".html"
            destination = output / "raw" / f"{target['symbol']}_{key}_{digest.hexdigest()[:12]}{suffix}"
            partial.replace(destination)
            record["raw_path"] = destination.relative_to(output).as_posix()
            record["status"] = "downloaded" if response.status_code == 200 and record["bytes"] else "http_error"
            if record["status"] == "downloaded" and any(marker in prefix.lower() for marker in (
                    b"<title>just a moment", b"<title>access denied", b"<title>sec.gov | request rate threshold")):
                record.update(status="challenge_response", error="complete_response_is_access_challenge")
    except Exception as exc:
        record.update(error_type=type(exc).__name__, error=str(exc).replace(identity, "[SEC identity]")[:400],
                      sha256=digest.hexdigest() if record["bytes"] else None,
                      raw_path=partial.relative_to(output).as_posix() if partial.exists() else None)
    record.update(ended_utc=utc(), download_total_ms=(time.perf_counter_ns()-started)/1e6)
    return record


def main():
    targets = json.loads(Path(__file__).with_name("history_targets.json").read_text(encoding="utf-8"))
    assert len(targets) == 32 and len({item["url"] for item in targets}) == 32
    for item in targets:
        assert set(item) == {"symbol", "period", "url"}
        parsed = urlsplit(item["url"])
        assert parsed.scheme == "https" and parsed.hostname in HOSTS and not parsed.username and not parsed.password
        assert re.fullmatch(r"[A-Z.]+", item["symbol"])
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "raw").mkdir(exist_ok=True)
    summary = {"scope": "historical_development_document_retrieval", "started_utc": utc(),
               "run_id": os.environ.get("GITHUB_RUN_ID"), "commit_sha": os.environ.get("GITHUB_SHA"),
               "target_count": len(targets), "sec_requests_per_second": 1, "automatic_retries": 0}
    identity = os.environ.get("SEC_USER_AGENT", "")
    if not identity or "@" not in identity:
        summary.update(status="sec_identity_missing", node=None)
        (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 2
    next_allowed = {}
    client = None

    def before_request(request):
        host = request.url.host
        key = "sec.gov" if host == "sec.gov" or host.endswith(".sec.gov") else host
        wait = next_allowed.get(key, 0)-time.monotonic()
        if wait > 0:
            time.sleep(wait)
        next_allowed[key] = time.monotonic()+1.01
        request.headers["User-Agent"] = identity if key == "sec.gov" else PUBLIC_UA
        record = getattr(client, "history_active_record", None)
        if record is not None:
            record["request_start_events"].append({"method": request.method, "url": str(request.url),
                                                    "started_utc": utc(), "started_mono_ns": time.perf_counter_ns()})

    def after_response(response):
        if response.status_code == 429:
            host = response.request.url.host
            key = "sec.gov" if host == "sec.gov" or host.endswith(".sec.gov") else host
            value = response.headers.get("retry-after", "60")
            delay = float(value) if value.isdigit() else 60
            next_allowed[key] = time.monotonic()+max(60, delay)

    results = []
    with httpx.Client(trust_env=False, http2=False, follow_redirects=True, max_redirects=5,
                      timeout=httpx.Timeout(40, connect=10),
                      event_hooks={"request": [before_request], "response": [after_response]}) as client:
        try:
            trace = client.get("https://www.cloudflare.com/cdn-cgi/trace")
            trace.raise_for_status()
            values = dict(line.split("=", 1) for line in trace.text.splitlines() if "=" in line)
            node = {"country": values.get("loc"), "colo": values.get("colo")}
            del values, trace  # No trace body or IP is archived or printed.
        except Exception as exc:
            summary.update(status="region_check_failed", error_type=type(exc).__name__, node=None)
            (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            return 2
        summary["node"] = node
        if node["country"] != "US":
            summary["status"] = "non_us_runner_no_target_requests"
            (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            return 2
        summary["status"] = "running"
        (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps({"node": node, "target_count": len(targets), "scope": summary["scope"]}), flush=True)
        with (OUTPUT / "results.ndjson").open("w", encoding="utf-8") as log:
            for target in targets:
                result = collect_one(client, target, OUTPUT, node, identity)
                results.append(result)
                log.write(json.dumps(result, ensure_ascii=False)+"\n")
                log.flush()
                print(json.dumps({key: result.get(key) for key in ("symbol", "period", "status", "http_status", "bytes", "download_total_ms")}), flush=True)
                summary.update(completed_targets=len(results), counts=dict(Counter(item["status"] for item in results)))
                (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary.update(status="completed_once", finished_utc=utc())
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
