"""Bounded public market-data connectivity diagnostic; never authenticates or trades."""

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
from statistics import median
import time
import uuid

import httpx
from websockets.asyncio.client import connect


TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
REST_URL = "https://fapi.binance.com/fapi/v1/exchangeInfo"
WS_URL = "wss://ws-fapi.binance.com/ws-fapi/v1"
SYMBOLS = ("CSCOUSDT", "NBISUSDT", "CBRSUSDT")
SAMPLES_PER_SYMBOL = 3
REQUEST_INTERVAL_NS = 300_000_000  # At most four starts in any one-second window.
SCOPE = {
    "market_data_only": True,
    "exchange_orders_sent": 0,
    "no_private_auth": True,
    "trading_permission_verified": False,
    "earnings_to_order_500ms_acceptance_applicable": False,
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def error_text(exc):
    # Do not expose an address embedded in a transport exception.
    return re.sub(r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}[.]){3}[0-9]{1,3}(?![A-Za-z0-9.])",
                  "[redacted_ip]", str(exc))[:1000]


async def public_get(client, url, output, requests, *, trace=False):
    row = {"kind": "node_trace" if trace else "exchange_info", "method": "GET",
           "url": url, "started_utc": utc_now(), "started_mono_ns": time.perf_counter_ns()}
    try:
        response = await client.get(url)
        row.update(status=response.status_code, response_complete=True,
                   received_utc=utc_now(), received_mono_ns=time.perf_counter_ns())
        if trace:
            fields = dict(line.split("=", 1) for line in response.text.splitlines() if "=" in line)
            # The trace body contains the runner IP. Only these two fields survive.
            row["node"] = {key: fields.get(key) for key in ("loc", "colo")}
            row["node"]["is_us"] = response.status_code == 200 and fields.get("loc") == "US"
        else:
            raw_path = output / "binance_exchangeInfo.response"
            raw_path.write_bytes(response.content)
            row.update(raw_artifact=raw_path.name, bytes=len(response.content),
                       sha256=hashlib.sha256(response.content).hexdigest())
            try:
                data = response.json()
                row["public_error"] = {key: data[key] for key in ("code", "msg") if key in data}
                if response.status_code == 200 and isinstance(data.get("symbols"), list):
                    row["requested_contracts"] = [
                        {key: item.get(key) for key in ("symbol", "status", "contractType", "underlyingType")}
                        for item in data["symbols"] if item.get("symbol") in SYMBOLS
                    ]
            except (ValueError, TypeError, AttributeError):
                pass  # The original non-JSON rejection is still retained byte-for-byte.
    except Exception as exc:
        row.update(status=None, response_complete=False, error_type=type(exc).__name__, error=error_text(exc))
    row.update(ended_utc=utc_now(), ended_mono_ns=time.perf_counter_ns())
    row["total_ms"] = (row["ended_mono_ns"] - row["started_mono_ns"]) / 1e6
    requests.append(row)
    save(output / "requests.json", requests)
    return row


def quote_checks(response, request_id, symbol):
    result = response.get("result") if isinstance(response, dict) else None
    price = result.get("price") if isinstance(result, dict) else None
    try:
        valid_price = isinstance(price, str) and Decimal(price).is_finite() and Decimal(price) > 0
    except InvalidOperation:
        valid_price = False
    return {
        "id_matches": isinstance(response, dict) and response.get("id") == request_id,
        "status_200": isinstance(response, dict) and response.get("status") == 200,
        "symbol_matches": isinstance(result, dict) and result.get("symbol") == symbol,
        "price_positive_finite": valid_price,
    }


async def collect_quotes(output, requests, results):
    schedule = [(sample, symbol) for sample in range(1, SAMPLES_PER_SYMBOL + 1) for symbol in SYMBOLS]
    handshake = {"kind": "ws_cold_handshake", "url": WS_URL, "proxy": None,
                 "started_utc": utc_now(), "started_mono_ns": time.perf_counter_ns()}
    stop_reason = "handshake_failed"
    try:
        async with connect(WS_URL, proxy=None, open_timeout=20, close_timeout=3, ping_interval=None) as ws:
            handshake.update(status=ws.response.status_code, accepted=True,
                             ended_utc=utc_now(), ended_mono_ns=time.perf_counter_ns())
            handshake["total_ms"] = (handshake["ended_mono_ns"] - handshake["started_mono_ns"]) / 1e6
            requests.append(handshake)
            save(output / "requests.json", requests)
            next_start = 0
            for sample, symbol in schedule:
                row = {"kind": "ws_public_quote", "symbol": symbol, "sample": sample,
                       "attempted": True, "queued_utc": utc_now(), "queued_mono_ns": time.perf_counter_ns()}
                wait_ns = max(0, next_start - time.perf_counter_ns())
                if wait_ns:
                    await asyncio.sleep(wait_ns / 1e9)
                request_id = str(uuid.uuid4())
                payload = {"id": request_id, "method": "ticker.price", "params": {"symbol": symbol}}
                row.update(request=payload, started_utc=utc_now(), started_mono_ns=time.perf_counter_ns())
                row["pacing_wait_ms"] = (row["started_mono_ns"] - row["queued_mono_ns"]) / 1e6
                next_start = row["started_mono_ns"] + REQUEST_INTERVAL_NS
                stop_reason = None
                try:
                    await ws.send(json.dumps(payload, separators=(",", ":")))
                    raw = await asyncio.wait_for(ws.recv(), timeout=10)
                    row.update(received_utc=utc_now(), received_mono_ns=time.perf_counter_ns())
                    row["request_response_ms"] = (row["received_mono_ns"] - row["started_mono_ns"]) / 1e6
                    row["raw_response"] = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                    row["response_bytes"] = len(row["raw_response"].encode("utf-8"))
                    data = json.loads(row["raw_response"])
                    row.update(response=data, checks=quote_checks(data, request_id, symbol))
                    row["public_quote_verified"] = all(row["checks"].values())
                    if not row["public_quote_verified"]:
                        row["failure_type"] = "response_contract_mismatch"
                    if isinstance(data, dict) and data.get("status") in (403, 418, 429, 451):
                        stop_reason = "server_denial_or_rate_limit_no_retry"
                except Exception as exc:
                    row.update(public_quote_verified=False, failure_type=type(exc).__name__, error=error_text(exc))
                    stop_reason = "connection_or_response_failure_no_retry"
                row.update(ended_utc=utc_now(), ended_mono_ns=time.perf_counter_ns())
                row["request_to_validation_ms"] = (row["ended_mono_ns"] - row["started_mono_ns"]) / 1e6
                results.append(row)
                requests.append(row)
                save(output / "results.json", results)
                save(output / "requests.json", requests)
                if stop_reason:
                    break
    except Exception as exc:
        if not handshake.get("accepted"):
            response = getattr(exc, "response", None)
            handshake.update(status=getattr(response, "status_code", None), accepted=False,
                             error_type=type(exc).__name__, error=error_text(exc),
                             ended_utc=utc_now(), ended_mono_ns=time.perf_counter_ns())
            handshake["total_ms"] = (handshake["ended_mono_ns"] - handshake["started_mono_ns"]) / 1e6
            requests.append(handshake)
        else:
            requests.append({"kind": "ws_close_error", "error_type": type(exc).__name__, "error": error_text(exc)})
    for sample, symbol in schedule[len(results):]:
        results.append({"kind": "ws_public_quote", "symbol": symbol, "sample": sample,
                        "attempted": False, "public_quote_verified": False,
                        "failure_type": stop_reason, "started_mono_ns": None,
                        "request_response_ms": None, "request_to_validation_ms": None})
    save(output / "requests.json", requests)
    save(output / "results.json", results)
    return handshake


def summarize(run_record, requests, results):
    companies = {}
    for symbol in SYMBOLS:
        rows = [row for row in results if row["symbol"] == symbol]
        valid = [row for row in rows if row["public_quote_verified"]]
        times = [row["request_response_ms"] for row in valid]
        companies[symbol] = {
            "attempted": sum(row["attempted"] for row in rows), "verified": len(valid),
            "failed": sum(row["attempted"] and not row["public_quote_verified"] for row in rows),
            "not_attempted": sum(not row["attempted"] for row in rows),
            "verified_response_median_ms": median(times) if times else None,
            "verified_response_max_ms": max(times) if times else None,
        }
    return {**SCOPE, "state": run_record["state"], "node": run_record.get("node"),
            "cold_handshake_ms": next((r["total_ms"] for r in requests if r["kind"] == "ws_cold_handshake"), None),
            "handshake_excluded_from_warm_request_times": True, "results": companies,
            "failures": dict(Counter(row["failure_type"] for row in results if row.get("failure_type"))),
            "latency_scope": "public quote only; not order acknowledgement or earnings signal pipeline",
            "statistics_scope": "median/max of verified responses, at most 3 per symbol; no p99 claim",
            "rest_status": next((r.get("status") for r in requests if r["kind"] == "exchange_info"), None)}


async def run(output):
    output.mkdir(parents=True, exist_ok=True)
    requests, results = [], []
    record = {**SCOPE, "state": "running", "run_id": os.environ.get("GITHUB_RUN_ID"),
              "source_commit": os.environ.get("GITHUB_SHA"), "started_utc": utc_now(),
              "started_mono_ns": time.perf_counter_ns(), "transport": "direct_proxy_none_trust_env_false",
              "symbols": list(SYMBOLS), "samples_per_symbol": SAMPLES_PER_SYMBOL,
              "official_ws_documentation": "https://developers.binance.com/en/docs/catalog/core-trading-derivatives-trading-usd-s-m-futures/api/ws-api/market-data"}
    save(output / "run.json", record)
    save(output / "requests.json", requests)
    save(output / "results.json", results)
    try:
        async with httpx.AsyncClient(proxy=None, trust_env=False, timeout=20, follow_redirects=False) as client:
            trace = await public_get(client, TRACE_URL, output, requests, trace=True)
            record["node"] = trace.get("node", {"loc": None, "colo": None, "is_us": False})
            save(output / "run.json", record)
            if not record["node"]["is_us"]:
                record["state"] = "stopped_us_region_not_verified"
            else:
                await public_get(client, REST_URL, output, requests)
                await collect_quotes(output, requests, results)
                record["state"] = "completed_with_results" if all(r["public_quote_verified"] for r in results) else "completed_with_failures"
    finally:
        record.update(ended_utc=utc_now(), ended_mono_ns=time.perf_counter_ns())
        record["total_ms"] = (record["ended_mono_ns"] - record["started_mono_ns"]) / 1e6
        save(output / "run.json", record)
        summary = summarize(record, requests, results)
        save(output / "summary.json", summary)
        print(json.dumps(summary, ensure_ascii=False))
    return 0 if record["state"] == "completed_with_results" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("outputs/exchange"))
    raise SystemExit(asyncio.run(run(parser.parse_args().output)))
