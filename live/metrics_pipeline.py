"""Local post-capture metric extraction and explicitly labelled comparison tests."""
from __future__ import annotations

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from metric_comparison import compare_metrics, load_forecasts, simulate_joint_signal, synthetic_forecasts


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def public_synthetic_extraction(record):
    """Return the public synthetic-only contract, or None for private/model input.

    Existing times are copied, never recomputed across processes or from UTC.
    The extractor's private diagnostics, rules, paths and model source are omitted.
    """
    from metric_comparison import CONTRACT_FIELDS
    from progress import public_url

    forecasts = record.get("forecasts", [])
    comparisons = record.get("comparison", {}).get("comparisons", [])
    if (record.get("forecast_mode") != "synthetic" or not isinstance(forecasts, list)
            or any(item.get("origin") != "synthetic_test" for item in forecasts)
            or any(item.get("forecast_origin") != "synthetic_test" for item in comparisons)):
        return None
    fields = ("schema_version", "symbol", "channel", "run_id", "evidence_id", "us_run_id", "mode", "context", "forecast_mode",
              "report_period", "period_start", "period_end", "status", "document_hash", "document_version",
              "already_present_on_first_poll", "last_negative_listing_ns", "discovered_mono_ns", "validated_mono_ns",
              "discovery_to_parsed_ms", "discovery_to_comparison_ms", "discovery_to_decision_ms", "timing_basis",
              "queued_mono_ns", "extraction_started_mono_ns", "started_at_utc", "extraction_completed_mono_ns",
              "extraction_completed_at_utc", "comparison_completed_mono_ns", "comparison_completed_at_utc",
              "decision_computed_mono_ns", "decision_computed_at_utc",
              "decision_completed_mono_ns", "decision_completed_at_utc", "ended_mono_ns", "ended_at_utc",
              "decision_budget_ms", "decision_budget_passed",
              "signal_status", "exchange_submitted", "observer", "node_region", "us_execution_qualified")
    public = {key: record[key] for key in fields if key in record}
    public["source_url"] = public_url(record.get("source_url"))
    if record.get("error_stage") in ("extraction", "comparison", "decision", "configuration"):
        public["error_stage"] = record["error_stage"]
    error_type = record.get("error_type")
    if isinstance(error_type, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type):
        public["error_type"] = error_type
    public["timings_ms"] = {key: value for key, value in record.get("timings_ms", {}).items()
                            if key in ("queue", "extraction", "comparison", "decision", "delivery_queue", "pipeline")}
    public["extractor_timings_ms"] = {key: value for key, value in record.get("extractor_timings_ms", {}).items()
                                     if key in ("location", "basis_validation", "total")}
    metric_fields = CONTRACT_FIELDS + ("share_basis", "scale", "raw_label", "raw_value", "normalized_value",
                                        "document_hash", "received_at_utc", "document_version", "status")
    public["metrics"] = []
    for metric in record.get("metrics", []):
        row = {key: metric[key] for key in metric_fields if key in metric}
        row["source_url"] = public_url(metric.get("source_url"))
        position = metric.get("source_position") or {}
        row["source_position"] = {key: position[key] for key in ("table_index", "row_index", "page")
                                  if type(position.get(key)) is int}
        for key in ("column_range", "bbox", "label_bbox"):
            if isinstance(position.get(key), list) and all(type(x) in (int, float) for x in position[key]):
                row["source_position"][key] = position[key]
        currency_evidence = position.get("currency_evidence") or {}
        if currency_evidence.get("scope") in ("document", "provided_company_rule"):
            row["source_position"]["currency_evidence"] = {"scope": currency_evidence["scope"]}
            currency = currency_evidence.get("currency")
            if isinstance(currency, str) and re.fullmatch(r"[A-Z]{3}", currency):
                row["source_position"]["currency_evidence"]["currency"] = currency
        public["metrics"].append(row)
    forecast_fields = CONTRACT_FIELDS + ("share_basis", "forecast_id", "origin", "generated_at_utc", "normalized_value",
                                          "not_a_model_prediction", "uses_actual_for_test_setup", "use_for_decision")
    public["forecasts"] = [{key: item[key] for key in forecast_fields if key in item} for item in forecasts]
    comparison_fields = ("forecast_id", "forecast_origin", "forecast_generated_at_utc", "forecast_value", "actual_value",
                         "difference", "surprise_pct", "formula", "status", "use_for_decision")
    public["comparison"] = {"comparisons": []}
    for comparison in comparisons:
        row = {key: comparison[key] for key in comparison_fields if key in comparison}
        row["contract"] = {key: comparison.get("contract", {}).get(key) for key in CONTRACT_FIELDS + ("share_basis",)}
        public["comparison"]["comparisons"].append(row)
    public["diagnostics"] = [{key: value for key, value in item.items()
                               if key in ("metric", "reason", "error_type") and isinstance(value, str)
                               and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", value)}
                              for item in record.get("diagnostics", [])]
    decision = record.get("simulation_decision")
    if decision is not None:
        if decision.get("mode") != "local_simulation":
            return None
        public["simulation_decision"] = {key: decision[key] for key in (
            "mode", "action", "reason", "eligible", "strict_thresholds", "contract_selection", "exchange_submitted",
            "exchange_acknowledged", "created_at_utc", "simulation_ms") if key in decision}
        for key in ("forecast_ids", "surprise_pct", "thresholds_pct"):
            public["simulation_decision"][key] = {metric: decision.get(key, {}).get(metric) for metric in ("eps", "revenue")}
    return public


def capture_context(capture, *, offline_replay=False):
    if offline_replay or capture.get("mode") in ("probe", "replay"):
        return "replay"
    if capture.get("context"):
        return capture["context"]
    if capture.get("old_document"):
        return "backfill"
    if capture.get("already_present_on_first_poll") is True:
        return "initially_present"
    if capture.get("already_present_on_first_poll") is False and capture.get("last_negative_listing_ns") is not None:
        return "live"
    return "unknown"


class MetricsPipeline:
    def __init__(self, store, run_id, *, mode, rules_path=None, forecasts_path=None):
        if mode not in ("synthetic", "forecasts"):
            raise ValueError("Metrics mode must be synthetic or forecasts")
        if (mode == "forecasts") != (forecasts_path is not None):
            raise ValueError("Only forecasts mode accepts and requires a forecast JSON file")
        self.store, self.run_id, self.mode = store, run_id, mode
        self.forecasts_path = Path(forecasts_path) if forecasts_path is not None else None
        self.rules, self.rules_sha256 = None, None
        if rules_path is not None:
            rules_body = Path(rules_path).read_bytes()
            self.rules = json.loads(rules_body.decode("utf-8-sig"))
            if not isinstance(self.rules, dict):
                raise ValueError("Metric rules must be a JSON object")
            self.rules_sha256 = hashlib.sha256(rules_body).hexdigest()
        # Do not queue this optional work in the full-report parser's executor.
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="earnings-metrics")

    async def process_capture(self, body, source_url, event, parsed, capture, *, offline_replay=False):
        queued = time.perf_counter_ns()
        result = await asyncio.get_running_loop().run_in_executor(self.executor, partial(
            self._process, body, source_url, event, parsed, capture, queued, offline_replay))
        delivered = time.perf_counter_ns()
        delivered_utc = utc()
        result["timings_ms"]["delivery_queue"] = (delivered-result["ended_mono_ns"])/1e6
        result.update(ended_mono_ns=delivered, ended_at_utc=delivered_utc)
        result["timings_ms"]["pipeline"] = (delivered-queued)/1e6
        if result.get("decision_computed_mono_ns") is not None:
            result.update(decision_completed_mono_ns=delivered, decision_completed_at_utc=delivered_utc)
            if result["discovered_mono_ns"] is not None:
                result["discovery_to_decision_ms"] = (delivered-result["discovered_mono_ns"])/1e6
                if (result["simulation_decision"]["eligible"]
                        and capture.get("validation", {}).get("accepted") is True):
                    result["decision_budget_passed"] = result["discovery_to_decision_ms"] <= 500
        # Store's SQLite connection remains on the collector's event-loop thread.
        # This audit write is after delivery; it is not an exchange acknowledgement.
        self.store.add("metric_extraction", result)
        return result

    def _process(self, body, source_url, event, parsed, capture, queued, offline_replay):
        started = time.perf_counter_ns()
        continuous = (not offline_replay and capture.get("run_id") == self.run_id
                      and capture.get("discovered_mono_ns") is not None)
        context = capture_context(capture, offline_replay=offline_replay)
        version = capture.get("document_version") or ("unknown_historical_version" if context == "replay" else "unknown_version")
        original = {name: capture.get(name) for name in (
            "id", "run_id", "mode", "context", "sha256", "document_version", "original_document_path",
            "discovered_utc", "discovered_mono_ns", "body_complete_utc", "body_complete_mono_ns",
            "validated_utc", "validated_mono_ns", "discovery_to_parsed_ms",
            "already_present_on_first_poll", "last_negative_listing_ns", "last_negative_listing_mono_ns",
            "old_document", "retry", "candidate_attempt")}
        result = {
            "schema_version": 1, "symbol": event["symbol"], "channel": capture.get("channel"),
            "run_id": self.run_id, "mode": "replay" if context == "replay" else capture.get("mode", "run"),
            "context": context, "source_url": source_url, "forecast_mode": self.mode,
            "report_period": f"FY{event['fiscal_year']} Q{event['quarter']}",
            "period_start": event.get("period_start"), "period_end": event.get("period_end"),
            "status": "error", "original_capture": original, "local_only": True,
            "document_hash": capture.get("sha256"), "document_version": version, "rules_sha256": self.rules_sha256,
            "already_present_on_first_poll": capture.get("already_present_on_first_poll"),
            "last_negative_listing_ns": capture.get("last_negative_listing_ns") if not offline_replay else None,
            "discovered_mono_ns": capture.get("discovered_mono_ns") if continuous else None,
            "validated_mono_ns": capture.get("validated_mono_ns") if continuous else None,
            "discovery_to_parsed_ms": capture.get("discovery_to_parsed_ms") if continuous else None,
            "timing_basis": "same_process_perf_counter" if continuous else "offline_or_unavailable_discovery_clock",
            "queued_mono_ns": queued, "extraction_started_mono_ns": started, "started_at_utc": utc(),
            "metrics": [], "diagnostics": [], "forecasts": [], "extractor_timings_ms": {},
            "comparison": {"comparisons": [], "signal_status": "joint_threshold_rule", "exchange_submitted": False},
            "signal_status": "joint_threshold_rule", "exchange_submitted": False,
            "simulation_decision": None, "decision_budget_ms": 500, "decision_budget_passed": None,
            "discovery_to_decision_ms": None,
            "timings_ms": {"queue": (started-queued)/1e6},
        }
        stage = "extraction"
        try:
            digest = hashlib.sha256(body).hexdigest()
            if capture.get("sha256") and capture["sha256"] != digest:
                raise ValueError("capture_original_sha256_mismatch")
            result["document_hash"] = digest
            received = capture.get("body_complete_utc") or capture.get("received_at_utc")
            if received is None:
                raise ValueError("original_receipt_time_required")
            from earnings_metrics import extract_metrics
            extracted = extract_metrics(body, source_url, event, received_at_utc=received,
                document_version=version,
                parsed=parsed, rules=self.rules)
            extracted_at = time.perf_counter_ns()
            result.update(metrics=extracted["metrics"], diagnostics=extracted["diagnostics"],
                          extractor_timings_ms=extracted["timings_ms"],
                          extraction_completed_mono_ns=extracted_at, extraction_completed_at_utc=utc())
            result["timings_ms"]["extraction"] = (extracted_at-started)/1e6
            stage = "comparison"
            if self.mode == "synthetic":
                forecasts = synthetic_forecasts(result["metrics"], generated_at_utc=utc())["forecasts"]
            else:
                # Re-read the explicit model input for this document; never use
                # a web consensus, the rules' examples, or a synthetic fallback.
                forecasts = [item for item in load_forecasts(self.forecasts_path) if item["symbol"] == event["symbol"]]
            result["forecasts"] = [dict(item, not_a_model_prediction=True) if item["origin"] == "synthetic_test"
                                   else item for item in forecasts]
            result["comparison"] = compare_metrics(result["metrics"], result["forecasts"])
            compared_at = time.perf_counter_ns()
            result.update(comparison_completed_mono_ns=compared_at,
                          comparison_completed_at_utc=utc())
            result["timings_ms"]["comparison"] = (compared_at-extracted_at)/1e6
            result["discovery_to_comparison_ms"] = ((compared_at-capture["discovered_mono_ns"])/1e6
                                                      if continuous else None)
            stage = "decision"
            result["simulation_decision"] = simulate_joint_signal(result["comparison"]["comparisons"])
            decided_at = time.perf_counter_ns()
            result.update(status="completed", decision_computed_mono_ns=decided_at,
                          decision_computed_at_utc=utc())
            result["timings_ms"]["decision"] = (decided_at-compared_at)/1e6
        except Exception as exc:
            result.update(error_stage=stage, error_type=type(exc).__name__, error_reason=str(exc),
                          discovery_to_comparison_ms=None)
            result["diagnostics"].append({"reason": stage + "_error", "error_type": type(exc).__name__})
        finished = time.perf_counter_ns()
        result.update(ended_mono_ns=finished, ended_at_utc=utc())
        result["timings_ms"]["pipeline"] = (finished-queued)/1e6
        return result

    def close(self):
        self.executor.shutdown(wait=True)


def main():
    parser = argparse.ArgumentParser(description="Replay archived documents locally; no network or exchange orders")
    parser.add_argument("command", choices=["replay"])
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--parsed", required=True, type=Path)
    parser.add_argument("--capture-json", type=Path, help="Original capture metadata when separate from parsed JSON")
    parser.add_argument("--source-url")
    parser.add_argument("--received-at-utc", help="Actual original receipt time, only when absent in metadata")
    parser.add_argument("--symbol", required=True)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("watchlist.json"))
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "runtime" / "metrics_replay")
    parser.add_argument("--rules", type=Path)
    forecasts = parser.add_mutually_exclusive_group(required=True)
    forecasts.add_argument("--synthetic", action="store_true")
    forecasts.add_argument("--forecasts", type=Path)
    args = parser.parse_args()
    event = next(row for row in json.loads(args.manifest.read_text(encoding="utf-8-sig")) if row["symbol"] == args.symbol)
    parsed = json.loads(args.parsed.read_text(encoding="utf-8-sig"))
    saved = json.loads((args.capture_json or args.parsed).read_text(encoding="utf-8-sig"))
    capture = dict(saved.get("metadata", {}))
    if args.received_at_utc:
        capture["body_complete_utc"] = args.received_at_utc
    source_url = args.source_url or capture.get("target_document_url") or capture.get("final_url") or capture["url"]
    from watch import Store
    store = Store(args.output)
    pipeline = MetricsPipeline(store, "metrics-replay-" + str(uuid.uuid4()),
        mode="synthetic" if args.synthetic else "forecasts", rules_path=args.rules, forecasts_path=args.forecasts)
    try:
        result = asyncio.run(pipeline.process_capture(args.body.read_bytes(), source_url, event, parsed, capture,
                                                     offline_replay=True))
        print(json.dumps({name: result[name] for name in ("run_id", "status", "context", "document_hash",
            "forecast_mode", "signal_status", "exchange_submitted", "discovery_to_comparison_ms",
            "discovery_to_decision_ms", "decision_budget_passed", "simulation_decision", "timings_ms")}, ensure_ascii=False))
        if result["status"] == "error":
            raise SystemExit(1)
    finally:
        pipeline.close()
        store.db.close()


if __name__ == "__main__":
    main()
