"""Compare explicit earnings contracts; produce local simulation receipts only.

The forecast JSON boundary is deliberately separate from extraction. Synthetic
fixtures are labelled and can later be replaced by a model's timestamped values.
No exchange credentials, network requests, or order submission are used here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import time


CONTRACT_FIELDS = (
    "company_id", "symbol", "report_period", "period_start", "period_end",
    "metric", "metric_definition", "business_scope", "currency",
)
FORECAST_ORIGINS = {"synthetic_test", "model"}
FORMULA = "100 * (actual - forecast) / abs(forecast)"


def decimal_value(value):
    """Validate numeric values at the external forecast/metric boundary."""
    if isinstance(value, bool) or value is None:
        raise ValueError("A finite decimal value is required")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("A finite decimal value is required") from exc
    if not number.is_finite():
        raise ValueError("A finite decimal value is required")
    return number


def decimal_text(value):
    return format(value, "f")


def contract_fields(record):
    return CONTRACT_FIELDS + (("share_basis",) if record.get("metric") == "eps" else ())


def missing_contract(record):
    return [name for name in contract_fields(record) if record.get(name) in (None, "", "unknown")]


def load_forecasts(path):
    """Read the future model interface, preserving every supplied basis field."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema_version") != 1 or not isinstance(data.get("forecasts"), list):
        raise ValueError("Expected forecast schema_version=1 and a forecasts array")
    identifiers = set()
    for forecast in data["forecasts"]:
        if not isinstance(forecast, dict):
            raise ValueError("Each forecast must be an object")
        identifier = forecast.get("forecast_id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("Forecast identifiers must be nonempty and unique")
        identifiers.add(identifier)
        if forecast.get("origin") not in FORECAST_ORIGINS or not forecast.get("source"):
            raise ValueError("Forecast origin and source are required")
        if forecast.get("metric") not in ("eps", "revenue") or missing_contract(forecast):
            raise ValueError("Forecast metric contract is incomplete")
        if "use_for_decision" in forecast and not isinstance(forecast["use_for_decision"], bool):
            raise ValueError("use_for_decision must be a boolean")
        decimal_value(forecast.get("normalized_value"))
        try:
            timestamp = datetime.fromisoformat(forecast["generated_at_utc"].replace("Z", "+00:00"))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise ValueError("Forecast generation time with timezone is required") from exc
        if timestamp.tzinfo is None:
            raise ValueError("Forecast generation time with timezone is required")
    return data["forecasts"]


def synthetic_forecasts(metrics, *, generated_at_utc, offset="0.10"):
    """Build visibly synthetic comparison fixtures, never purported predictions.

    Values are derived from the observed actuals solely to exercise the pipeline;
    therefore these fixtures cannot evaluate a prediction model or profitability.
    """
    offset = decimal_value(offset)
    records = []
    for metric in metrics:
        if metric.get("status") != "matched" or missing_contract(metric):
            continue
        actual = decimal_value(metric["normalized_value"])
        # Use a nonzero difference for a zero actual as well. It is test data.
        expected = actual - (abs(actual) if actual else Decimal("1")) * offset
        contract = {name: metric[name] for name in contract_fields(metric)}
        fingerprint = hashlib.sha256(json.dumps(contract, ensure_ascii=False,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
        records.append({**contract, "forecast_id": "synthetic-" + fingerprint,
            "origin": "synthetic_test", "source": "actual_derived_pipeline_fixture",
            "generated_at_utc": generated_at_utc, "normalized_value": decimal_text(expected),
            "not_a_model_prediction": True, "uses_actual_for_test_setup": True})
    # Select a visibly synthetic pair solely to exercise the agreed joint rule.
    # Real model input is never given this automatic fixture selection.
    eps = [row for row in records if row["metric"] == "eps"]
    diluted = [row for row in eps if "diluted" in row["share_basis"].lower()]
    revenue = [row for row in records if row["metric"] == "revenue"]
    selected = {row["forecast_id"] for row in (diluted or eps)[:1] + revenue[:1]}
    for row in records:
        row["use_for_decision"] = row["forecast_id"] in selected
    return {"schema_version": 1, "forecasts": records,
            "use": "pipeline testing only; not forecast accuracy or trading performance"}


def compare_metrics(metrics, forecasts):
    """Keep units/bases exact and return all individual comparisons, no strategy."""
    started = time.perf_counter_ns()
    comparisons = []
    for forecast in forecasts:
        fields = contract_fields(forecast)
        result = {"forecast_id": forecast["forecast_id"], "forecast_origin": forecast["origin"],
            "forecast_source": forecast["source"], "forecast_generated_at_utc": forecast["generated_at_utc"],
            "use_for_decision": forecast.get("use_for_decision"),
            "contract": {name: forecast.get(name) for name in fields},
            "forecast_value": forecast["normalized_value"], "actual_value": None,
            "difference": None, "surprise_pct": None, "formula": FORMULA,
            "status": "actual_missing", "source_evidence": []}
        candidates = [metric for metric in metrics if metric.get("symbol") == forecast.get("symbol")
                      and metric.get("metric") == forecast.get("metric")]
        exact = [metric for metric in candidates if all(metric.get(name) == forecast.get(name) for name in fields)]
        eligible = [metric for metric in exact if metric.get("status") == "matched" and not missing_contract(metric)]
        if not eligible:
            result["status"] = "actual_unverified" if exact else "contract_mismatch" if candidates else "actual_missing"
            result["actual_statuses"] = sorted({metric.get("status", "missing") for metric in exact})
            result["mismatched_fields"] = sorted({name for metric in candidates for name in fields
                                                  if metric.get(name) != forecast.get(name)})
            comparisons.append(result)
            continue
        actual_values = {decimal_value(metric["normalized_value"]) for metric in eligible}
        versions = {(metric.get("document_hash"), metric.get("document_version")) for metric in eligible}
        if len(actual_values) != 1 or len(versions) != 1:
            # A caller must select the actual document version, not silently prefer
            # a later revision or mix multiple announcement documents.
            result["status"] = "ambiguous_actual"
            comparisons.append(result)
            continue
        actual = actual_values.pop()
        expected = decimal_value(forecast["normalized_value"])
        result.update(actual_value=decimal_text(actual), difference=decimal_text(actual-expected),
            status="zero_forecast" if expected == 0 else "compared", source_evidence=[{
                name: metric.get(name) for name in ("source_url", "source_position", "raw_label", "raw_value",
                    "document_hash", "received_at_utc", "document_version")
            } for metric in eligible])
        if expected != 0:
            result["surprise_pct"] = decimal_text((actual-expected)/abs(expected)*Decimal("100"))
        comparisons.append(result)
    return {"comparisons": comparisons, "comparison_ms": (time.perf_counter_ns()-started)/1e6,
            "signal_status": "joint_threshold_rule", "exchange_submitted": False}


def simulate_joint_signal(comparisons):
    """EPS +/-5% AND revenue +/-3%; equality, conflict and gaps do not trade.

    This returns a local simulation decision only. A real model supplies exactly
    one contract per metric or explicitly marks its two use_for_decision rows.
    """
    started = time.perf_counter_ns()
    explicit = any(row.get("use_for_decision") is not None for row in comparisons)
    selected = [row for row in comparisons if row.get("use_for_decision") is True] if explicit else comparisons
    by_metric = {metric: [row for row in selected if row["contract"]["metric"] == metric]
                 for metric in ("eps", "revenue")}
    result = {"mode": "local_simulation", "action": "no_signal", "reason": "missing_metric_contract",
        "eligible": False, "forecast_ids": {"eps": None, "revenue": None},
        "surprise_pct": {"eps": None, "revenue": None},
        "thresholds_pct": {"eps": "5", "revenue": "3"}, "strict_thresholds": True,
        "contract_selection": "synthetic_fixture" if selected and all(row["forecast_origin"] == "synthetic_test"
            for row in selected) else "forecast_input",
        "exchange_submitted": False, "exchange_acknowledged": False, "fill_price": None,
        "created_at_utc": datetime.now(timezone.utc).isoformat()}
    if any(len(rows) > 1 for rows in by_metric.values()):
        result["reason"] = "ambiguous_metric_contract"
    elif all(len(rows) == 1 for rows in by_metric.values()):
        eps, revenue = by_metric["eps"][0], by_metric["revenue"][0]
        result["forecast_ids"] = {"eps": eps["forecast_id"], "revenue": revenue["forecast_id"]}
        same_period = all(eps["contract"][key] == revenue["contract"][key] for key in
            ("company_id", "symbol", "report_period", "period_start", "period_end", "currency", "business_scope"))
        versions = {(evidence["document_hash"], evidence["document_version"])
                    for row in (eps, revenue) for evidence in row["source_evidence"]}
        if not same_period:
            result["reason"] = "metric_contracts_do_not_align"
        elif eps["status"] != "compared" or revenue["status"] != "compared":
            result["reason"] = "metric_comparison_unavailable"
        elif len(versions) != 1:
            result["reason"] = "document_versions_do_not_align"
        else:
            e, r = decimal_value(eps["surprise_pct"]), decimal_value(revenue["surprise_pct"])
            result.update(eligible=True, surprise_pct={"eps": decimal_text(e), "revenue": decimal_text(r)},
                          reason="inside_thresholds_or_conflicting_directions")
            if e > Decimal("5") and r > Decimal("3"):
                result.update(action="long", reason="both_above_positive_thresholds")
            elif e < Decimal("-5") and r < Decimal("-3"):
                result.update(action="short", reason="both_below_negative_thresholds")
    result["simulation_ms"] = (time.perf_counter_ns()-started)/1e6
    return result
