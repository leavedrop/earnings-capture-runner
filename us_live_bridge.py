"""Import the US collector's public evidence and keep its bounded workflow running."""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

import httpx

import progress
from publish_progress import ROW_FIELDS, PATROL_FIELDS

BASE = Path(__file__).resolve().parent
REPOSITORY = "leavedrop/earnings-capture-runner"
PUBLIC_BASE = f"https://api.github.com/repos/{REPOSITORY}/contents/"
EVIDENCE_API = f"https://api.github.com/repos/{REPOSITORY}/commits/evidence"
WORKFLOW_API = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/live.yml"
DISPATCH_UNTIL = max(datetime.fromisoformat(row["window_end"]) for row in
                     json.loads((BASE / "watchlist.json" if (BASE / "watchlist.json").exists()
                                 else BASE / "live/watchlist.json").read_text(encoding="utf-8"))) + timedelta(minutes=4)
SYNC_UNTIL = (DISPATCH_UNTIL + timedelta(minutes=7)).isoformat()
KEEPALIVE_STATE_API = PUBLIC_BASE + "controls/cloud-keepalive.json"
REPORT = re.compile(r"reports/[A-Za-z0-9._-]+_(?:official|sec|newswire)_[a-fA-F0-9]{12}\.(html|pdf|xlsx|txt|json)")


def utc():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def database(runtime):
    connection = sqlite3.connect(runtime / "us_live_observations.sqlite3")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE IF NOT EXISTS captures (evidence_id TEXT PRIMARY KEY,run_id TEXT,payload TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY,payload TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY,kind TEXT,symbol TEXT,channel TEXT,at_ns INTEGER,payload TEXT)")
    return connection


def log_error(connection, stage, exc, evidence_id=None):
    status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
    payload = {"stage": stage, "error_type": type(exc).__name__, "status": status, "evidence_id": evidence_id}
    connection.execute("INSERT INTO log(kind,at_ns,payload) VALUES ('sync_failure',?,?)", (time.time_ns(), json.dumps(payload)))
    connection.commit()
    return payload


async def download_report(client, runtime, artifact, prefix, commit):
    name = artifact["path"]
    match = REPORT.fullmatch(name)
    if (not match or artifact.get("kind") != match[1]
            or not re.fullmatch(r"[a-fA-F0-9]{64}", str(artifact.get("sha256", "")))
            or type(artifact.get("bytes")) is not int or artifact["bytes"] < 0):
        raise ValueError("invalid_public_report_contract")
    target = runtime / "reports" / (prefix + Path(name).name)
    body = target.read_bytes() if target.is_file() else None
    if body is None or hashlib.sha256(body).hexdigest() != artifact["sha256"].lower():
        response = await client.get(PUBLIC_BASE + name, params={"ref": commit}, headers={"Accept": "application/vnd.github.raw+json"})
        response.raise_for_status()
        body = response.content
    if len(body) != artifact["bytes"] or hashlib.sha256(body).hexdigest() != artifact["sha256"].lower():
        raise ValueError("public_report_digest_or_length_mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(body)
    os.replace(temporary, target)
    labels = {"html": "原文 HTML", "pdf": "原文 PDF", "xlsx": "原文 XLSX", "txt": "全文文本", "json": "文本与表格 JSON"}
    return {"path": target.relative_to(runtime).as_posix(), "label": labels[match[1]], "local_only": True}


async def import_snapshot(snapshot, runtime, connection, client, commit):
    if snapshot.get("schema_version") != 1 or not re.fullmatch(r"[A-Za-z0-9_-]+", str(snapshot.get("run_id", ""))):
        raise ValueError("invalid_evidence_snapshot")
    run_id = snapshot["run_id"]
    node = snapshot.get("node") or {}
    region = progress.cloud_region({"country": node.get("loc"), "colo": node.get("colo")})
    qualified = node.get("loc") == "US"
    added = failed = 0
    for capture in snapshot.get("captures", []):
        evidence_id = capture.get("evidence_id")
        try:
            if not isinstance(evidence_id, str) or not evidence_id.startswith(run_id + ":"):
                raise ValueError("capture_run_identity_mismatch")
            existing = connection.execute("SELECT payload FROM captures WHERE evidence_id=?", (evidence_id,)).fetchone()
            if existing:
                # Restore stage timings omitted by an older projection. The
                # original discovery time and elapsed total are never replaced.
                saved = json.loads(existing[0])
                stages = {key: capture[key] for key in ("queue_ms", "parse_ms", "validation_queue_ms")
                          if saved.get(key) is None and isinstance(capture.get(key), (int, float))}
                if stages:
                    saved.update(stages)
                    connection.execute("UPDATE captures SET payload=? WHERE evidence_id=?",
                                       (json.dumps(saved, ensure_ascii=False), evidence_id))
                    connection.commit()
                continue
            artifacts = capture.get("artifacts", [])
            kinds = {item.get("kind") for item in artifacts}
            if not {"txt", "json"}.issubset(kinds) or not kinds.intersection({"html", "pdf", "xlsx"}):
                raise ValueError("capture_public_files_incomplete")
            prefix = "us_" + hashlib.sha256(evidence_id.encode()).hexdigest()[:12] + "_"
            local = await asyncio.gather(*(download_report(client, runtime, item, prefix, commit) for item in artifacts))
            text_path = next(runtime / item["path"] for item in local if item["path"].endswith(".txt"))
            parsed = json.loads(text_path.with_suffix(".json").read_text(encoding="utf-8"))
            if (parsed.get("text") != text_path.read_text(encoding="utf-8")
                    or not isinstance(parsed.get("tables"), list) or len(parsed["tables"]) != capture.get("table_count")):
                raise ValueError("capture_text_or_tables_mismatch")
            if "table_spans" in parsed:
                from sources import check_table_spans
                check_table_spans(parsed["tables"], parsed["table_spans"])
            if "xlsx" in kinds:
                from sources import SKYD_XLSX_URL, check_xlsx_archive
                if capture.get("symbol") != "SKYD" or capture.get("url") != SKYD_XLSX_URL:
                    raise ValueError("unverified_spreadsheet_source")
                original = next(runtime / item["path"] for item in local if item["path"].endswith(".xlsx"))
                check_xlsx_archive(original.read_bytes(), parsed)
            row = {key: capture[key] for key in ROW_FIELDS if key in capture}
            for key in progress.OBSERVATION_FIELDS:
                row.setdefault(key, None)
            row["url"] = progress.public_url(row.get("url"))
            if row.get("context") not in progress.CONTEXTS or (row.get("context") == "live" and not progress.has_negative_observation(row)):
                row.update(context="unknown", context_label=progress.CONTEXTS["unknown"],
                           context_explanation="缺少此前未见公告的原始观察时间，不能认作首发记录。")
            row.update(evidence_id=evidence_id, run_id=run_id, artifacts=local, observer="美国采集器",
                       node_region=region, us_execution_qualified=qualified, bridge_received_at_beijing=progress.beijing(utc()),
                       archive_readback_verified=True)
            row["latency_budget_passed"] = bool(qualified and row.get("latency_budget_passed") is True
                and row.get("accepted") is True and row.get("tables_complete") is True and not row.get("retry"))
            connection.execute("INSERT INTO captures VALUES (?,?,?)", (evidence_id, run_id, json.dumps(row, ensure_ascii=False)))
            connection.commit()
            added += 1
        except Exception as exc:
            log_error(connection, "capture_import", exc, evidence_id)
            failed += 1
    for attachment in snapshot.get("attachments", []):
        evidence_id = attachment.get("evidence_id")
        try:
            if (not isinstance(evidence_id, str) or not evidence_id.startswith(run_id + ":")
                    or not progress.recognized_achr_attachment(attachment)):
                raise ValueError("unverified_supporting_letter_contract")
            if connection.execute("SELECT 1 FROM log WHERE kind='attachment' AND json_extract(payload,'$.evidence_id')=?", (evidence_id,)).fetchone():
                continue
            artifacts = attachment.get("artifacts", [])
            if len(artifacts) != 3 or {item.get("kind") for item in artifacts} != {"pdf", "txt", "json"}:
                raise ValueError("supporting_letter_public_files_incomplete")
            if any(not progress.ACHR_SUPPORT_FILE.fullmatch(item["path"]) for item in artifacts):
                raise ValueError("unverified_supporting_letter_path")
            pdf = next(item for item in artifacts if item["kind"] == "pdf")
            if pdf["sha256"] != attachment["sha256"] or pdf["bytes"] != attachment["bytes"]:
                raise ValueError("supporting_letter_original_mismatch")
            prefix = "us_" + hashlib.sha256(evidence_id.encode()).hexdigest()[:12] + "_"
            local = await asyncio.gather(*(download_report(client, runtime, item, prefix, commit) for item in artifacts))
            text_path = next(runtime / item["path"] for item in local if item["path"].endswith(".txt"))
            parsed = json.loads(text_path.with_suffix(".json").read_text(encoding="utf-8"))
            if (not parsed["text"] or parsed["text"] != text_path.read_text(encoding="utf-8")
                    or parsed["tables"] != [] or parsed["table_spans"] != []
                    or parsed["supporting_document"] != attachment["supporting_document"]
                    or parsed["pdf_pages_total"] != 16 or parsed["pdf_pages_processed"] != 16
                    or parsed["pdf_pages_text_extracted"] != 16 or len(parsed["page_diagnostics"]) != 16
                    or parsed["pdf_metadata"]["title"] != attachment["supporting_title"]):
                raise ValueError("supporting_letter_native_content_mismatch")
            original = next(item["path"] for item in local if item["path"].endswith(".pdf"))
            row = progress.attachment_row({**attachment, "original_document_path": original}, runtime)
            row.update(evidence_id=evidence_id, run_id=run_id, observer="美国采集器", node_region=region,
                       original_document_path=original, archive_readback_verified=True, latency_budget_passed=None)
            connection.execute("INSERT INTO log(kind,symbol,channel,at_ns,payload) VALUES('attachment','ACHR','official',?,?)",
                               (time.time_ns(), json.dumps(row, ensure_ascii=False)))
            connection.commit()
        except Exception as exc:
            log_error(connection, "attachment_import", exc, evidence_id)
            failed += 1
    from metrics_pipeline import public_synthetic_extraction
    for extraction in snapshot.get("metric_extractions", []):
        evidence_id = extraction.get("evidence_id")
        try:
            if not isinstance(evidence_id, str) or not evidence_id.startswith(run_id + ":"):
                raise ValueError("metric_run_identity_mismatch")
            row = public_synthetic_extraction(extraction)
            if row is None:
                continue
            if connection.execute("SELECT 1 FROM log WHERE kind='metric_extraction' AND json_extract(payload,'$.evidence_id')=?",
                                  (evidence_id,)).fetchone():
                continue
            row.update(us_run_id=run_id, observer="美国采集器", node_region=region, us_execution_qualified=qualified)
            connection.execute("INSERT INTO log(kind,symbol,channel,at_ns,payload) VALUES('metric_extraction',?,?,?,?)",
                               (row.get("symbol"), row.get("channel"), time.time_ns(), json.dumps(row, ensure_ascii=False)))
            connection.commit()
        except Exception as exc:
            log_error(connection, "metric_import", exc, evidence_id)
            failed += 1
    metadata = {key: snapshot.get(key) for key in ("schema_version", "run_id", "started_utc", "until_utc", "updated_utc", "state", "collector_heartbeat_utc",
        "hard_stop_utc", "handoff_slot", "sec_rps", "evidence_branch", "symbols", "handoff_control_version",
        "metrics_mode", "metrics_pipeline_mode", "metrics_rules_sha256",
        "collector_last_alive_utc", "collector_stopped_observed_utc")}
    metadata.update(node_region=region, us_execution_qualified=qualified,
                    handoff_sources=[{key: row.get(key) for key in ("symbol", "channel", "url", "window_start", "window_end",
                        "completed", "required", "state", "status", "request_start_utc", "request_end_utc",
                        "first_request_start_utc", "first_request_end_utc", "valid_discovery", "validity_basis")}
                        for row in snapshot.get("handoff_sources", [])],
                    source_patrols=[{key: row[key] for key in PATROL_FIELDS if key in row} for row in snapshot.get("source_patrols", [])],
                    request_failures={key: snapshot.get("request_failures", {}).get(key, 0) for key in ("requests", "failed_requests")},
                    failure_groups=[{key: row.get(key) for key in ("symbol", "channel", "failure_type", "count", "lastseen")} for row in snapshot.get("failure_groups", [])])
    for patrol in metadata["source_patrols"]:
        patrol["url"] = progress.public_url(patrol.get("url"))
        patrol["observer"] = "美国采集器"
    connection.execute("INSERT INTO runs VALUES (?,?) ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload", (run_id, json.dumps(metadata, ensure_ascii=False)))
    connection.commit()
    return metadata, added, failed


def github_token():
    result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("github_identity_unavailable")
    return result.stdout.strip()


async def evidence_commit(client=None, token_loader=github_token, branch="evidence"):
    owned = client is None
    if owned:
        client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30)
    try:
        token = await asyncio.to_thread(token_loader)
        response = await client.get(EVIDENCE_API.rsplit("/", 1)[0] + "/" + branch, headers={"Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json", "Cache-Control": "no-cache"})
        if response.status_code == 404 or (response.status_code == 422 and response.json().get("message") == "No commit found for SHA: " + branch):
            return None
        response.raise_for_status()
        commit = response.json()["sha"]
        if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise ValueError("invalid_evidence_commit")
        return commit
    finally:
        if owned:
            await client.aclose()


def run_alive(snapshot, now):
    heartbeat = progress.date_value(snapshot.get("collector_heartbeat_utc"))
    return bool(snapshot.get("state") == "running" and snapshot.get("us_execution_qualified")
                and heartbeat and 0 <= (now-heartbeat).total_seconds() <= 300
                and snapshot.get("request_failures", {}).get("requests", 0) > 0)


def handoff_ready(successor, previous, now):
    rows = successor.get("handoff_sources", [])
    required = {(row["symbol"], row["channel"], row.get("url")): row for row in rows
                if progress.date_value(row.get("window_start")) and progress.date_value(row["window_start"]) <= now
                and (now <= DISPATCH_UNTIL if row["channel"] == "sec" else
                     not row.get("completed") and now <= progress.date_value(row["window_end"]))}
    missing = [":".join(part for part in key if part) for key, row in required.items() if not row.get("request_end_utc")]
    companies = {row["symbol"] for row in required.values()}
    valid = {row["symbol"] for row in rows if (row.get("valid_discovery") is True or row.get("completed") is True)
             and row.get("status") in (200, 304) and row.get("request_end_utc")}
    old_rows = previous.get("handoff_sources") or previous.get("source_patrols", [])
    missing_good = []
    for old in old_rows:
        key = (old.get("symbol"), old.get("channel"), old.get("url"))
        ended = progress.date_value(old.get("request_end_utc") or old.get("last_patrol_at_beijing"))
        if key in required and old.get("status") in (200, 304) and ended and (now-ended).total_seconds() <= 300:
            new = required[key]
            if not new.get("request_end_utc") or new.get("status") not in (200, 304):
                missing_good.append(":".join(part for part in key if part))
    return {"ready": bool(rows and run_alive(successor, now) and not missing and not missing_good and companies <= valid),
            "active_companies": sorted(companies), "unobserved_sources": missing,
            "companies_without_valid_discovery": sorted(companies-valid),
            "previously_accessible_sources_not_ready": missing_good}


async def workflow_runs(client):
    response = await client.get(WORKFLOW_API + "/runs", params={"per_page": 10})
    response.raise_for_status()
    return response.json().get("workflow_runs", [])


async def read_keepalive_state(client):
    response = await client.get(KEEPALIVE_STATE_API, params={"ref": "handoff-control"})
    if response.status_code == 404:
        return {}, None
    response.raise_for_status()
    value = response.json()
    state = json.loads(base64.b64decode(value["content"]))
    if state.get("schema_version") != 1 or state.get("owner") != "github_actions":
        raise ValueError("invalid_cloud_keepalive_state")
    return state, value["sha"]


def continuity_observation(previous, successor):
    first = min((row["first_request_start_utc"] for row in successor.get("handoff_sources", [])
                 if row.get("first_request_start_utc")), default=None)
    started = progress.date_value(first)
    alive = progress.date_value(previous.get("collector_last_alive_utc"))
    stopped = progress.date_value(previous.get("collector_stopped_observed_utc"))
    if not started:
        return None
    overlap = bool(alive and started <= alive)
    return {"previous_run_id": previous["run_id"], "successor_run_id": successor["run_id"],
            "successor_first_request_utc": first, "previous_last_alive_utc": previous.get("collector_last_alive_utc"),
            "previous_stopped_observed_utc": previous.get("collector_stopped_observed_utc"),
            "collector_request_gap_lower_ms": 0 if overlap else max(0, (started-stopped).total_seconds()*1000) if stopped else None,
            "collector_request_gap_upper_ms": max(0, (started-alive).total_seconds()*1000) if alive else None,
            "timing_basis": "UTC process observation bounds; not per-source publication latency; no cross-run monotonic clock"}


async def retire_run(client, previous, successor, now):
    if previous.get("handoff_control_version") != 1:
        response = await client.post(f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{previous['run_id'].split('-')[0]}/cancel")
        response.raise_for_status()
        return "legacy_workflow_cancel_final_snapshot_not_guaranteed"
    api = f"https://api.github.com/repos/{REPOSITORY}"
    branch = await client.get(api + "/git/ref/heads/handoff-control")
    if branch.status_code == 404:
        main = await client.get(api + "/git/ref/heads/main")
        main.raise_for_status()
        branch = await client.post(api + "/git/refs", json={"ref": "refs/heads/handoff-control", "sha": main.json()["object"]["sha"]})
    branch.raise_for_status()
    payload = {"run_id": previous["run_id"], "successor_run_id": successor["run_id"],
               "action": "retire_after_healthy_successor", "requested_utc": now.isoformat()}
    path = api + "/contents/controls/retire-" + previous["run_id"] + ".json"
    existing = await client.get(path, params={"ref": "handoff-control"})
    data = {"message": "Retire collector after observed healthy handoff", "branch": "handoff-control",
            "content": base64.b64encode(json.dumps(payload).encode()).decode()}
    if existing.status_code != 404:
        existing.raise_for_status()
        data["sha"] = existing.json()["sha"]
    response = await client.put(path, json=data)
    response.raise_for_status()
    return "cooperative_stop_and_final_snapshot"


def completed_document_inventory(runtime):
    """Carry verified document identities forward, never observations or clocks."""
    runtime = Path(runtime).resolve()
    manifest_path = (BASE / "us_runner/live/source_manifest.json" if (BASE / "us_runner/live").is_dir()
                     else BASE / "live/source_manifest.json")
    manifest_body = manifest_path.read_bytes()
    manifest = json.loads(manifest_body)
    watchlist = manifest_path.with_name("watchlist.json").read_bytes()
    watchlist_sha = hashlib.sha256(watchlist).hexdigest()
    if watchlist_sha != manifest["watchlist.json"]["sha256"]:
        raise ValueError("inheritance_manifest_mismatch")
    events = {event["symbol"]: event for event in json.loads(watchlist)}
    documents = {}
    for row in progress.read_us_live(runtime)[0]:
        if (row.get("archive_readback_verified") is not True or row.get("accepted") is not True
                or row.get("tables_complete") is not True or row.get("us_execution_qualified") is not True
                or row.get("url_parameters_removed") or row.get("symbol") not in events):
            continue
        event = events[row["symbol"]]
        if row.get("channel") not in {source["channel"] for source in event["sources"]}:
            continue
        paths = {Path(item["path"]).suffix: (runtime / item["path"]).resolve() for item in row.get("artifacts", [])}
        original = paths.get(".html") or paths.get(".pdf") or paths.get(".xlsx")
        if (original is None or not {".txt", ".json"}.issubset(paths)
                or any(path.parent != runtime / "reports" or not path.is_file() for path in paths.values())):
            continue
        raw = original.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        # Older imported rows retain the verified content hash in their filename.
        if not original.stem.endswith("_" + digest[:12]):
            continue
        report = json.loads(paths[".json"].read_text(encoding="utf-8"))
        if (report.get("text") != paths[".txt"].read_text(encoding="utf-8")
                or not report.get("text") or not isinstance(report.get("tables"), list)
                or len(report["tables"]) != row.get("table_count")):
            continue
        if event["symbol"] == "SE" and original.suffix == ".pdf":
            details = report.get("table_details", [])
            if not details or any(table.get("column_associations_verified") is not True
                                  or not table.get("source_xref") for table in details):
                continue  # The old page-wide guessed tables must be collected again.
        key = (row["symbol"], row["channel"], row["url"], digest)
        documents.setdefault(key, {"symbol": row["symbol"], "channel": row["channel"], "url": row["url"],
            "sha256": digest, "source_evidence_id": row["evidence_id"], "accepted": True, "tables_complete": True,
            "fiscal_year": event["fiscal_year"], "quarter": event["quarter"], "period_end": event["period_end"]})
    return {"schema_version": 1, "source_manifest_sha256": hashlib.sha256(manifest_body).hexdigest(),
            "watchlist_sha256": watchlist_sha, "documents": list(documents.values())}


async def publish_completed_inventory(client, inventory):
    api = f"https://api.github.com/repos/{REPOSITORY}"
    branch = await client.get(api + "/git/ref/heads/handoff-control")
    if branch.status_code == 404:
        main = await client.get(api + "/git/ref/heads/main")
        main.raise_for_status()
        branch = await client.post(api + "/git/refs", json={"ref": "refs/heads/handoff-control", "sha": main.json()["object"]["sha"]})
    branch.raise_for_status()
    path = api + "/contents/controls/completed-documents.json"
    existing = await client.get(path, params={"ref": "handoff-control"})
    update = {"message": "Carry verified earnings documents into the next collector", "branch": "handoff-control",
              "content": base64.b64encode(json.dumps(inventory, ensure_ascii=False).encode()).decode()}
    if existing.status_code == 200:
        update["sha"] = existing.json()["sha"]
    elif existing.status_code != 404:
        existing.raise_for_status()
    response = await client.put(path, json=update)
    response.raise_for_status()


async def maintain_workflow(snapshots, state, now=None, client=None, token_loader=github_token, jobs=None, runtime=None,
                            *, sync_only=False, dispatch_blockers=None, local_sec_rps=0):
    now = now or datetime.now(timezone.utc)
    if now >= DISPATCH_UNTIL:
        return {"workflow_state": "dispatch_deadline_reached"}
    if not snapshots:
        return {"workflow_state": "awaiting_first_deployment"}
    if isinstance(snapshots, dict):
        snapshots = [snapshots]
    owned = client is None
    if owned:
        token = await asyncio.to_thread(token_loader)
        client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30,
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"})
    try:
        jobs = jobs if jobs is not None else await workflow_runs(client)
        active = sorted((row for row in jobs if row["status"] != "completed"), key=lambda row: row["created_at"])
        by_id = {row["run_id"].split("-")[0]: row for row in snapshots}
        result = {"active_run_ids": [str(row["id"]) for row in active]}
        healthy = [by_id[str(job["id"])] for job in active
                   if str(job["id"]) in by_id and run_alive(by_id[str(job["id"])], now)]
        result["selected_run_id"] = healthy[0]["run_id"] if healthy else None
        if len(active) >= 2:
            old, new = by_id.get(str(active[0]["id"]), {}), by_id.get(str(active[-1]["id"]), {})
            budget = sum(by_id.get(str(job["id"]), {}).get("sec_rps") or (8 if str(job["id"]) == str(active[0]["id"]) else state.get("dispatched_sec_rps", 2)) for job in active)
            result["overlap_sec_rps_budget"] = budget
            readiness = handoff_ready(new, old, now)
            result.update(workflow_state="waiting_for_successor_readiness", handoff_readiness=readiness)
            if len(active) > 2 or budget + local_sec_rps > 10:
                result["workflow_state"] = "overlap_budget_violation"
                return result
            if readiness["ready"]:
                result["selected_run_id"] = new["run_id"]
                old_id = str(active[0]["id"])
                if not sync_only and state.get("retirement_requested_run_id") != old_id:
                    method = await retire_run(client, old, new, now)
                    result.update(retirement_requested_run_id=old_id, retirement_requested_utc=now.isoformat(), retirement_method=method)
                first = min((row["first_request_start_utc"] for row in new.get("handoff_sources", []) if row.get("first_request_start_utc")), default=None)
                result.update(workflow_state="healthy_successor_retiring_previous", handoff_observation={
                    "previous_run_id": old.get("run_id"), "successor_run_id": new["run_id"],
                    "successor_first_request_utc": first, "previous_last_alive_utc": old.get("collector_last_alive_utc"),
                    "previous_last_heartbeat_utc": old.get("collector_heartbeat_utc"),
                    "readiness_confirmed_utc": now.isoformat(),
                    "monitoring_gap_ms": 0 if first and old.get("collector_last_alive_utc") and first <= old["collector_last_alive_utc"] else None,
                    "timing_basis": "Separate run UTC observations; no cross-run monotonic timing"})
                if sync_only:
                    result["workflow_state"] = "healthy_successor_waiting_for_cloud_retirement"
            return result
        old = by_id.get(str(active[0]["id"]), {}) if active else max(snapshots, key=lambda row: row.get("started_utc") or "")
        if active and not old:
            return {**result, "workflow_state": "awaiting_new_run_evidence"}
        until = progress.date_value(old.get("until_utc"))
        heartbeat = progress.date_value(old.get("collector_heartbeat_utc"))
        started = progress.date_value(old.get("started_utc"))
        if active and until and (until-now).total_seconds() > 1800 and (
                heartbeat and (now-heartbeat).total_seconds() <= 300 or started and (now-started).total_seconds() <= 300):
            return {**result, "workflow_state": "healthy" if run_alive(old, now) else "initializing_or_awaiting_window"}
        last_dispatch = progress.date_value(state.get("last_dispatch_utc"))
        if last_dispatch and (now-last_dispatch).total_seconds() < 300:
            return {**result, "workflow_state": "awaiting_dispatched_job"}
        # A queued initial run is already the replacement; do not create a third run.
        if active and active[0]["status"] != "in_progress":
            return {**result, "workflow_state": "awaiting_dispatched_job"}
        if sync_only:
            return {**result, "workflow_state": "sync_only_awaiting_cloud_dispatch"}
        if dispatch_blockers:
            return {**result, "workflow_state": "dispatch_blocked", "dispatch_blockers": dispatch_blockers}
        budget = 2 if active and (old.get("sec_rps") or 8) > 4 else 4
        if budget + ((old.get("sec_rps") or 8) if active else 0) + local_sec_rps > 10:
            return {**result, "workflow_state": "dispatch_budget_violation"}
        slot = 1-int(old.get("handoff_slot") or 0) if active else 0
        if runtime is not None:
            inventory = await asyncio.to_thread(completed_document_inventory, runtime)
            await publish_completed_inventory(client, inventory)
            result["inherited_document_count"] = len(inventory["documents"])
        response = await client.post(WORKFLOW_API + "/dispatches", json={"ref": "main", "inputs": {
            "duration_minutes": "300", "symbols": old.get("symbols") or "", "handoff_slot": str(slot), "sec_rps": str(budget)}})
        response.raise_for_status()
        return {**result, "workflow_state": "successor_dispatched" if active else "dispatched",
                "last_dispatch_utc": now.isoformat(), "dispatched_sec_rps": budget,
                "overlap_sec_rps_budget": budget+(old.get("sec_rps") or 8) if active else budget}
    finally:
        if owned:
            await client.aclose()


async def sync_once(runtime, proxy=None, api_client=None, token_loader=github_token, *, sync_only=False):
    runtime = Path(runtime).resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    status_path = runtime / "us_live_bridge_status.json"
    state = progress.read_json(status_path)
    for key in ("error_type", "stage", "evidence_id", "workflow_error"):
        state.pop(key, None)
    state.update(pid=os.getpid(), started_utc=utc(), state="syncing", imported_captures=0, failed_imports=0)
    api_owned = api_client is None
    token = await asyncio.to_thread(token_loader)
    if api_owned:
        api_client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30)
    api_client.headers.update({"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "Cache-Control": "no-cache"})
    with closing(database(runtime)) as connection:
        try:
            jobs = await workflow_runs(api_client)
            active = [job for job in jobs if job["status"] != "completed"]
            completed = [job for job in jobs if job["status"] == "completed"][:2]
            branches = ["evidence-" + str(job["id"]) + "-" + str(job.get("run_attempt", 1)) for job in active+completed]
            # Legacy evidence is read during migration, then independent per-run branches own all new snapshots.
            branches.append("evidence")
            commits = set()
            for branch in dict.fromkeys(branches):
                try:
                    commit = await evidence_commit(api_client, lambda: token, branch)
                    if not commit or commit in commits:
                        continue
                    commits.add(commit)
                    response = await api_client.get(PUBLIC_BASE + "latest.json", params={"ref": commit}, headers={"Accept": "application/vnd.github.raw+json"})
                    response.raise_for_status()
                    snapshot = response.json()
                    metadata, added, failed = await import_snapshot(snapshot, runtime, connection, api_client, commit)
                    state.update(state="synced" if not failed else "partial", status=200, evidence_commit=commit,
                                 last_success_utc=utc(), imported_captures=state["imported_captures"]+added,
                                 failed_imports=state["failed_imports"]+failed)
                except Exception as exc:
                    state.update(state="partial", **log_error(connection, "snapshot", exc, branch))
            snapshots = [json.loads(row[0]) for row in connection.execute("SELECT payload FROM runs")]
            ordered = sorted(snapshots, key=lambda row: row.get("started_utc") or "")
            observations = [item for old, new in zip(ordered, ordered[1:])
                            if (item := continuity_observation(old, new)) is not None]
            for observation in observations:
                if observation not in state.get("continuity_observations", []):
                    connection.execute("INSERT INTO log(kind,at_ns,payload) VALUES ('continuity',?,?)",
                                       (time.time_ns(), json.dumps(observation)))
            connection.commit()
            state["continuity_observations"] = observations
            outcome = await maintain_workflow(snapshots, state, client=api_client, jobs=jobs, runtime=runtime,
                                              sync_only=sync_only)
            if sync_only:
                control, _ = await read_keepalive_state(api_client)
                observation = control.get("handoff_observation") or {}
                known_runs = {row["run_id"] for row in snapshots}
                if (control.get("retirement_requested_utc") and observation.get("previous_run_id") in known_runs
                        and observation.get("successor_run_id") in known_runs):
                    outcome.update({key: control[key] for key in ("retirement_requested_run_id", "retirement_requested_utc",
                                    "retirement_method", "handoff_observation") if key in control})
            if outcome.get("retirement_requested_utc") and outcome.get("retirement_requested_utc") != state.get("retirement_requested_utc"):
                connection.execute("INSERT INTO log(kind,at_ns,payload) VALUES ('handoff',?,?)", (time.time_ns(), json.dumps(outcome["handoff_observation"])))
                connection.commit()
            state.update(outcome)
            selected = next((row for row in snapshots if row["run_id"] == state.get("selected_run_id")), None)
            if selected:
                state.update(run_id=selected["run_id"], source_updated_utc=selected["updated_utc"],
                             collector_heartbeat_utc=selected["collector_heartbeat_utc"])
        except Exception as exc:
            state.update(state="failed", selected_run_id=None, **log_error(connection, "workflow_or_snapshot", exc))
        finally:
            if api_owned:
                await api_client.aclose()
    state["updated_utc"] = utc()
    save_json(status_path, state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=BASE / "runtime")
    parser.add_argument("--proxy", default="http://127.0.0.1:10808")
    parser.add_argument("--until", default=SYNC_UNTIL)
    parser.add_argument("--sync-only", action="store_true", help="Import evidence; cloud keepalive alone dispatches and retires runs")
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    if datetime.now(timezone.utc) >= datetime.fromisoformat(args.until) or (runtime / "STOP_US_LIVE_BRIDGE").exists():
        return
    import msvcrt
    with (runtime / "us_live_bridge.lock").open("a+b") as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        try:
            state = asyncio.run(sync_once(runtime, args.proxy, sync_only=args.sync_only))
            if sys.stdout is not None:
                print(json.dumps(state, ensure_ascii=False))
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == "__main__":
    main()
