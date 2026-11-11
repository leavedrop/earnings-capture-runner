"""One bounded cloud handoff check. No SEC requests or local-machine dependency."""
from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import httpx

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / "live"))
import us_live_bridge as bridge

API = f"https://api.github.com/repos/{bridge.REPOSITORY}"


async def retained_inventory(client):
    """Reuse the already verified inventory; do not redownload 104 reports."""
    manifest_body = (BASE / "live/source_manifest.json").read_bytes()
    watchlist_body = (BASE / "live/watchlist.json").read_bytes()
    manifest = json.loads(manifest_body)
    response = await client.get(bridge.PUBLIC_BASE + "controls/completed-documents.json",
                                params={"ref": "handoff-control"})
    if response.status_code == 404:
        return {"inventory_state": "missing", "inventory_count": 0}
    response.raise_for_status()
    inventory = json.loads(base64.b64decode(response.json()["content"]))
    watchlist_sha = hashlib.sha256(watchlist_body).hexdigest()
    valid = (inventory.get("schema_version") == 1
             and inventory.get("source_manifest_sha256") == hashlib.sha256(manifest_body).hexdigest()
             and inventory.get("watchlist_sha256") == watchlist_sha == manifest["watchlist.json"]["sha256"]
             and isinstance(inventory.get("documents"), list))
    return {"inventory_state": "verified_hashes" if valid else "manifest_mismatch",
            "inventory_count": len(inventory.get("documents", [])) if valid else 0,
            "inventory_refresh": "retained_existing; new documents may be initially_present on the next run"}


async def save_state(client, state, previous_sha):
    update = {"message": "Record cloud collector handoff check", "branch": "handoff-control",
              "content": base64.b64encode(json.dumps(state, ensure_ascii=False, indent=2).encode()).decode()}
    if previous_sha:
        update["sha"] = previous_sha
    response = await client.put(bridge.KEEPALIVE_STATE_API, json=update)
    response.raise_for_status()


async def check_once(client, token, *, now=None):
    """Reuse maintain_workflow, handoff_ready and retire_run for every decision."""
    now = now or datetime.now(timezone.utc)
    state, previous_sha = await bridge.read_keepalive_state(client)
    for key in ("error_type", "error_status", "snapshot_errors", "dispatch_blockers"):
        state.pop(key, None)
    state.update(schema_version=1, owner="github_actions", checked_at_utc=now.isoformat(),
                 dispatch_until_utc=bridge.DISPATCH_UNTIL.isoformat(), local_sec_rps_budget=2,
                 total_sec_rps_limit=10, raw_report_requests=0)
    try:
        if now >= bridge.DISPATCH_UNTIL:
            state.update(await bridge.maintain_workflow([], state, now, client, jobs=[], runtime=None))
            response = await client.put(API + "/actions/workflows/keepalive.yml/disable")
            response.raise_for_status()
            state.update(self_disabled=True, disabled_at_utc=now.isoformat(), selected_run_id=None)
        else:
            jobs = await bridge.workflow_runs(client)
            response = await client.get(API + "/actions/workflows/probe.yml/runs", params={"per_page": 10})
            response.raise_for_status()
            probes = [str(row["id"]) for row in response.json().get("workflow_runs", []) if row["status"] != "completed"]
            state["active_probe_run_ids"] = probes
            inventory = await retained_inventory(client)
            state.update(inventory)
            blockers = (["active_probe:" + ident for ident in probes]
                        + ([] if inventory["inventory_state"] == "verified_hashes" else ["inventory_not_verified"]))
            active = [row for row in jobs if row["status"] != "completed"]
            completed = [row for row in jobs if row["status"] == "completed"][:2]
            snapshots, observations, errors = [], [], []
            for job in active + completed:
                run_id = f"{job['id']}-{job.get('run_attempt', 1)}"
                branch = "evidence-" + run_id
                try:
                    commit = await bridge.evidence_commit(client, lambda: token, branch)
                    if commit is None:
                        errors.append({"run_id": run_id, "error_type": "evidence_not_yet_published"})
                        continue
                    response = await client.get(bridge.PUBLIC_BASE + "latest.json", params={"ref": commit},
                                                headers={"Accept": "application/vnd.github.raw+json"})
                    response.raise_for_status()
                    snapshot = response.json()
                    node = snapshot.get("node") or {}
                    if (snapshot.get("schema_version") != 1 or snapshot.get("run_id") != run_id
                            or snapshot.get("evidence_branch", branch) != branch
                            or not re.fullmatch(r"[A-Z]{2}", str(node.get("loc", "")))
                            or not re.fullmatch(r"[A-Z0-9]{3,8}", str(node.get("colo", "")))):
                        raise ValueError("snapshot_run_or_node_mismatch")
                    snapshot["us_execution_qualified"] = node["loc"] == "US"
                    snapshots.append(snapshot)
                    observations.append({"run_id": run_id, "commit": commit, "node": {"loc": node["loc"], "colo": node["colo"]},
                                         "state": snapshot.get("state"), "updated_utc": snapshot.get("updated_utc"),
                                         "collector_heartbeat_utc": snapshot.get("collector_heartbeat_utc"),
                                         "requests": snapshot.get("request_failures", {}).get("requests", 0)})
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                    errors.append({"run_id": run_id, "error_type": type(exc).__name__})
            state.update(evidence_observations=observations, snapshot_errors=errors)
            outcome = await bridge.maintain_workflow(snapshots, state, now, client, jobs=jobs, runtime=None,
                                                     dispatch_blockers=blockers, local_sec_rps=2)
            state.update(outcome)
            if blockers:
                state["dispatch_blockers"] = blockers
            if outcome.get("overlap_sec_rps_budget") is not None:
                state["projected_total_sec_rps"] = outcome["overlap_sec_rps_budget"] + 2
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        state.update(workflow_state="check_failed", error_type=type(exc).__name__, selected_run_id=None)
        if isinstance(exc, httpx.HTTPStatusError):
            state["error_status"] = exc.response.status_code
    state["updated_utc"] = datetime.now(timezone.utc).isoformat()
    await save_state(client, state, previous_sha)
    return state


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token or os.environ.get("GITHUB_REPOSITORY", bridge.REPOSITORY) != bridge.REPOSITORY:
        raise SystemExit("Expected repository GITHUB_TOKEN context is required")

    async def run():
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30,
                headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                         "Cache-Control": "no-cache"}) as client:
            result = await check_once(client, token)
        print(json.dumps({key: result.get(key) for key in ("workflow_state", "checked_at_utc", "selected_run_id",
              "active_run_ids", "active_probe_run_ids", "inventory_state", "inventory_count", "projected_total_sec_rps",
              "self_disabled", "error_type")}, ensure_ascii=False))
        return 1 if result["workflow_state"] == "check_failed" else 0

    try:
        raise SystemExit(asyncio.run(run()))
    except httpx.HTTPError as exc:
        raise SystemExit("Cloud handoff API failed: " + type(exc).__name__) from None


if __name__ == "__main__":
    main()
