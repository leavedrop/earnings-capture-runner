"""Run the existing collector in one US window and publish safe evidence to this repo."""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import httpx

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
import progress

PUBLIC_REPORT = re.compile(r"reports/[A-Za-z0-9._-]+\.(?:html|pdf|xlsx|txt|json)")


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def public_bytes(value):
    body = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, indent=2).encode()
    identity = os.environ.get("SEC_USER_AGENT", "")
    private = [identity, os.environ.get("GITHUB_TOKEN", ""), *re.findall(r"\S+@\S+", identity)]
    if any(secret and secret.encode() in body for secret in private):
        raise ValueError("Private identity or token found in public evidence")
    return body


def write_public(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_bytes(value))


def handoff_sources(runtime, status, connection, metadata):
    """Read completed discovery evidence; a successful HTML shell is not readiness."""
    events = json.loads((BASE / "watchlist.json").read_text(encoding="utf-8"))
    selected = set(filter(None, metadata.get("symbols", "").split(",")))
    latest, first = {}, {}
    if connection is not None:
        for symbol, channel, payload in connection.execute("""
            SELECT symbol,channel,payload FROM log WHERE id IN (
              SELECT max(id) FROM log WHERE kind='request' AND json_extract(payload,'$.purpose')='discovery'
              GROUP BY symbol,channel,json_extract(payload,'$.url'))"""):
            record = json.loads(payload)
            latest[(symbol, channel, record.get("url"))] = record
        for symbol, channel, payload in connection.execute("""
            SELECT symbol,channel,payload FROM log WHERE id IN (
              SELECT min(id) FROM log WHERE kind='request' AND json_extract(payload,'$.purpose')='discovery'
              GROUP BY symbol,channel,json_extract(payload,'$.url'))"""):
            record = json.loads(payload)
            first[(symbol, channel, record.get("url"))] = record
    now = datetime.now(timezone.utc)
    patrols = {(*key.split(":", 2)[:2], value.get("url")): value
               for key, value in status.get("source_status", {}).items()}
    rows = []
    for event in events:
        if selected and event["symbol"] not in selected:
            continue
        for source in event["sources"]:
            symbol, channel = event["symbol"], source["channel"]
            key = (symbol, channel, source["url"])
            patrol = patrols.get(key, {})
            completed = patrol.get("state") in ("captured", "captured_monitoring_later_filings")
            deadline = datetime.fromisoformat(metadata.get("hard_stop_utc") or metadata.get("until_utc")
                                             or "2026-11-13T13:03:00+08:00")
            required = (datetime.fromisoformat(event["window_start"]) <= now and
                        (now <= deadline if channel == "sec" else
                         not completed and now <= datetime.fromisoformat(event["window_end"])))
            rec, initial = latest.get(key, {}), first.get(key, {})
            valid, basis = False, None
            if rec.get("status") in (200, 304) and rec.get("request_end_utc"):
                digest = rec.get("sha256") or rec.get("reused_sha256")
                if digest:
                    try:
                        with gzip.open(runtime / "raw" / (digest + ".gz"), "rb") as stream:
                            body = stream.read()
                        if channel == "sec":
                            document = json.loads(body)
                            valid = (int(document.get("cik", -1)) == int(event["cik"])
                                     and isinstance(document.get("filings", {}).get("recent"), dict))
                            basis = "SEC submissions CIK and recent filings structure"
                        elif source.get("kind") == "rss" or body.lstrip().startswith(b"<?xml"):
                            document = ET.fromstring(body)
                            valid = any(item.tag.rsplit("}", 1)[-1] in ("item", "entry") for item in document.iter())
                            basis = "Parsed public feed with entries"
                        else:
                            from sources import discover, listing_structure
                            valid = bool(discover(body, rec.get("final_url") or source["url"],
                                                 rec.get("response_headers", {}).get("content-type", ""), event)
                                         or listing_structure(body, rec.get("final_url") or source["url"],
                                                              rec.get("response_headers", {}).get("content-type", ""), event))
                            if not valid:
                                from bs4 import BeautifulSoup
                                page = BeautifulSoup(body, "lxml")
                                # Historical entries establish a functioning list before the new quarter appears.
                                valid = any(re.search(r"/(?:news-release-details|news-details|press-release-details)/|/(?:20\d{2})/.*(?:results|earnings|reports)",
                                                      link.get("href", ""), re.I) for link in page.select("a[href]"))
                            basis = "Public announcement links present; current-quarter candidate may be absent"
                    except (ValueError, OSError, ET.ParseError):
                        pass
            rows.append({"symbol": symbol, "channel": channel, "url": source["url"],
                         "window_start": event["window_start"], "window_end": event["window_end"],
                         "completed": completed, "required": required, "state": patrol.get("state"),
                         "status": rec.get("status"), "request_start_utc": rec.get("request_start_utc"),
                         "request_end_utc": rec.get("request_end_utc"),
                         "first_request_start_utc": initial.get("request_start_utc"),
                         "first_request_end_utc": initial.get("request_end_utc"),
                         "valid_discovery": valid, "validity_basis": basis if valid else None})
    return rows


def snapshot(runtime, checkout, metadata, cached):
    """Whitelist projection only: never publish the source DB, headers or metadata."""
    database = runtime / "observations.sqlite3"
    failures, requests, failed_requests = [], 0, 0
    if database.exists():
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            starts = {json.loads(payload)["run_id"]: datetime.fromtimestamp(at / 1e9, timezone.utc)
                      for at, payload in connection.execute("select at_ns,payload from log where kind='run_start'")}
            for ident, payload in connection.execute("select id,payload from log where kind='capture' order by id"):
                if ident in cached:
                    continue
                record = json.loads(payload)
                row = progress.capture_row(record, runtime, runtime, starts.get(record.get("run_id")))
                stem = "reports/" + row["symbol"].replace(".", "_") + "_" + row["channel"] + "_" + record["sha256"][:12]
                artifacts = []
                for artifact in row["artifacts"]:
                    relative = artifact["path"]
                    source = (runtime / relative).resolve()
                    if not PUBLIC_REPORT.fullmatch(relative) or source.parent != runtime / "reports":
                        raise ValueError("Artifact outside the public reports directory")
                    body = source.read_bytes()
                    if source.suffix in (".html", ".pdf", ".xlsx") and hashlib.sha256(body).hexdigest() != record["sha256"]:
                        raise ValueError("Original report SHA-256 mismatch")
                    write_public(checkout / relative, body)
                    artifacts.append({"path": relative, "sha256": hashlib.sha256(body).hexdigest(),
                                      "bytes": len(body), "kind": source.suffix[1:]})
                report = json.loads((runtime / (stem + ".json")).read_text(encoding="utf-8"))
                parsed = {"text": (runtime / (stem + ".txt")).read_text(encoding="utf-8"),
                          "tables": report["tables"]}
                if "table_spans" in report:
                    from sources import check_table_spans
                    check_table_spans(report["tables"], report["table_spans"])
                    parsed["table_spans"] = report["table_spans"]
                parsed.update({key: report[key] for key in ("table_details", "page_diagnostics", "spreadsheet") if key in report})
                body = public_bytes(parsed)
                write_public(checkout / (stem + ".json"), body)
                artifacts.append({"path": stem + ".json", "sha256": hashlib.sha256(body).hexdigest(),
                                  "bytes": len(body), "kind": "json"})
                row.update(evidence_id=metadata["run_id"] + ":" + str(ident),
                           mode="live", retry=record.get("retry"),
                           artifacts=artifacts, sha256=record["sha256"],
                           started_utc=record.get("discovered_utc"), parsed_utc=record.get("validated_utc"),
                           parse_ms=record.get("parse_ms"), queue_ms=record.get("queue_ms"))
                cached[ident] = row
            for ident, payload in connection.execute("select id,payload from log where kind='attachment' order by id"):
                cache_key = ("attachment", ident)
                if cache_key in cached:
                    continue
                record = json.loads(payload)
                if not progress.recognized_achr_attachment(record):
                    continue
                row = progress.attachment_row(record, runtime)
                artifacts = []
                if {Path(item["path"]).suffix for item in row.get("artifacts", [])} != {".pdf", ".txt", ".json"}:
                    raise ValueError("Supporting letter public files incomplete")
                for artifact in row["artifacts"]:
                    relative = artifact["path"]
                    source = (runtime / relative).resolve()
                    if not progress.ACHR_SUPPORT_FILE.fullmatch(relative) or source.parent != runtime / "reports":
                        raise ValueError("Supporting letter outside public reports directory")
                    body = source.read_bytes()
                    if source.suffix == ".pdf" and hashlib.sha256(body).hexdigest() != row["sha256"]:
                        raise ValueError("Supporting letter SHA-256 mismatch")
                    if source.suffix == ".json":
                        parsed = json.loads(body)
                        body = public_bytes({key: parsed[key] for key in ("text", "tables", "table_spans", "page_diagnostics",
                            "pdf_pages_total", "pdf_pages_processed", "pdf_pages_text_extracted", "pdf_metadata", "supporting_document")})
                    write_public(checkout / relative, body)
                    artifacts.append({"path": relative, "sha256": hashlib.sha256(body).hexdigest(),
                                      "bytes": len(body), "kind": source.suffix[1:]})
                row.update(evidence_id=metadata["run_id"] + ":" + str(ident), artifacts=artifacts)
                cached[cache_key] = row
            groups = connection.execute("""
                select symbol,channel,json_extract(payload,'$.status'),
                    case when json_extract(payload,'$.status') is null then
                      substr(coalesce(json_extract(payload,'$.error'),'RequestError'),1,
                        case when instr(coalesce(json_extract(payload,'$.error'),''),':')>0
                        then instr(json_extract(payload,'$.error'),':')-1 else 40 end)
                    else '' end,
                    count(*),max(at_ns) from log where kind='request' group by 1,2,3,4
            """).fetchall()
            for symbol, channel, status, error_type, count, at in groups:
                requests += count
                if status is not None and status < 400:
                    continue
                failed_requests += count
                failures.append({"symbol": symbol, "channel": channel,
                                 "failure_type": "HTTP " + str(status) if status is not None else
                                 error_type if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", error_type) else "RequestError",
                                 "count": count, "lastseen": datetime.fromtimestamp(at / 1e9, timezone.utc).isoformat()})
    status = progress.read_json(runtime / "status.json")
    if database.exists():
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
            readiness = handoff_sources(runtime, status, connection, metadata)
    else:
        readiness = handoff_sources(runtime, status, None, metadata)
    data = {**metadata, "schema_version": 1, "updated_utc": utc(),
            "collector_heartbeat_utc": status.get("updated_utc"),
            "captures": [row for key, row in cached.items() if isinstance(key, int)],
            "capture_count": sum(isinstance(key, int) for key in cached),
            "attachments": [row for key, row in cached.items() if isinstance(key, tuple) and key[0] == "attachment"],
            "source_patrols": progress.source_patrols(status, "US live runner"),
            "handoff_sources": readiness,
            "request_failures": {"requests": requests, "failed_requests": failed_requests},
            "failure_groups": failures,
            "publication_scope": "Public documents and safe fields; no raw database, headers or private identity",
            "timing_scope": "Discovery to full parse; CI startup and evidence publication are outside this duration"}
    write_public(checkout / "latest.json", data)
    write_public(checkout / "runs" / metadata["run_id"] / "latest.json", data)
    return data


def git(arguments, directory, env):
    result = subprocess.run(["git", *arguments], cwd=directory, env=env, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Evidence git operation failed: " + arguments[0])
    return result.stdout.strip()


def evidence_checkout(directory, repository, token, branch):
    env = dict(os.environ)
    authorization = base64.b64encode(("x-access-token:" + token).encode()).decode()
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_COUNT="1",
               GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
               GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + authorization)
    git(["init", "--quiet"], directory, env)
    git(["remote", "add", "origin", "https://github.com/" + repository + ".git"], directory, env)
    exists = git(["ls-remote", "--heads", "origin", "refs/heads/" + branch], directory, env)
    if exists:
        git(["fetch", "--depth=1", "origin", branch], directory, env)
        git(["checkout", "-B", branch, "FETCH_HEAD"], directory, env)
    else:
        git(["checkout", "--orphan", branch], directory, env)
    git(["config", "user.name", "github-actions[bot]"], directory, env)
    git(["config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], directory, env)
    (directory / ".gitattributes").write_text("reports/** -text\n", encoding="utf-8")
    return env


def publish(checkout, env, run_id):
    git(["add", "--", ".gitattributes", "latest.json", "runs/" + run_id], checkout, env)
    if (checkout / "reports").exists():
        git(["add", "--", "reports"], checkout, env)
    if git(["diff", "--cached", "--name-only"], checkout, env):
        git(["commit", "--quiet", "-m", "Update public live earnings evidence"], checkout, env)
        git(["push", "origin", "HEAD:refs/heads/evidence-" + run_id], checkout, env)


def retirement_requested(repository, token, run_id):
    # Separate control branch: the bridge never edits a producer's evidence branch.
    with httpx.Client(trust_env=False, timeout=5) as client:
        response = client.get(f"https://api.github.com/repos/{repository}/contents/controls/retire-{run_id}.json",
                              params={"ref": "handoff-control"},
                              headers={"Authorization": "Bearer " + token, "Cache-Control": "no-cache"})
    if response.status_code == 404:
        return False
    response.raise_for_status()
    command = json.loads(base64.b64decode(response.json()["content"]))
    return command.get("run_id") == run_id and command.get("action") == "retire_after_healthy_successor"


def inherit_completed_documents(repository, token, runtime, hashes):
    """Import the bridge's verified URL inventory; this creates no captures."""
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=10) as client:
        response = client.get(f"https://api.github.com/repos/{repository}/contents/controls/completed-documents.json",
                              params={"ref": "handoff-control"},
                              headers={"Authorization": "Bearer " + token, "Cache-Control": "no-cache"})
    if response.status_code == 404:
        return 0
    response.raise_for_status()
    inventory = json.loads(base64.b64decode(response.json()["content"]))
    if (inventory.get("schema_version") != 1
            or inventory.get("source_manifest_sha256") != hashlib.sha256((BASE / "source_manifest.json").read_bytes()).hexdigest()
            or inventory.get("watchlist_sha256") != hashes["watchlist.json"]["sha256"]):
        raise ValueError("inheritance_manifest_mismatch")
    events = {event["symbol"]: event for event in json.loads((BASE / "watchlist.json").read_text(encoding="utf-8"))}
    from watch import Store
    store = Store(runtime)
    count = 0
    try:
        for document in inventory.get("documents", []):
            event = events.get(document.get("symbol"))
            if (event is None or document.get("accepted") is not True or document.get("tables_complete") is not True
                    or document.get("channel") not in {source["channel"] for source in event["sources"]}
                    or any(document.get(key) != event[key] for key in ("fiscal_year", "quarter", "period_end"))
                    or not re.fullmatch(r"[a-f0-9]{64}", str(document.get("sha256", "")))
                    or not re.fullmatch(r"[0-9]+-[0-9]+:[0-9]+", str(document.get("source_evidence_id", "")))
                    or not isinstance(document.get("url"), str) or not document["url"].startswith(("https://", "http://"))
                    or progress.public_url(document.get("url")) != document.get("url")):
                continue
            store.add("inherited_document", {key: document[key] for key in (
                "symbol", "channel", "url", "sha256", "source_evidence_id", "accepted", "tables_complete",
                "fiscal_year", "quarter", "period_end")})
            count += 1
    finally:
        store.db.close()
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-minutes", type=int, default=300)
    parser.add_argument("--symbols", default="")
    parser.add_argument("--handoff-slot", type=int, choices=(0, 1), default=0)
    parser.add_argument("--sec-rps", type=int, choices=(2, 4), default=2)
    parser.add_argument("--output", type=Path, default=BASE / "outputs")
    args = parser.parse_args()
    if not 1 <= args.duration_minutes <= 300:
        parser.error("duration must be between 1 and 300 minutes")
    repository, token = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token:
        parser.error("This entry requires its own GitHub repository and job token")
    hashes = json.loads((BASE / "source_manifest.json").read_text(encoding="utf-8"))
    if any(hashlib.sha256((BASE / name).read_bytes()).hexdigest() != value["sha256"] for name, value in hashes.items()):
        raise ValueError("Production source copy hash mismatch")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = args.output / "private_runtime"
    runtime.mkdir()
    run_id = os.environ.get("GITHUB_RUN_ID", "") + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if not re.fullmatch(r"[0-9]+-[0-9]+", run_id):
        raise ValueError("Expected a GitHub run identity")
    stop = False
    def interrupt(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    with tempfile.TemporaryDirectory(prefix="earnings-public-evidence-") as temporary:
        checkout = Path(temporary)
        env = evidence_checkout(checkout, repository, token, "evidence-" + run_id)
        node = {"loc": None, "colo": None}
        try:
            with httpx.Client(trust_env=False, timeout=10) as client:
                response = client.get("https://www.cloudflare.com/cdn-cgi/trace")
            if response.status_code == 200:
                fields = dict(line.split("=", 1) for line in response.text.splitlines() if line.startswith(("loc=", "colo=")))
                node = {"loc": fields.get("loc"), "colo": fields.get("colo")}
        except httpx.HTTPError:
            pass
        started = datetime.now(timezone.utc)
        until = min(started + timedelta(minutes=args.duration_minutes), datetime.fromisoformat("2026-11-13T13:03:00+08:00"))
        hard_stop = min(until + timedelta(minutes=20), datetime.fromisoformat("2026-11-13T13:03:00+08:00"))
        metadata = {"run_id": run_id, "node": node, "started_utc": started.isoformat(),
                    "until_utc": until.isoformat(), "hard_stop_utc": hard_stop.isoformat(), "state": "starting", "mode": "live",
                    "handoff_slot": args.handoff_slot, "sec_rps": args.sec_rps, "symbols": args.symbols,
                    "handoff_control_version": 1,
                    "evidence_branch": "evidence-" + run_id,
                    "source_sha256": hashes, "startup_gap_semantics": "Monitoring starts only after the collector's first actual source request"}
        cached = {}
        if node.get("loc") != "US" or not node.get("colo") or not os.environ.get("SEC_USER_AGENT", "").strip() or until <= started:
            metadata["state"] = "not_us" if node.get("loc") != "US" or not node.get("colo") else "deadline_reached" if until <= started else "identity_missing"
            data = snapshot(runtime, checkout, metadata, cached)
            publish(checkout, env, run_id)
            write_public(args.output / "latest.json", data)
            return 1
        try:
            metadata["inherited_document_count"] = inherit_completed_documents(repository, token, runtime, hashes)
        except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
            metadata["inheritance_error_type"] = type(exc).__name__
            print("Document inheritance unavailable: " + type(exc).__name__, flush=True)
        child_env = dict(os.environ)
        for key in ("GITHUB_TOKEN", "GH_TOKEN", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
            child_env.pop(key, None)
        command = [sys.executable, str(BASE / "watch.py"), "run", "--manifest", str(BASE / "watchlist.json"),
                   "--output", str(runtime), "--symbols", args.symbols,
                   "--node", "github-actions-" + node["loc"] + "-" + node["colo"] + "-" + run_id,
                   "--sec-rps", str(args.sec_rps), "--until", hard_stop.isoformat()]
        with (runtime / "launcher.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, env=child_env, cwd=BASE, stdout=log, stderr=log)
            last_publish, last_count, last_control = 0., -1, 0.
            try:
                while process.poll() is None and not stop and datetime.now(timezone.utc) < hard_stop:
                    metadata["collector_last_alive_utc"] = utc()
                    if time.monotonic() - last_control >= 30:
                        try:
                            if retirement_requested(repository, token, run_id):
                                metadata["retirement_instruction_received_utc"] = utc()
                                break
                        except httpx.HTTPError as exc:
                            print("Handoff control check failed: " + type(exc).__name__, flush=True)
                        last_control = time.monotonic()
                    count = 0
                    database = runtime / "observations.sqlite3"
                    if database.exists():
                        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
                            count = connection.execute("select count(*) from log where kind='capture'").fetchone()[0]
                    if time.monotonic() - last_publish >= 120 or count != last_count and time.monotonic() - last_publish >= 10:
                        metadata["state"] = "running"
                        try:
                            data = snapshot(runtime, checkout, metadata, cached)
                            publish(checkout, env, run_id)
                            write_public(args.output / "latest.json", data)
                        except Exception as exc:
                            print("Public evidence publication failed: " + type(exc).__name__, flush=True)
                        last_publish, last_count = time.monotonic(), count
                    time.sleep(5)
            finally:
                (runtime / "STOP").touch()
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=15)
                metadata.update(state="finished" if process.returncode == 0 else "collector_failed", collector_exit_code=process.returncode,
                                collector_stopped_observed_utc=utc())
                data = snapshot(runtime, checkout, metadata, cached)
                publish(checkout, env, run_id)
                write_public(args.output / "latest.json", data)
    return 0 if process.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
