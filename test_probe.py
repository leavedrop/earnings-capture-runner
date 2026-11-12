import asyncio
import argparse
from collections import deque
import hashlib
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from probe import BASE, collect_one, collect_watch_case, content_hashes, pace, reference_match, run, select_targets


class ProbeTimingTest(unittest.IsolatedAsyncioTestCase):
    async def test_regression_ab_alternates_versions_and_keeps_full_44_separate(self):
        selected = select_targets([], "metrics-all-supported")
        calls = []
        node = {"loc": "US", "colo": "TEST", "is_us": True}
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ("before", "after"):
                live = root / version / "live"
                live.mkdir(parents=True)
                body = version.encode()
                (live / "watch.py").write_bytes(body)
                (live / "source_manifest.json").write_text(json.dumps({
                    "watch.py": {"sha256": hashlib.sha256(body).hexdigest()}}), encoding="utf-8")

            async def capture(target, output, observed_node, *, collector_base=None):
                calls.append((target["event"]["symbol"], collector_base.name, output))
                self.assertEqual(observed_node, node)
                self.assertEqual(target["metrics_mode"], "synthetic")
                self.assertEqual(target["pipeline"], "production_watch_list_seed")
                # One HTTP failure and a timely no-signal must remain different outcomes.
                failed = len(calls) == 2
                no_signal = len(calls) == 3
                elapsed = 100 if no_signal else 600 if len(calls) == 4 else 200
                row = {"target_id": target["target_id"], "symbol": target["event"]["symbol"],
                       "url": target["url"], "sha256": None if failed else "a" * 64,
                       "mode": "replay", "node": node, "status": 403 if failed else 200,
                       "complete": not failed, "archived": not failed,
                       "metrics_pipeline_completed": not failed,
                       "decision_budget_passed": not failed and not no_signal and elapsed <= 500,
                       "queue_ms": 5, "headers_ms": 20, "request_total_ms": 30,
                       "parse_ms": 40, "metric_extractions": [] if failed else [{
                           "status": "completed", "discovery_to_decision_ms": elapsed,
                           "timings_ms": {"metrics_extraction_ms": 50},
                           "simulation_decision": {"action": "no_signal" if no_signal else "long"}}]}
                if failed:
                    row["error_type"] = "HTTP_403"
                with (output / "results.ndjson").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row) + "\n")
                return row

            args = argparse.Namespace(scope="metrics-regression-ab", output=root / "outputs",
                                      targets=BASE / "targets.json", baseline_dir=root / "before")
            with patch("probe.BASE", root / "after"), \
                    patch("probe.select_targets", return_value=selected), \
                    patch("probe.httpx.AsyncClient", return_value=client), \
                    patch("probe.identify_node", new_callable=AsyncMock, return_value=node), \
                    patch("probe.execution_hardware", return_value={"cpu_model": "mock CPU"}), \
                    patch("probe.collect_watch_case", side_effect=capture), \
                    patch("probe.asyncio.sleep", new_callable=AsyncMock) as sleep:
                self.assertEqual(await run(args), 1)
            expected = [(symbol, version) for versions in (("before", "after"), ("after", "before"), ("before", "after"))
                        for symbol in ("CSCO", "NBIS", "BRK.B", "KKR") for version in versions]
            self.assertEqual([(symbol, version) for symbol, version, _ in calls[:24]], expected)
            self.assertEqual([symbol for symbol, _, _ in calls[24:]], [row["event"]["symbol"] for row in selected])
            self.assertTrue(all(version == "after" for _, version, _ in calls[24:]))
            self.assertEqual(sleep.await_count, 67)
            self.assertTrue(all(call.args[0] >= 1 for call in sleep.await_args_list))
            summary = json.loads((args.output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(len(summary["attempts"]), 24)
            self.assertEqual(summary["attempts"][1]["error_type"], "HTTP_403")
            self.assertIsNone(summary["attempts"][1]["discovery_to_decision_ms"])
            self.assertTrue(summary["attempts"][2]["processing_within_500ms"])
            self.assertFalse(summary["attempts"][2]["speed_timeout"])
            self.assertFalse(summary["attempts"][2]["decision_budget_passed"])
            self.assertTrue(summary["attempts"][3]["speed_timeout"])
            self.assertEqual(summary["attempts"][3]["metrics_timings_ms"], {"metrics_extraction_ms": 50})
            self.assertEqual(summary["requests_per_second"]["production_child_sec"], 2)
            self.assertNotIn("p95_ms", summary)
            all_rows = [json.loads(line) for line in (args.output / "after_all_44/results.ndjson").read_text().splitlines()]
            self.assertEqual(len(all_rows), 44)
            full_summary = json.loads((args.output / "after_all_44/summary.json").read_text())
            self.assertEqual(full_summary["attempted"], 44)
            self.assertEqual(full_summary["p95_ms"], 200)

    async def test_bw_browser_diagnostic_keeps_denial_events_when_dom_evidence_fails(self):
        from types import ModuleType, SimpleNamespace

        callbacks = {}
        page = MagicMock()
        page.on.side_effect = lambda name, callback: callbacks.__setitem__(name, callback)
        request = MagicMock()
        request.url = "https://www.businesswire.com/newsroom?keywords=D-Wave%20Quantum&token=SECRET_TEST_TOKEN"
        request.method, request.resource_type, request.post_data = "GET", "document", None
        request.is_navigation_request.return_value = True
        request.headers = {"Authorization": "SECRET_TEST_TOKEN", "Cookie": "SECRET_TEST_TOKEN"}
        response = SimpleNamespace(status=403, request=request, url=request.url)
        async def navigate(url, **kwargs):
            self.assertEqual(url, "https://www.businesswire.com/newsroom")
            callbacks["request"](request)
            callbacks["response"](response)
            self.assertEqual(len((args.output / "browser_network.ndjson").read_text().splitlines()), 2)
            return response
        page.goto = AsyncMock(side_effect=navigate)
        page.content = AsyncMock(side_effect=RuntimeError("Page is navigating and changing the content"))
        page.title = AsyncMock(return_value="Page Unavailable")
        page.screenshot = AsyncMock(side_effect=RuntimeError("Screenshot failed"))
        context = MagicMock(new_page=AsyncMock(return_value=page), route=AsyncMock())
        browser = MagicMock(version="Chrome-fixture", new_context=AsyncMock(return_value=context), close=AsyncMock())
        playwright = MagicMock()
        playwright.chromium.launch = AsyncMock(return_value=browser)
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=playwright)
        manager.__aexit__ = AsyncMock(return_value=False)
        package, module = ModuleType("playwright"), ModuleType("playwright.async_api")
        module.async_playwright = lambda: manager
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(scope="bw-browser-http1-access", output=Path(directory) / "outputs",
                                      targets=Path(directory) / "must-not-read-targets.json")
            with patch.dict("sys.modules", {"playwright": package, "playwright.async_api": module}), \
                    patch("importlib.metadata.version", return_value="1.61.0"), \
                    patch("probe.shutil.which", return_value="/usr/bin/google-chrome"), \
                    patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST", "is_us": True}), \
                    patch("probe.prewarm_pdf_pool") as warm, patch("probe.validate") as validate, \
                    patch("probe.collect_one") as collect, patch("probe.collect_watch_case") as production:
                self.assertEqual(await run(args), 0)
            for unused in (warm, validate, collect, production):
                unused.assert_not_called()
            page.goto.assert_awaited_once()
            self.assertEqual(playwright.chromium.launch.call_args.kwargs['args'], ['--disable-http2'])
            page.get_by_role.assert_not_called()
            browser.close.assert_awaited_once()
            summary = json.loads((args.output / "summary.json").read_text())
            self.assertEqual(summary["outcome"], "http_denial_stop_no_retry")
            self.assertTrue(summary['browser_http2_disabled'])
            self.assertEqual(summary["navigation_attempts"], 1)
            self.assertEqual(summary["first_denial"]["status"], 403)
            self.assertFalse(summary["search"]["attempted"])
            self.assertEqual({item["artifact"] for item in summary["evidence_errors"]}, {"html", "png"})
            self.assertEqual(summary["page_snapshots"][0]["title"], "Page Unavailable")
            self.assertTrue(summary["diagnostic_only"])
            self.assertFalse(summary["sla_applicable"] or summary["new_release_evidence"])
            self.assertNotIn("budget_passed", summary)
            self.assertNotIn("discovery_to_parsed_ms", summary)
            self.assertFalse((args.output / "results.ndjson").exists())
            self.assertFalse((args.output / "materials.ndjson").exists())
            events = [json.loads(line) for line in (args.output / "browser_network.ndjson").read_text().splitlines()]
            self.assertEqual([row["kind"] for row in events], ["request", "response"])
            self.assertEqual(events[0]["request_id"], events[1]["request_id"])
            self.assertEqual(events[1]["status"], 403)
            self.assertTrue(all(row["at_utc"] and row["mono_ns"] >= summary["started_mono_ns"] for row in events))
            self.assertNotIn("SECRET_TEST_TOKEN", "".join(path.read_text() for path in args.output.glob("*.*")))
            following = MagicMock(request=request, abort=AsyncMock(), continue_=AsyncMock())
            await context.route.call_args.args[1](following)
            following.abort.assert_awaited_once_with("blockedbyclient")
            following.continue_.assert_not_awaited()

    async def test_skyd_complete_production_export_keeps_both_original_formats_and_structure(self):
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "skyd-complete")
        self.assertEqual(len(targets), 2)
        self.assertEqual([t["reference"]["format"] for t in targets], ["pdf", "xlsx"])
        self.assertTrue(all(t["pipeline"] == "production_watch_list_seed" and t["require_seed_candidate"] for t in targets))
        current = {}
        def collector(command, **kwargs):
            target, raw, parsed = current["target"], current["raw"], current["parsed"]
            self.assertEqual(command[command.index("--samples") + 1], "1")
            self.assertEqual(command[command.index("--candidate-url") + 1], target["url"])
            self.assertNotIn("SEC_USER_AGENT", kwargs["env"])
            runtime = Path(command[command.index("--output") + 1])
            (runtime / "reports").mkdir(); (runtime / "raw").mkdir()
            sha = hashlib.sha256(raw).hexdigest()
            stem = "reports/SKYD_official_" + sha[:12]
            extension = "." + target["reference"]["format"]
            (runtime / (stem + extension)).write_bytes(raw)
            (runtime / (stem + ".txt")).write_text(parsed["text"], encoding="utf-8")
            (runtime / (stem + ".json")).write_text(json.dumps({"metadata": {"private": "SECRET_TEST_TOKEN"}, **parsed}), encoding="utf-8")
            listing = ('<html><div class="qr-doc-list"><a href="' + target["url"] + '">Q3 2026 financial results</a></div></html>').encode()
            requests = []
            for purpose, payload, url in (("discovery", listing, target["listing_url"]), ("candidate", raw, target["url"])):
                path = "raw/" + purpose + ".gz"
                with gzip.open(runtime / path, "wb") as stream:
                    stream.write(payload)
                done = 100_000_000 if purpose == "discovery" else 190_000_000
                requests.append({"id": purpose, "purpose": purpose, "url": url, "final_url": url,
                    "status": 200, "raw_path": path, "queued_mono_ns": 0,
                    "body_complete_mono_ns": done, "request_end_mono_ns": done,
                    "sha256": hashlib.sha256(payload).hexdigest(), "body_bytes": len(payload)})
            capture = {"original_document_path": stem + extension,
                "validation": {"accepted": True, "tables_complete": True,
                    **{key: parsed[key] for key in ("pdf_pages_total", "pdf_pages_processed", "pdf_metadata", "display_complete", "document_format") if key in parsed}},
                "discovery_to_parsed_ms": 60, "discovered_utc": "2026-11-10T00:00:00.140Z", "discovered_mono_ns": 140_000_000,
                "validated_utc": "2026-11-10T00:00:00.200Z", "validated_mono_ns": 200_000_000,
                "parse_ms": 10, "sha256": sha, "body_bytes": len(raw)}
            with sqlite3.connect(runtime / "observations.sqlite3") as connection:
                connection.execute("CREATE TABLE log(id INTEGER PRIMARY KEY,kind TEXT,payload TEXT)")
                for request in requests:
                    connection.execute("INSERT INTO log(kind,payload) VALUES('request',?)", (json.dumps(request),))
                connection.execute("INSERT INTO log(kind,payload) VALUES('capture',?)", (json.dumps(capture),))
            connection.close()
            return MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "raw").mkdir(); (output / "parsed").mkdir()
            for target in targets:
                kind = target["reference"]["format"]
                raw = b"%PDF-fixture" if kind == "pdf" else b"PK\x03\x04-complete-fixture"
                parsed = {"text": "Complete fixture", "tables": [[["Revenue", "$ 2,513"]]], "table_spans": [[[[1, 1], [1, 1]]]]}
                if kind == "pdf":
                    parsed.update(table_details=[{"source_words": ["Revenue", "$", "2,513"]}], page_diagnostics=[{"page": 1}],
                                  pdf_metadata={"title": "Ex 99_Q3'26"}, pdf_pages_total=1, pdf_pages_processed=1)
                    structure = {key: parsed[key] for key in ("table_details", "page_diagnostics", "pdf_metadata")}
                else:
                    parsed.update(document_format="xlsx", display_complete=True, spreadsheet={"worksheets": [{"cells": [{"raw_value": "2513000000", "display_value": "$ 2,513"}], "merged_ranges": ["A1:B1"]}], "display_complete": True})
                    structure = parsed["spreadsheet"]
                sha = lambda value: hashlib.sha256(value).hexdigest()
                reference = {"url": target["url"], "format": kind, "raw_sha256": sha(raw), **content_hashes(parsed),
                    "table_spans_sha256": sha(json.dumps(parsed["table_spans"], ensure_ascii=False, separators=(",", ":")).encode()),
                    "structure_sha256": sha(json.dumps(structure, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())}
                current.update(target={**target, "reference": reference}, raw=raw, parsed=parsed)
                with patch("probe.subprocess.run", side_effect=collector):
                    row = await collect_watch_case(current["target"], output, {"loc": "US", "colo": "TEST"})
                self.assertTrue(row["complete"])
                self.assertNotIn("error_type", row)
                self.assertTrue(row["reference_raw_matches"] and row["reference_spans_match"] and row["reference_structure_matches"])
                self.assertEqual(row["discovery_to_parsed_ms"], 60)
                self.assertEqual((output / row["raw_document_artifact"]).suffix, "." + kind)
                archived = json.loads((output / ("parsed/" + target["target_id"] + ".json")).read_text(encoding="utf-8"))
                self.assertEqual(archived.get("spreadsheet"), parsed.get("spreadsheet"))
                self.assertNotIn("SECRET_TEST_TOKEN", json.dumps(archived))
                if kind == "xlsx":
                    broken = {**archived, "spreadsheet": {}}
                    self.assertFalse(reference_match(broken, reference)["reference_structure_matches"])
            self.assertEqual(len((output / "results.ndjson").read_text().splitlines()), 2)
            self.assertFalse((output / "materials.ndjson").exists())

    async def test_skyd_range_streams_exact_cover_and_aborts_ignored_range_before_full_transfer(self):
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "skyd-range")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["reference_bytes"], 11841890)
        kkr = select_targets([], "kkr-range-transport")[0]
        self.assertEqual((kkr["reference_bytes"], kkr["range_parts"]), (935929, 4))
        full = b"PK\x03\x04" + bytes(range(256)) * 8192
        state = {}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_HEAD(self):
                case = state["case"]
                case["requests"].append((self.path, None))
                case["connections"].append(("HEAD", self.client_address[1], time.perf_counter()))
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

            def do_GET(self):
                case = state["case"]
                case["requests"].append((self.path, self.headers.get("Range")))
                case["connections"].append(("GET", self.client_address[1], time.perf_counter()))
                if self.path == "/quarterly":
                    data = b"<div><a href='/workbook'>Q3 2026 Trending Schedules</a></div>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers(); self.wfile.write(data)
                    return
                start, end = map(int, self.headers["Range"].removeprefix("bytes=").split("-"))
                data = full if case["ignored"] else full[start:end + 1]
                self.send_response(200 if case["ignored"] else 206)
                self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                self.send_header("Content-Length", str(len(data)))
                if not case["ignored"]:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(full)}")
                    self.send_header("ETag", '"different"' if case["wrong_etag"] and start >= len(full)//2 else '"same"')
                self.end_headers()
                sent = 0
                try:
                    for offset in range(0, len(data), 16384):
                        chunk = data[offset:offset + 16384]
                        self.wfile.write(chunk); self.wfile.flush()
                        sent += len(chunk)
                        time.sleep(.002)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    case["sent"].append(sent)
                    if len(case["sent"]) == case["parts"]:
                        case["finished"].set()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for scope, ignored, wrong_etag in (("skyd-range", False, False), ("skyd-range", True, False),
                                               ("kkr-range-transport", False, False), ("kkr-range-transport", False, True)):
                is_kkr = scope == "kkr-range-transport"
                full = (b"%PDF-1.7\n" if is_kkr else b"PK\x03\x04") + bytes(range(256)) * 8192
                parsed = {"accepted": True, "tables_complete": True, "text": "fixture", "tables": [[["full cell"]]] * 28,
                          "pdf_pages_total": 49, "pdf_pages_processed": 49}
                reference = {**content_hashes(parsed), "raw_sha256": hashlib.sha256(full).hexdigest(),
                             "url": kkr["reference"]["url"], "pdf_pages_total": 49,
                             "structure_sha256": hashlib.sha256(json.dumps({"table_details": None, "page_diagnostics": None,
                                 "pdf_metadata": None}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
                target = {**(kkr if is_kkr else targets[0]), "url": f"http://127.0.0.1:{server.server_port}/workbook",
                          "listing_url": f"http://127.0.0.1:{server.server_port}/quarterly",
                          "warmup_url": f"http://127.0.0.1:{server.server_port}/sdk.js", "reference": reference,
                          "reference_bytes": len(full), "reference_sha256": hashlib.sha256(full).hexdigest()}
                case = {"ignored": ignored, "wrong_etag": wrong_etag, "parts": 4 if is_kkr else 3,
                        "requests": [], "connections": [], "sent": [], "finished": threading.Event()}
                state["case"] = case
                with tempfile.TemporaryDirectory() as directory:
                    args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "outputs", scope=scope)
                    with patch("probe.select_targets", return_value=[target]), \
                            patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST", "is_us": True, "status": 200}), \
                            patch("probe.validate", return_value=parsed) as parse, patch("probe.prewarm_pdf_pool", return_value={"fixture": True}) as warm:
                        self.assertEqual(await run(args), 1 if ignored or wrong_etag else 0)
                    self.assertEqual(parse.call_count, int(is_kkr and not wrong_etag)); self.assertEqual(warm.call_count, int(is_kkr))
                    self.assertTrue(await asyncio.to_thread(case["finished"].wait, 2))
                    count, setup = case["parts"], 4 if is_kkr else 1
                    expected = [f"bytes={i * len(full) // count}-{(i + 1) * len(full) // count - 1}" for i in range(count)]
                    self.assertEqual(case["requests"][:setup], [("/sdk.js" if is_kkr else "/quarterly", None)] * setup)
                    self.assertEqual(sorted(value for path, value in case["requests"][setup:]), sorted(expected))
                    self.assertEqual(len(case["requests"]), setup + count)
                    row = json.loads((args.output / "materials.ndjson").read_text())
                    parts = [json.loads(line) for line in (args.output / "range_parts.ndjson").read_text().splitlines()]
                    self.assertEqual(len(parts), count)
                    self.assertFalse(row["complete"] or row["budget_passed"] or row["tables_complete"])
                    self.assertIsNone(row["discovery_to_parsed_ms"])
                    self.assertFalse((args.output / "results.ndjson").exists())
                    if ignored:
                        self.assertTrue(all(part["status"] == 200 and part["stopped_on_headers"] and not part["http_response_complete"] for part in parts))
                        self.assertTrue(all(sent < len(full) for sent in case["sent"]))
                        self.assertFalse(row["material_download_complete"])
                    elif wrong_etag:
                        self.assertFalse(row["material_download_complete"])
                        self.assertTrue(any(part["stopped_on_headers"] for part in parts))
                    else:
                        self.assertTrue(all(part["status"] == 206 and part["http_response_complete"] for part in parts))
                        self.assertEqual(sum(part["bytes"] for part in parts), len(full))
                        self.assertTrue(row["material_download_complete"])
                        self.assertEqual(row["sha256"], target["reference_sha256"])
                        self.assertEqual((args.output / row["raw_document_artifact"]).read_bytes(), full)
                        self.assertGreaterEqual(row["invocation_to_hashed_download_ms"], max(part["request_total_ms"] for part in parts))
                    if is_kkr:
                        heads = [item for item in case["connections"] if item[0] == "HEAD"]
                        gets = [item for item in case["connections"] if item[0] == "GET"]
                        self.assertEqual(len({item[1] for item in heads}), 4)
                        self.assertEqual({item[1] for item in heads}, {item[1] for item in gets})
                        self.assertGreaterEqual(min(item[2] for item in gets)-max(item[2] for item in heads), .95)
                        if not wrong_etag:
                            self.assertTrue(row["native_reference_verified"])
                            self.assertGreaterEqual(row["invocation_to_parsed_ms"], row["invocation_to_hashed_download_ms"])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    async def test_skyd_materials_archive_two_files_without_financial_acceptance_and_keep_failed_eof(self):
        from contextlib import asynccontextmanager
        from curl_cffi.const import CurlHttpVersion, CurlOpt
        from io import BytesIO
        from probe import execution_hardware
        import zipfile

        cpu_output = json.dumps({"lscpu": [{"field":"Model name:","data":"Neoverse fixture"},
                                           {"field":"Hostname:","data":"SECRET_TEST_HOST"}]})
        with patch("probe.platform.machine", return_value="aarch64"), \
                patch("probe.platform.system", return_value="Linux"), \
                patch("probe.os.cpu_count", return_value=4), \
                patch("probe.subprocess.run", return_value=MagicMock(stdout=cpu_output)):
            hardware = execution_hardware()
        self.assertEqual(hardware, {"machine":"aarch64","logical_cpus":4,"cpu_model":"Neoverse fixture",
                                    "cpu_model_source":"lscpu Model name"})
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "skyd-materials")
        self.assertEqual(len(targets), 2)
        self.assertTrue(all(target["purpose"] == "material_download" for target in targets))
        listing = ("<div class='qr-doc-list'><a href='" + targets[0]["url"] + "'>Q3 2026 Shareholder Letter</a>"
                   "<a href='" + targets[1]["url"] + "'>Q3 2026 Trending Schedules</a></div>").encode()
        pdf = b"%PDF-1.7\nDownloaded evidence only\n%%EOF\n"
        zipped = BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("xl/workbook.xml", "<workbook/>")
        xlsx = zipped.getvalue()
        for scope, interrupted in (("skyd-materials", False), ("skyd-materials", True), ("skyd-http1-material", False)):
            selected_targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), scope)
            if scope == "skyd-http1-material":
                self.assertEqual(len(selected_targets), 1)
                self.assertEqual(selected_targets[0]["url"], targets[1]["url"])
                self.assertEqual(selected_targets[0]["protocol_profile"], "chrome_h1")
            calls = []
            session = MagicMock()
            session.curl_options = {}
            session.__aenter__ = AsyncMock(return_value=session)
            session.__aexit__ = AsyncMock(return_value=False)
            native_timing = {"http_version": "HTTP/1.1" if scope == "skyd-http1-material" else "HTTP/2",
                             "curl_cumulative_ms": {"first_response_byte": 45, "transfer_done": 65},
                             "new_tcp_connections": 0, "connection_reused": True}

            @asynccontextmanager
            async def transfer(client, method, url, headers):
                if scope == "skyd-http1-material":
                    self.assertEqual(client.curl_options[CurlOpt.HTTP_VERSION], CurlHttpVersion.V1_1)
                calls.append((client, method, url))
                if url == targets[0]["listing_url"]:
                    body, kind = listing, "text/html"
                elif url == targets[0]["url"]:
                    body, kind = pdf, "application/pdf"
                else:
                    self.assertEqual(url, targets[1]["url"])
                    if interrupted:
                        raise httpx.ReadError("connection closed before HTTP EOF")
                    body, kind = xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                yield httpx.Response(200, content=body, headers={"content-type": kind}, request=httpx.Request(method, url))

            with tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "outputs", scope=scope)
                with patch("browser_transport.browser_session", return_value=session), \
                        patch("probe.execution_hardware", return_value=hardware), \
                        patch("browser_transport.browser_response", transfer), \
                        patch("browser_transport.browser_timing", return_value=native_timing), \
                        patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST", "is_us": True, "status": 200}), \
                        patch("probe.prewarm_pdf_pool") as warm, patch("probe.validate") as parse:
                    self.assertEqual(await run(args), 1 if interrupted else 0)
                warm.assert_not_called()
                parse.assert_not_called()
                self.assertEqual([call[1:] for call in calls], [("GET", targets[0]["listing_url"])] +
                                 [("GET", target["url"]) for target in selected_targets])
                self.assertTrue(all(call[0] is session for call in calls))
                if scope == "skyd-http1-material":
                    self.assertEqual(session.curl_options[CurlOpt.HTTP_VERSION], CurlHttpVersion.V1_1)
                self.assertFalse((args.output / "results.ndjson").exists())
                rows = [json.loads(line) for line in (args.output / "materials.ndjson").read_text().splitlines()]
                self.assertEqual(len(rows), len(selected_targets))
                for row, target in zip(rows, selected_targets):
                    self.assertEqual(row["purpose"], "material_download")
                    self.assertEqual(row["mode"], "download_only")
                    self.assertFalse(row["complete"] or row["budget_passed"] or row["accepted"] or row["tables_complete"])
                    self.assertIsNone(row["parsed_utc"])
                    self.assertIsNone(row["discovery_to_parsed_ms"])
                    if interrupted and target["material_format"] == "xlsx":
                        self.assertFalse(row["http_response_complete"] or row["material_download_complete"])
                        self.assertEqual(row["error_type"], "ReadError")
                    else:
                        expected = xlsx if target["material_format"] == "xlsx" else pdf
                        self.assertTrue(row["http_response_complete"] and row["material_download_complete"])
                        self.assertTrue(row["raw_document_artifact"].endswith("." + target["material_format"]))
                        self.assertEqual((args.output / row["raw_document_artifact"]).read_bytes(), expected)
                        self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())
                        self.assertEqual(row["bytes"], len(expected))
                        for key, value in native_timing.items():
                            self.assertEqual(row[key], value)
                warmup = json.loads((args.output / "warmup.ndjson").read_text())
                self.assertEqual(warmup["url"], targets[0]["listing_url"])
                self.assertIsNotNone(warmup["request_total_ms"])
                summary = json.loads((args.output / "summary.json").read_text())
                run_metadata = json.loads((args.output / "run.json").read_text())
                self.assertEqual(run_metadata["execution_environment"], hardware)
                self.assertEqual(summary["execution_environment"], hardware)
                self.assertIn("not the runner data-center", run_metadata["node_semantics"])
                self.assertNotIn("SECRET_TEST_HOST", json.dumps(run_metadata))
                self.assertEqual(summary["material_downloaded"], len(selected_targets) - int(interrupted))
                self.assertEqual((summary["complete"], summary["passed"]), (0, 0))
                self.assertFalse(summary["sla_applicable"])

    async def test_lcid_chrome_pair_reuses_each_session_and_stops_on_listing_rejection(self):
        from curl_cffi.const import CurlHttpVersion, CurlOpt
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "lcid-chrome-protocols")
        self.assertTrue(all(row["transport"] == "curl_cffi_chrome" and row["require_raw_reference_match"] for row in targets))
        self.assertEqual(targets[0]["reference"]["pdf_pages_total"], 42)
        for refused in (False, True):
            calls = []
            async def sample(client, target, output, node, recent, blocked):
                version = client.curl_options[CurlOpt.HTTP_VERSION]
                listing = target.get("purpose") == "connection_warmup"
                calls.append((client, target, recent, blocked))
                status = 403 if refused and listing and version == CurlHttpVersion.V2TLS else 200
                row = {"status": status, "http_response_complete": True, "complete": status == 200,
                       "archived": True, "budget_passed": False,
                       "http_version": "HTTP/1.1" if version == CurlHttpVersion.V1_1 else "HTTP/2"}
                if listing:
                    path = "raw/" + target["target_id"] + ".html"
                    (output / path).write_text('<a href="' + targets[0]["url"] + '">Lucid Group Q3 2026 Earnings Presentation</a>')
                    row.update(raw_document_artifact=path, final_url=target["url"], content_type="text/html")
                return row
            with tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "output", scope="lcid-chrome-protocols")
                with patch("probe.prewarm_pdf_pool", return_value={}), \
                        patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST"}), \
                        patch("probe.collect_one", new_callable=AsyncMock, side_effect=sample):
                    self.assertEqual(await run(args), 1 if refused else 0)
                metadata = json.loads((args.output / "summary.json").read_text())
                self.assertEqual(metadata["actual_target_protocols_match_profiles"], not refused)
            self.assertEqual(len(calls), 2 if refused else 4)
            self.assertIsNot(calls[0][0], calls[1][0])
            self.assertTrue(all(call[2] is calls[0][2] and call[3] is calls[0][3] for call in calls))
            if not refused:
                self.assertIs(calls[0][0], calls[2][0]); self.assertIs(calls[1][0], calls[3][0])
                self.assertEqual([call[1]["url"] for call in calls[2:]], [targets[0]["url"]] * 2)
                self.assertTrue(all(call[1]["cache_profile"] == "ordinary" for call in calls[2:]))

    async def test_browser_transport_uses_native_first_byte_and_preserves_403_body(self):
        from browser_transport import browser_session
        text = "Example Corporation revenues net income earnings per share assets cash flows operating income. " * 20
        body = ("<html><h1>Example Corporation Third Quarter 2026 Financial Results</h1><p>" + text +
                "</p><table><tr><td>Revenue</td><td>2026</td><td>2025</td></tr><tr><td>Revenue</td><td>200</td><td>100</td></tr>"
                "<tr><td>Net income</td><td>20</td><td>10</td></tr><tr><td>Cash flows</td><td>30</td><td>15</td></tr></table></html>").encode()
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                denied = self.path == "/denied"
                content = b"Just a moment... Enable JavaScript and cookies" if denied else body
                time.sleep(.02)
                self.send_response(403 if denied else 200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                time.sleep(.03)
                self.wfile.write(content)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory); (output / "raw").mkdir(); (output / "parsed").mkdir()
                target = {**self.target(), "url": f"http://127.0.0.1:{server.server_port}/report",
                          "transport": "curl_cffi_chrome", "cache_profile": "ordinary"}
                async with browser_session() as client:
                    row = await collect_one(client, target, output, {"loc": "TEST", "colo": "LOOPBACK"}, {}, {})
                    self.assertTrue(row["complete"])
                    self.assertIsNone(row["headers_ms"])
                    self.assertIsNone(row["body_ms"])
                    self.assertLess(row["curl_cumulative_ms"]["first_response_byte"], row["curl_cumulative_ms"]["transfer_done"])
                    self.assertGreaterEqual(row["discovery_to_parsed_ms"], 50)
                    self.assertEqual((output / row["raw_document_artifact"]).read_bytes(), body)
                    denied = await collect_one(client, {**target, "target_id": "TEST_denied", "url": target["url"].replace("/report", "/denied")}, output, {"loc": "TEST", "colo": "LOOPBACK"}, {}, {})
                    self.assertEqual(denied["status"], 403)
                    self.assertFalse(denied["complete"])
                    self.assertIn(b"JavaScript", (output / denied["raw_document_artifact"]).read_bytes())
        finally:
            server.shutdown(); server.server_close(); thread.join()

    async def test_alternate_routes_head_only_warms_origin_and_fetches_each_target_once(self):
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "alternate-routes")
        self.assertEqual([(t["event"]["symbol"], t["channel"]) for t in targets], [("BAM", "newswire"), ("MSGK", "official")])
        self.assertEqual(targets[1]["canonical_channel"], "newswire")
        self.assertEqual(targets[1]["document_variant"], "issuer_copy")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); (output / "raw").mkdir(); (output / "parsed").mkdir()
            def head(request):
                self.assertEqual(request.method, "HEAD")
                self.assertEqual(request.url.path, "/")
                return httpx.Response(200, headers={"content-length": "1234"})
            warm = {**targets[0], "url": targets[0]["warmup_url"], "method": "HEAD", "purpose": "connection_warmup"}
            async with httpx.AsyncClient(transport=httpx.MockTransport(head)) as client:
                row = await collect_one(client, warm, output, {"loc": "US", "colo": "TEST"}, {}, {})
            self.assertTrue(row["http_response_complete"])
            self.assertEqual(row["bytes"], 0)
            self.assertFalse(row["complete"])
            self.assertTrue((output / "warmup.ndjson").exists())
            self.assertFalse((output / "results.ndjson").exists())
        for refused in (False, True):
            clients = [MagicMock(), MagicMock()]
            for client in clients:
                client.__aenter__ = AsyncMock(return_value=client)
                client.__aexit__ = AsyncMock(return_value=False)
            async def sample(client, target, *unused):
                is_head = target.get("method") == "HEAD"
                denied = refused and is_head and target["event"]["symbol"] == "BAM"
                return {"status": 403 if denied else 200, "http_response_complete": True,
                        "complete": not is_head, "archived": not is_head, "budget_passed": False}
            with tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "outputs", scope="alternate-routes")
                with patch("probe.httpx.AsyncClient", side_effect=clients), patch("probe.prewarm_pdf_pool", return_value={}), \
                        patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST"}), \
                        patch("probe.collect_one", new_callable=AsyncMock, side_effect=sample) as collect:
                    self.assertEqual(await run(args), 1 if refused else 0)
                called = [call.args[1] for call in collect.await_args_list]
                self.assertEqual(sum(t.get("method") == "HEAD" for t in called), 2)
                self.assertEqual([t["url"] for t in called if t.get("method") != "HEAD"], [t["url"] for t in targets if not refused or t["event"]["symbol"] != "BAM"])

    async def test_remaining_two_use_print_and_one_production_seed_probe(self):
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "remaining-paths")
        self.assertEqual([(x["event"]["symbol"], x["channel"]) for x in targets], [("BAM", "newswire"), ("MSGK", "newswire")])
        self.assertEqual(targets[0]["url"], targets[0]["canonical_url"] + "?print=1")
        self.assertEqual(targets[0]["canonical_previous_status"], 403)
        parsed = {"text": "Full public report", "tables": [[["Revenue", "200"]]]}
        raw = b"<article>Full public report<table><tr><td>Revenue</td><td>200</td></tr></table></article>"
        sha = hashlib.sha256(raw).hexdigest()
        target = {**targets[1], "reference": {"url": targets[1]["url"], "raw_sha256": sha, **content_hashes(parsed)}}
        self.assertFalse(reference_match({**parsed, "tables": []}, target["reference"])["reference_tables_match"])
        eof_proven = [True]
        range_mode = [None]
        expected_base = [BASE]

        def collector(command, **kwargs):
            self.assertEqual(Path(command[1]), expected_base[0] / "live/watch.py")
            self.assertEqual(kwargs["cwd"], expected_base[0] / "live")
            self.assertEqual(command[command.index("--samples") + 1], "1")
            actual = target.get("discovery_route") == "actual_issuer_rss"
            if actual:
                self.assertNotIn("--candidate-url", command)
                self.assertEqual(command[command.index("--channel") + 1], "official")
                manifest = json.loads(Path(command[command.index("--manifest") + 1]).read_text(encoding="utf-8"))
                self.assertEqual(len(manifest[0]["sources"]), 1)
                self.assertEqual(manifest[0]["sources"][0]["url"], "https://investor.msgknicks.com/rss/pressrelease.aspx")
            else:
                self.assertEqual(command[command.index("--candidate-url") + 1], target.get("filing_index_url", target["url"]))
                if target.get("listing_url"):
                    manifest = json.loads(Path(command[command.index("--manifest") + 1]).read_text(encoding="utf-8"))
                    sources = [source for source in manifest[0]["sources"] if source["channel"] == target["channel"]]
                    self.assertTrue(sources)
                    self.assertEqual({source["url"] for source in sources}, {target["listing_url"]})
                    self.assertTrue(all("expected_bytes" not in source and "metadata" not in source for source in sources))
                if target.get("filing_form"):
                    self.assertEqual(command[command.index("--candidate-filing-form") + 1], target["filing_form"])
            if target["channel"] != "sec":
                self.assertNotIn("SEC_USER_AGENT", kwargs["env"])
            runtime = Path(command[command.index("--output") + 1])
            (runtime / "reports").mkdir(); (runtime / "raw").mkdir()
            stem = "reports/MSGK_" + target["channel"] + "_" + sha[:12]
            (runtime / (stem + ".html")).write_bytes(raw)
            (runtime / (stem + ".txt")).write_text(parsed["text"], encoding="utf-8")
            (runtime / (stem + ".json")).write_text(json.dumps({"tables": parsed["tables"], "metadata": {"private": "SECRET_TEST_TOKEN"}}), encoding="utf-8")
            requests = []
            listing = ("<rss><channel><item><title>MSG Knickerbockers Corp. Reports Fiscal 2027 First Quarter Results</title><link>" + target["url"] + "</link></item></channel></rss>").encode() if actual else b"<html>News listing</html>"
            listing_url = "https://investor.msgknicks.com/rss/pressrelease.aspx" if actual else target.get("listing_url", "https://www.businesswire.com/newsroom")
            for purpose, body, url in [("discovery", listing, listing_url), ("candidate", raw, target["url"])]:
                path = "raw/" + purpose + ".gz"
                with gzip.open(runtime / path, "wb") as stream: stream.write(body)
                completed = 100000000 if purpose == "discovery" else 190000000
                requests.append({"id": purpose, "purpose": purpose, "url": url, "status": 200, "raw_path": path,
                                 "queued_mono_ns": 0, "request_total_ms": 50, "queue_ms": 30,
                                 "body_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                                 "body_complete_mono_ns": completed if eof_proven[0] else None,
                                 "request_end_mono_ns": completed,
                                 "response_headers_received_ms": 40, "connection_reused": purpose == "candidate",
                                 "response_headers": {"set-cookie": "SECRET_TEST_TOKEN"}})
            if range_mode[0]:
                parts = []
                for index in range(4):
                    start, stop = len(raw)*index//4, len(raw)*(index+1)//4
                    parts.append({"part": index, "requested_range": f"bytes={start}-{stop-1}",
                        "content_range": f"bytes {start}-{stop-1}/{len(raw)}", "content_length": str(stop-start),
                        "expected_bytes": stop-start, "expected_total_bytes": len(raw), "bytes": stop-start,
                        "sha256": hashlib.sha256(raw[start:stop]).hexdigest(), "status": 206, "etag": '"same-document"',
                        "content_encoding": "identity", "http_response_complete": True, "verified": True,
                        "queued_mono_ns": 140000000, "request_start_mono_ns": 150000000,
                        "eof_mono_ns": 190000000, "request_end_mono_ns": 190000000,
                        "headers": {"set-cookie": "SECRET_TEST_TOKEN"}})
                requests[-1].update(status=206, http_response_complete=False, whole_http_response_complete=False)
                if range_mode[0] == "assembled":
                    requests[-1].update(range_assembly_verified=True, range_expected_bytes=len(raw), range_parts=parts,
                                        http_request_count=4, http_failed_request_count=0)
                else:
                    failed_parts = json.loads(json.dumps(parts))
                    failed_parts[0].update(status=403, verified=False, eof_mono_ns=None, error_type="HTTP_403")
                    requests.insert(1, {"id": "failed-range", "purpose": "candidate", "url": target["url"],
                        "status": None, "error": "RangeAssemblyVerificationError", "range_assembly_verified": False,
                        "range_expected_bytes": len(raw), "range_parts": failed_parts,
                        "http_request_count": 4, "http_failed_request_count": 1})
            capture = {"original_document_path": stem + ".html", "validation": {"accepted": True, "tables_complete": True},
                       "discovery_to_parsed_ms": 100 if actual else 60, "discovered_utc": "2026-11-09T00:00:00.100Z" if actual else "2026-11-09T00:00:00.140Z",
                       "discovered_mono_ns": 100000000 if actual else 140000000, "listing_request_id": "discovery" if actual else None,
                       "validated_utc": "2026-11-09T00:00:00.200Z", "validated_mono_ns": 200000000,
                       "parse_ms": 10, "sha256": sha, "body_bytes": len(raw), "candidate_attempt": 1, "retry": False}
            if target.get("filing_index_url"):
                requests[-1].update(sec_stream_attempt=True, target_document_complete=True,
                                    target_document_url=target["url"], http_response_complete=False)
                audit = b"<html>Later filing index audit, not the financial document</html>"
                with gzip.open(runtime / "raw/audit.gz", "wb") as stream:
                    stream.write(audit)
                requests.append({**requests[-1], "id": "audit", "url": target["filing_index_url"],
                                 "raw_path": "raw/audit.gz", "sha256": hashlib.sha256(audit).hexdigest(),
                                 "body_bytes": len(audit), "sec_stream_attempt": False, "target_document_complete": False})
            with sqlite3.connect(runtime / "observations.sqlite3") as connection:
                connection.execute("create table log(id integer primary key,kind text,payload text)")
                for request in requests: connection.execute("insert into log(kind,payload) values('request',?)", (json.dumps(request),))
                connection.execute("insert into log(kind,payload) values('capture',?)", (json.dumps(capture),))
            connection.close()
            return MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); (output / "raw").mkdir(); (output / "parsed").mkdir()
            with patch("probe.subprocess.run", side_effect=collector):
                row = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertTrue(row["complete"])
            self.assertTrue(row["budget_passed"])
            self.assertEqual(row["discovery_to_parsed_ms"], 60)
            self.assertEqual(row["seed_request_to_parsed_ms"], 200)
            self.assertTrue(row["connection_reused"])
            self.assertFalse(row["seed_listing_contains_candidate"])
            self.assertEqual(row["mode"], "replay")
            self.assertTrue(row["http_response_complete"])
            self.assertEqual((output / row["raw_document_artifact"]).read_bytes(), raw)
            self.assertNotIn("SECRET_TEST_TOKEN", (output / ("requests_" + target["target_id"] + ".ndjson")).read_text())
            expected_base[0] = output / "baseline"
            with patch("probe.subprocess.run", side_effect=collector):
                baseline_row = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"}, collector_base=expected_base[0])
            self.assertTrue(baseline_row["complete"])
            expected_base[0] = BASE
            eof_proven[0] = False
            with patch("probe.subprocess.run", side_effect=collector):
                missing_eof = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertFalse(missing_eof["http_response_complete"])
            self.assertFalse(missing_eof["complete"])
            eof_proven[0] = True
            actual_target = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "msgk-production-issuer")[0]
            target = {**actual_target, "reference": target["reference"]}
            with patch("probe.subprocess.run", side_effect=collector):
                actual = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertTrue(actual["complete"])
            self.assertTrue(actual["seed_listing_contains_candidate"])
            self.assertTrue(actual["discovery_clock_preserved"])
            self.assertEqual(actual["discovery_to_parsed_ms"], 100)
            self.assertEqual(actual["seed_request_to_parsed_ms"], 200)
            self.assertEqual(actual["channel"], "official")
            self.assertEqual(actual["document_variant"], "issuer_copy")
            target = {**targets[1], "channel": "sec", "reference": target["reference"],
                      "filing_index_url": "https://www.sec.gov/Archives/edgar/data/1636519/000163651927000001/0001636519-27-000001-index.html",
                      "filing_form": "8-K"}
            with patch("probe.subprocess.run", side_effect=collector):
                streamed = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertTrue(streamed["complete"])
            self.assertFalse(streamed["http_response_complete"])
            self.assertTrue(streamed["target_document_complete"])
            self.assertEqual(streamed["body_completion_scope"], "complete_exhibit_at_sgml_closing_markers")
            self.assertEqual((output / streamed["raw_document_artifact"]).read_bytes(), raw)
            target = {**targets[1], "listing_url": "https://www.businesswire.com/newsroom?timeline=past",
                      "reference": {**target["reference"], "expected_bytes": 999999, "metadata": {"injected": True}}}
            original_read = Path.read_text
            references = json.loads((BASE / "remaining_references.json").read_text(encoding="utf-8"))
            references["KKR_CURRENT_METRICS_PRODUCTION"]["listing_url"] = target["listing_url"]
            def configured_reference(path, *args, **kwargs):
                return json.dumps(references) if path == BASE / "remaining_references.json" else original_read(path, *args, **kwargs)
            with patch.object(Path, "read_text", configured_reference):
                configured = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "metrics-kkr-complete-sources")
            self.assertEqual(configured[0]["listing_url"], target["listing_url"])
            range_mode[0] = "assembled"
            with patch("probe.subprocess.run", side_effect=collector):
                assembled = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertTrue(assembled["complete"] and assembled["range_assembly_verified"])
            self.assertEqual(assembled["status"], 206)
            self.assertFalse(assembled["http_response_complete"] or assembled["whole_http_response_complete"])
            self.assertEqual(assembled["body_completion_scope"], "verified_four_part_range_assembly")
            self.assertEqual((output / assembled["raw_document_artifact"]).read_bytes(), raw)
            self.assertEqual(assembled["http_request_count"], 4)
            self.assertTrue(assembled["seed_listing_url_matches"])
            self.assertEqual(assembled["seed"]["url"], "https://www.businesswire.com/newsroom")
            safe_requests = (output / ("requests_" + target["target_id"] + ".ndjson")).read_text()
            self.assertNotIn("SECRET_TEST_TOKEN", safe_requests)
            self.assertEqual(json.loads(safe_requests.splitlines()[-1])["range_parts"][3]["eof_mono_ns"], 190000000)
            range_mode[0] = "standalone"
            with patch("probe.subprocess.run", side_effect=collector):
                standalone = await collect_watch_case(target, output, {"loc": "US", "colo": "TEST"})
            self.assertFalse(standalone["complete"] or standalone["http_response_complete"]
                             or standalone["whole_http_response_complete"] or standalone["range_assembly_verified"])
            safe_requests = [json.loads(line) for line in (output / ("requests_" + target["target_id"] + ".ndjson")).read_text().splitlines()]
            failed_range = next(request for request in safe_requests if request["id"] == "failed-range")
            self.assertEqual(failed_range["http_request_count"], 4)
            self.assertEqual(failed_range["http_failed_request_count"], 1)
            self.assertEqual(failed_range["range_parts"][0]["status"], 403)

    async def test_cache_profiles_keep_download_trace_and_stop_after_rejection(self):
        targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "msgk-cache-control")
        self.assertEqual([row["cache_profile"] for row in targets], ["no_cache", "ordinary"])
        self.assertEqual(targets[0]["url"], targets[1]["url"])
        reversed_targets = select_targets(json.loads((BASE / "targets.json").read_text(encoding="utf-8")), "msgk-cache-control-reverse")
        self.assertEqual(reversed_targets, list(reversed(targets)))
        for profile in ("no_cache", "ordinary"):
            async def response(request):
                self.assertEqual(request.headers.get("cache-control"), "no-cache" if profile == "no_cache" else None)
                trace = request.extensions["trace"]
                await trace("connection.connect_tcp.started", {})
                await asyncio.sleep(.001)
                await trace("connection.connect_tcp.complete", {})
                return httpx.Response(403, content=b"Denied", headers={"age": "10", "set-cookie": "PRIVATE_COOKIE"})
            row = await self.execute(response, {**self.target(), "cache_profile": profile})
            self.assertFalse(row["connection_reused"])
            self.assertGreater(row["transport_trace_ms"]["connection.connect_tcp"], 0)
            self.assertEqual(row["response_cache_headers"], {"age": "10"})
        clients = [MagicMock(), MagicMock()]
        for client in clients:
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "outputs", scope="msgk-cache-control")
            with patch("probe.httpx.AsyncClient", side_effect=clients), patch("probe.prewarm_pdf_pool", return_value={}), \
                    patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST"}), \
                    patch("probe.collect_one", new_callable=AsyncMock, return_value={"status": 403, "http_response_complete": True}) as collect:
                self.assertEqual(await run(args), 1)
                collect.assert_awaited_once()
                self.assertEqual(collect.await_args.args[1]["url"], "https://www.businesswire.com/")

    async def test_sec_hosts_share_eight_request_budget(self):
        clock = [.25]
        recent = {"sec.gov": deque([0.] * 7)}

        async def sleep(delay):
            clock[0] += delay

        with patch("probe.time.perf_counter", side_effect=lambda: clock[0]), patch("probe.asyncio.sleep", new_callable=AsyncMock, side_effect=sleep) as wait:
            await pace("https://www.sec.gov/one", recent, {})
            wait.assert_not_awaited()
            self.assertEqual(len(recent["sec.gov"]), 8)
            await pace("https://data.sec.gov/two", recent, {})
            wait.assert_awaited_once_with(.75)

    async def test_run_keeps_businesswire_on_one_separate_http1_client(self):
        clients = [MagicMock(), MagicMock()]
        for client in clients:
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(targets=BASE / "targets.json", output=Path(directory) / "outputs", scope="sec-businesswire")
            with patch("probe.httpx.AsyncClient", side_effect=clients) as factory, \
                    patch("probe.prewarm_pdf_pool", return_value={"workers": 0}), \
                    patch("probe.identify_node", new_callable=AsyncMock, return_value={"loc": "US", "colo": "TEST", "is_us": True}), \
                    patch("probe.collect_one", new_callable=AsyncMock, return_value={"complete": True, "archived": True, "budget_passed": False}) as collect:
                self.assertEqual(await run(args), 0)
            self.assertTrue(factory.call_args_list[0].kwargs["http2"])
            self.assertFalse(factory.call_args_list[1].kwargs["http2"])
            self.assertEqual(collect.await_count, 13)
            for call in collect.await_args_list:
                expected = clients[0] if call.args[1]["channel"] == "sec" else clients[1]
                self.assertIs(call.args[0], expected)

    def test_manifest_filters_keep_only_eleven_sec_and_two_businesswire(self):
        targets = json.loads((BASE / "targets.json").read_text(encoding="utf-8"))
        self.assertEqual(len(select_targets(targets, "all")), 19)
        self.assertEqual(len(select_targets(targets, "sec")), 11)
        selected = select_targets(targets, "sec-businesswire")
        self.assertEqual(len(selected), 13)
        self.assertEqual(sum(row["channel"] == "sec" for row in selected), 11)
        self.assertEqual({row["event"]["symbol"] for row in selected if row["channel"] != "sec"}, {"MSGK", "MSGR"})
        pdf = select_targets(targets, "bam-pdf")
        self.assertEqual(len(pdf), 1)
        self.assertTrue(pdf[0]["url"].endswith("brookfield-asset-management-announces-strong.pdf"))
        self.assertNotEqual(pdf[0]["canonical_url"], pdf[0]["url"])
        self.assertEqual(pdf[0]["document_variant"], "official_pdf_alternative")
        self.assertEqual(pdf[0]["canonical_previous_status"], 403)
        self.assertEqual(pdf[0]["reference"]["pdf_pages_total"], 10)
        self.assertEqual(len(pdf[0]["reference"]["financial_row_sha256"]), 6)
        issuer = select_targets(targets, "msgk-issuer-cold")
        self.assertEqual(len(issuer), 1)
        self.assertEqual((issuer[0]["event"]["symbol"], issuer[0]["channel"]), ("MSGK", "official"))
        self.assertNotIn("warmup_url", issuer[0])
        self.assertTrue(issuer[0]["http1"])
        browser = select_targets(targets, "msgk-browser-transport")
        self.assertEqual([target["channel"] for target in browser], ["newswire", "official"])
        self.assertTrue(all(target["transport"] == "curl_cffi_chrome" and "warmup_url" not in target for target in browser))

    def test_exchange_target_replay_uses_actual_channels_and_historical_periods(self):
        selected = select_targets([], "metrics-exchange-targets")
        self.assertEqual([(row["event"]["symbol"], row["channel"], row["event"]["quarter"])
                          for row in selected], [("CSCO", "sec", 4), ("NBIS", "sec", 2), ("CBRS", "official", 2)])
        for row in selected:
            self.assertEqual(row["event"]["period_end"], row["reference"]["event_override"]["period_end"])
            self.assertEqual(row["pipeline"], "production_watch_list_seed")
            self.assertEqual(row["metrics_mode"], "synthetic")
            self.assertIn("table_spans_sha256", row["reference"])
            self.assertTrue(row["reference"]["table_sha256"])

    def test_coverage_replay_includes_every_configured_metric_company(self):
        from probe import main

        for scope in ("metrics-22-coverage", "metrics-unresolved-paths", "metrics-ncmi-issuer", "metrics-all-supported"):
            with patch("sys.argv", ["probe.py", "--scope", scope]), \
                    patch("probe.run", new_callable=AsyncMock, return_value=0) as execute:
                with self.assertRaises(SystemExit) as exit_result:
                    main()
            self.assertEqual(exit_result.exception.code, 0)
            self.assertEqual(execute.call_args.args[0].scope, scope)
        expected = set("ONON SE QBTS TDG MRDN NCMI RGTI GIB FNV BN NBIS CBRS CSCO XPEV BIDU BEKE HTHT ARMK TSN ACM INFQ STEM".split())
        selected = select_targets([], "metrics-22-coverage")
        assert len(selected) == 22
        assert {row["event"]["symbol"] for row in selected} == expected
        assert all(row["metrics_mode"] == "synthetic" and row["pipeline"] == "production_watch_list_seed" for row in selected)
        nbis = next(row for row in selected if row["event"]["symbol"] == "NBIS")
        assert nbis["channel"] == "sec" and nbis["reference"]["uses_same_quarter_alternate"]
        assert all(row["reference"].get("table_spans_sha256") for row in selected)
        repaired = {row["event"]["symbol"]: row for row in select_targets([], "metrics-unresolved-paths")}
        assert set(repaired) == {"SE", "NCMI", "RGTI", "CBRS", "BIDU"}
        assert repaired["SE"]["filing_form"] == "6-K" and repaired["NCMI"]["filing_form"] == "8-K"
        assert repaired["RGTI"]["channel"] == "official"
        all_supported = select_targets([], "metrics-all-supported")
        assert len(all_supported) == 44
        assert {row["event"]["symbol"] for row in all_supported} == {event["symbol"] for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        scheduled = {event["symbol"]: event for event in json.loads((BASE / "live/watchlist.json").read_text(encoding="utf-8"))}
        assert sum(all(row["event"][key] == scheduled[row["event"]["symbol"]][key]
                       for key in ("period_start", "period_end")) for row in all_supported) == 29
        coverage = {row["event"]["symbol"]: row for row in selected}
        assert all(coverage[symbol]["reference"] == row["reference"] for symbol, row in repaired.items())

    def test_reference_text_variants_accept_only_exact_sec_wrapper_and_body(self):
        base = {"text": "Third quarter results Revenue 100 Net income 20",
                "tables": [[["Revenue", "100"], ["Net income", "20"]]],
                "table_spans": [[[[1, 1], [1, 1]], [[1, 1], [1, 1]]]]}
        prefix = "EX-99.1 2 d141003dex991.htm EX-99.1 "
        wrapped = {**base, "text": prefix + base["text"]}
        reference = {"url": "https://www.sec.gov/Archives/edgar/data/756894/000119312526441663/d141003dex991.htm",
                     "raw_sha256": "fixture", **content_hashes(base),
                     "text_sha256_variants": [hashlib.sha256((prefix + base["text"]).encode()).hexdigest()],
                     "table_spans_sha256": hashlib.sha256(json.dumps(base["table_spans"], separators=(",", ":")).encode()).hexdigest()}
        for parsed in (base, wrapped):
            matched = reference_match(parsed, reference)
            self.assertTrue(matched["reference_text_matches"])
            self.assertTrue(matched["reference_tables_match"] and matched["reference_spans_match"])
        changed_body = {**wrapped, "text": wrapped["text"].replace("Revenue 100", "Revenue 101")}
        self.assertFalse(reference_match(changed_body, reference)["reference_text_matches"])
        self.assertFalse(reference_match({**wrapped, "tables": [[["Revenue", "101"]]]}, reference)["reference_tables_match"])
        self.assertFalse(reference_match({**wrapped, "table_spans": [[[[1, 2]]]]}, reference)["reference_spans_match"])

    def test_ncmi_issuer_scope_is_single_historical_official_target_and_requires_reference(self):
        selected = select_targets([], "metrics-ncmi-issuer")
        self.assertEqual(len(selected), 1)
        target = selected[0]
        self.assertEqual((target["event"]["symbol"], target["channel"], target["event"]["quarter"]), ("NCMI", "official", 2))
        self.assertEqual(target["event"]["period_end"], "2026-07-02")
        self.assertEqual(target["url"], "https://nationalcinemedia.gcs-web.com/news-releases/news-release-details/national-cinemedia-inc-reports-results-fiscal-second-quarter-15")
        self.assertEqual(target["pipeline"], "production_watch_list_seed")
        self.assertEqual(target["metrics_mode"], "synthetic")
        self.assertNotIn("filing_index_url", target)
        self.assertNotIn("connection_warmup_url", target["reference"])
        pending = {**target["reference"], "raw_sha256": None, "text_sha256": None, "table_sha256": None}
        comparison = reference_match({"text": "Untested report", "tables": [[['Revenue', '100']]], "table_spans": []}, pending)
        self.assertFalse(comparison["reference_text_matches"])
        self.assertFalse(comparison["reference_tables_match"])

    def target(self):
        return {"target_id": "TEST_official", "channel": "official", "url": "https://example.com/report",
                "event": {"symbol": "TEST", "company": "Example Corporation", "aliases": ["Example Corporation"],
                          "quarter": 3, "fiscal_year": 2026, "period_end": "2026-09-30",
                          "sources": [{"channel": "official", "url": "https://example.com/news"}]}}

    async def execute(self, handler, target=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "raw").mkdir(); (output / "parsed").mkdir()
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                row = await collect_one(client, target or self.target(), output, {"loc": "US", "colo": "TEST", "is_us": True}, {}, {})
            evidence = json.loads((output / "results.ndjson").read_text(encoding="utf-8"))
            self.assertEqual(row, evidence)
            self.assertEqual(row["mode"], "replay")
            self.assertFalse(row["new_release_evidence"])
            return row

    async def test_download_delay_is_inside_complete_parse_clock(self):
        text = "Example Corporation revenues net income earnings per share assets cash flows operating income. " * 20
        body = ("<html><h1>Example Corporation Third Quarter 2026 Financial Results</h1><p>" + text +
                "</p><table><tr><td>Revenue</td><td>2026</td><td>2025</td></tr>" +
                "<tr><td>Revenue</td><td>200</td><td>100</td></tr>" +
                "<tr><td>Net income</td><td>20</td><td>10</td></tr>" +
                "<tr><td>Cash flows</td><td>30</td><td>15</td></tr></table></html>").encode()

        async def response(request):
            self.assertEqual(request.headers["User-Agent"], "Example Company developer@example.invalid")
            await asyncio.sleep(.02)
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})

        target = self.target()
        target.update(url="https://www.sec.gov/Archives/edgar/data/123/report.htm", channel="sec")
        with patch.dict(os.environ, {"SEC_USER_AGENT": "Example Company developer@example.invalid"}):
            row = await self.execute(response, target)
        self.assertTrue(row["complete"])
        self.assertTrue(row["http_response_complete"])
        self.assertTrue(row["archived"])
        self.assertEqual(row["table_count"], 1)
        self.assertGreaterEqual(row["discovery_to_parsed_ms"], 20)
        self.assertGreaterEqual(row["discovery_to_parsed_ms"], row["request_total_ms"] + row["parse_ms"])

    async def test_network_failure_retains_elapsed_time_without_parse_success(self):
        async def failure(request):
            await asyncio.sleep(.02)
            raise httpx.ConnectTimeout("timeout peer 203.0.113.1 https://example.com/private?token=SECRET token=SECRET")

        row = await self.execute(failure)
        self.assertEqual(row["error_type"], "ConnectTimeout")
        self.assertGreaterEqual(row["invocation_to_end_ms"], 20)
        self.assertIsNone(row["discovery_to_parsed_ms"])
        self.assertFalse(row["complete"])
        self.assertFalse(row["budget_passed"])
        self.assertNotIn("203.0.113.1", row["error_message"])
        self.assertNotIn("SECRET", row["error_message"])
        self.assertNotIn("/private", row["error_message"])

    async def test_sec_without_declared_identity_makes_no_request(self):
        requested = []

        async def unexpected_request(request):
            requested.append(request)
            raise AssertionError("SEC must be skipped without its declared identity")

        target = self.target()
        target.update(url="https://www.sec.gov/Archives/edgar/data/123/report.htm", channel="sec")
        with patch.dict(os.environ, {"SEC_USER_AGENT": ""}):
            row = await self.execute(unexpected_request, target)
        self.assertEqual(requested, [])
        self.assertEqual(row["error_type"], "identity_missing")
        self.assertTrue(row["request_skipped"])
        self.assertEqual(row["attempts"], 0)
        self.assertIsNone(row["discovery_to_parsed_ms"])
        self.assertFalse(row["budget_passed"])


class LiveExportTest(unittest.TestCase):
    def test_public_snapshot_keeps_report_bytes_and_excludes_private_log_fields(self):
        from live.run_live import snapshot
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, published = root / "runtime", root / "public"
            (runtime / "reports").mkdir(parents=True)
            published.mkdir()
            raw = b"<html><h1>Example</h1><table><tr><td>Revenue</td><td>123</td></tr></table></html>"
            sha = hashlib.sha256(raw).hexdigest()
            stem = "reports/TEST_official_" + sha[:12]
            (runtime / (stem + ".html")).write_bytes(raw)
            (runtime / (stem + ".txt")).write_text("Example Revenue 123", encoding="utf-8")
            (runtime / (stem + ".json")).write_text(json.dumps({"tables": [[["Revenue", "123"]]],
                "metadata": {"authorization": "SECRET_TEST_TOKEN", "user_agent": "Example secret@example.invalid"}}), encoding="utf-8")
            with sqlite3.connect(runtime / "observations.sqlite3") as connection:
                connection.execute("create table log(id integer primary key,kind text,symbol text,channel text,at_ns integer,payload text)")
                capture = {"run_id": "collector-test", "symbol": "TEST", "channel": "official", "mode": "run",
                           "url": "https://example.com/report", "sha256": sha, "original_document_path": stem + ".html",
                           "discovered_utc": "2026-11-09T10:00:00+00:00", "validated_utc": "2026-11-09T10:00:00.025+00:00",
                           "already_present_on_first_poll": False, "discovery_to_parsed_ms": 25,
                           "last_negative_listing_ns": 1794218399800000000,
                           "last_negative_listing_mono_ns": 1000000000,
                           "discovered_mono_ns": 1200000000, "validated_mono_ns": 1225000000,
                           "validation": {"accepted": True, "tables_complete": True},
                           "response_headers": {"set-cookie": "SECRET_TEST_TOKEN"}, "private_path": r"C:\Users\private\secret"}
                connection.execute("insert into log values(1,'capture','TEST','official',1,?)", (json.dumps(capture),))
                connection.execute("insert into log values(2,'request','TEST','official',2,?)", (json.dumps({"status": None,"error": "ConnectError: SECRET_TEST_TOKEN"}),))
            connection.close()
            metadata = {"run_id": "123-1", "node": {"loc": "US", "colo": "TEST"}, "state": "running"}
            with patch.dict(os.environ, {"SEC_USER_AGENT": "Example secret@example.invalid", "GITHUB_TOKEN": "SECRET_TEST_TOKEN"}):
                data = snapshot(runtime.resolve(), published, metadata, {})
            rendered = json.dumps(data)
            self.assertNotIn("SECRET_TEST_TOKEN", rendered)
            self.assertNotIn("secret@example.invalid", rendered)
            self.assertNotIn("response_headers", rendered)
            self.assertNotIn("private_path", rendered)
            self.assertEqual(data["captures"][0]["context"], "live")
            self.assertEqual(data["captures"][0]["discovery_to_parsed_ms"], 25)
            self.assertEqual(data["failure_groups"][0]["failure_type"], "ConnectError")
            self.assertEqual((published / (stem + ".html")).read_bytes(), raw)
            parsed = json.loads((published / (stem + ".json")).read_text(encoding="utf-8"))
            self.assertEqual(set(parsed), {"text", "tables"})
            self.assertTrue(all(hashlib.sha256((published / a["path"]).read_bytes()).hexdigest() == a["sha256"]
                                for a in data["captures"][0]["artifacts"]))
            (runtime / (stem + ".html")).write_bytes(raw + b"changed")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                snapshot(runtime.resolve(), published, metadata, {})


if __name__ == "__main__":
    unittest.main()
