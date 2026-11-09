import asyncio
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from probe import BASE, collect_one, pace, run, select_targets


class ProbeTimingTest(unittest.IsolatedAsyncioTestCase):
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
