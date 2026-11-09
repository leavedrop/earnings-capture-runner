import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from probe import BASE, collect_one, select_targets


class ProbeTimingTest(unittest.IsolatedAsyncioTestCase):
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


if __name__ == "__main__":
    unittest.main()
