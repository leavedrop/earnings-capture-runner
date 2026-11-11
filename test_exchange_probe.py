import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import exchange_probe as probe


class PublicQuoteTest(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, mismatch=False):
        clock = [0]
        sent = []

        class Socket:
            response = SimpleNamespace(status_code=101)

            async def send(self, wire):
                sent.append(json.loads(wire))

            async def recv(self):
                clock[0] += 20_000_000
                request = sent[-1]
                return json.dumps({"id": "wrong-id" if mismatch and len(sent) == 1 else request["id"],
                                   "status": 200, "result": {"symbol": request["params"]["symbol"], "price": "98.70000"}})

        class Connection:
            async def __aenter__(self):
                clock[0] += 2_000_000_000
                return Socket()

            async def __aexit__(self, *args):
                return False

        async def sleep(seconds):
            clock[0] += round(seconds * 1e9)

        with TemporaryDirectory() as folder:
            output = Path(folder)
            requests, results = [], []
            with patch.object(probe, "connect", return_value=Connection()) as connection, \
                    patch.object(probe.time, "perf_counter_ns", side_effect=lambda: clock[0]), \
                    patch.object(probe.asyncio, "sleep", side_effect=sleep):
                handshake = await probe.collect_quotes(output, requests, results)
            connection.assert_called_once_with(probe.WS_URL, proxy=None, open_timeout=20, close_timeout=3, ping_interval=None)
            stored = json.loads((output / "results.json").read_text())
        self.assertEqual(len(sent), 9)
        self.assertEqual(len({row["id"] for row in sent}), 9)
        self.assertEqual({row["method"] for row in sent}, {"ticker.price"})
        self.assertTrue(all(set(row) == {"id", "method", "params"} for row in sent))
        return handshake, stored

    async def test_id_mismatch_is_preserved_as_failure(self):
        _, rows = await self.exercise(mismatch=True)
        self.assertFalse(rows[0]["public_quote_verified"])
        self.assertEqual(rows[0]["failure_type"], "response_contract_mismatch")
        self.assertEqual(rows[0]["response"]["id"], "wrong-id")
        self.assertEqual(sum(row["public_quote_verified"] for row in rows), 8)

    async def test_cold_handshake_and_pacing_are_separate_from_warm_response(self):
        handshake, rows = await self.exercise()
        self.assertEqual(handshake["total_ms"], 2000)
        self.assertTrue(all(row["request_response_ms"] == 20 for row in rows))
        self.assertTrue(all(row["request_to_validation_ms"] == 20 for row in rows))
        starts = [row["started_mono_ns"] for row in rows]
        self.assertTrue(all(b - a >= 300_000_000 for a, b in zip(starts, starts[1:])))
        self.assertTrue(all(row["public_quote_verified"] for row in rows))


if __name__ == "__main__":
    unittest.main()
