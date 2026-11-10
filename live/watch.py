"""Public earnings observation: persistent raw evidence and explicit clock semantics."""
from __future__ import annotations

import argparse
import asyncio
import base64
from collections import deque
import csv
import gzip
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
from pathlib import Path
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urljoin
import uuid

import httpx

BASE = Path(__file__).resolve().parent
UTC = timezone.utc
BJ = timezone(timedelta(hours=8))
LATENCY_BUDGET_MS = 300


def iso(ns: int | None) -> str | None:
    if ns is None:
        return None
    dt = datetime.fromtimestamp(ns / 1e9, UTC)
    return dt.isoformat(timespec="microseconds")


def epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def atomic_json(path: Path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


class Clock:
    def __init__(self):
        self.state = {"verified": False, "offset_ms": None, "uncertainty_ms": None,
                      "method": "uncalibrated_system_clock"}

    def stamp(self):
        raw = time.time_ns()
        offset = self.state.get("offset_ms")
        return raw, raw + round((offset or 0) * 1e6)

    def calibrate(self):
        samples = []
        for host in ("ntp.aliyun.com", "time.cloudflare.com", "time.windows.com"):
            try:
                packet = bytearray(48)
                packet[0] = 0x23
                t1 = time.time()
                ntp = t1 + 2208988800
                struct.pack_into("!II", packet, 40, int(ntp), int((ntp % 1) * 2**32))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1.5)
                    sock.sendto(packet, (host, 123))
                    reply, _ = sock.recvfrom(512)
                t4 = time.time()
                if len(reply) < 48 or reply[0] >> 6 == 3 or reply[0] & 7 != 4 or not 1 <= reply[1] <= 15:
                    raise ValueError("invalid/unsynchronized NTP response")
                if reply[24:32] != packet[40:48]:
                    raise ValueError("NTP originate mismatch")
                def ts(at):
                    sec, frac = struct.unpack_from("!II", reply, at)
                    return sec - 2208988800 + frac / 2**32
                t2, t3 = ts(32), ts(40)
                rtt = max(0, (t4 - t1) - (t3 - t2))
                delay = struct.unpack_from("!i", reply, 4)[0] / 65536
                dispersion = struct.unpack_from("!I", reply, 8)[0] / 65536
                samples.append({"server": host, "offset_ms": ((t2-t1)+(t3-t4))*500,
                                "rtt_ms": rtt*1000,
                                "uncertainty_ms": (rtt/2 + abs(delay)/2 + dispersion)*1000})
            except Exception as exc:
                samples.append({"server": host, "error": str(exc)})
        valid = [s for s in samples if "offset_ms" in s]
        if valid:
            best = min(valid, key=lambda s: s["rtt_ms"])
            # Include disagreement between servers, not just packet RTT precision.
            uncertainty = max(best["uncertainty_ms"], max(abs(s["offset_ms"]-best["offset_ms"]) for s in valid))
            self.state = {"verified": True, **best, "uncertainty_ms": uncertainty,
                          "method": "SNTP_estimate_no_OS_clock_change",
                          "calibrated_raw_utc": iso(time.time_ns()), "samples": samples}
        else:
            self.state = {"verified": False, "offset_ms": None, "uncertainty_ms": None,
                          "method": "uncalibrated_system_clock", "samples": samples}
        return self.state


class Store:
    def __init__(self, directory: Path):
        self.root = directory
        self.root.mkdir(parents=True, exist_ok=True)
        (directory / "raw").mkdir(exist_ok=True)
        (directory / "reports").mkdir(exist_ok=True)
        self.db = sqlite3.connect(directory / "observations.sqlite3")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, kind TEXT, symbol TEXT,
            channel TEXT, at_ns INTEGER, payload TEXT);
          CREATE INDEX IF NOT EXISTS log_kind ON log(kind,symbol,channel);
        """)
        self.db.commit()

    def add(self, kind, payload, connection=None):
        connection = self.db if connection is None else connection
        connection.execute("INSERT INTO log(kind,symbol,channel,at_ns,payload) VALUES(?,?,?,?,?)",
                           (kind, payload.get("symbol"), payload.get("channel"), time.time_ns(),
                            json.dumps(payload, ensure_ascii=False)))
        connection.commit()

    def archive_request(self, record, body):
        # This runs off the event loop. SQLite connections remain thread-owned.
        if record.get("raw_path"):
            self.raw(body)
        record = {**record, "evidence_persisted_mono_ns": time.perf_counter_ns()}
        with sqlite3.connect(self.root / "observations.sqlite3") as connection:
            connection.execute("PRAGMA synchronous=NORMAL")
            self.add("request", record, connection)

    def raw(self, body):
        digest = hashlib.sha256(body).hexdigest()
        dest = self.root / "raw" / (digest + ".gz")
        if not dest.exists():
            with gzip.open(dest, "wb") as fh:
                fh.write(body)
        return digest, str(dest.relative_to(self.root))

    def records(self, kind):
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT payload FROM log WHERE kind=? ORDER BY id", (kind,))]


class RateLimit:
    """One shared SEC budget includes listing, index, documents, and retries."""
    def __init__(self, sec_rps=8):
        self.sec_rps = sec_rps
        self.locks = {}
        self.next = {}
        self.blocked = {}
        self.blocked_paths = {}
        self.recent = {}
        self.waiters = {}
        self.changed = {}

    @staticmethod
    def key(url):
        host = urlsplit(url).hostname or ""
        if host == "sec.gov" or host.endswith(".sec.gov"):
            return "sec.gov"
        for wire in ("businesswire.com", "prnewswire.com", "globenewswire.com"):
            if host == wire or host.endswith("." + wire):
                return wire
        return host

    async def wait(self, url, purpose="discovery", *, discovery_interval=None):
        key = self.key(url)
        path_key = (key, urlsplit(url).path or "/")
        pacing = max(0.25, 1/max(1, self.sec_rps-1)) if key == "sec.gov" else (max(1/3, discovery_interval) if discovery_interval is not None else 1.0)
        reasons = set()
        # Listing probes retain their pacing. Newly discovered documents can use
        # reserved capacity immediately, within a single rolling host budget.
        limit = self.sec_rps if key == "sec.gov" else 4
        pending = self.waiters.setdefault(key, deque())
        waiter = (object(), path_key, purpose)
        pending.append(waiter)
        try:
            while True:
                async with self.locks.setdefault(key, asyncio.Lock()):
                    now = time.monotonic()
                    recent = self.recent.setdefault(key, deque())
                    while recent and recent[0] <= now-1:
                        recent.popleft()
                    constraints = {"host_cooldown": self.blocked.get(key, 0),
                                   "path_cooldown": self.blocked_paths.get(path_key, 0)}
                    if purpose == "discovery":
                        constraints["listing_pacing"] = self.next.get(key, 0)
                    if len(recent) >= limit:
                        constraints["shared_rolling_budget"] = recent[0]+1
                    remaining = max(constraints.values())-now
                    if remaining <= 0:
                        # Keep arrival order across sleeps. A denied path must
                        # not hold up another ready path, and ready documents
                        # retain priority over discovery within the same budget.
                        ready = [item for item in pending
                                 if self.blocked_paths.get(item[1], 0) <= now
                                 and (item[2] != "discovery" or self.next.get(key, 0) <= now)]
                        first = next((item for item in ready if item[2] != "discovery"), ready[0])
                        if first is waiter:
                            recent.append(now)
                            if purpose == "discovery":
                                self.next[key] = now + pacing
                            return {"queue_reasons": sorted(reasons)}
                        reasons.add("fair_queue")
                        changed = self.changed.setdefault(key, asyncio.Event())
                    else:
                        reasons.update(name for name, until in constraints.items() if until > now)
                # Eligibility deadlines only move later. Sleep until this
                # request can run, or await a queue change if another is first.
                if remaining > 0:
                    await asyncio.sleep(remaining)
                else:
                    await changed.wait()
        finally:
            pending.remove(waiter)
            self._notify(key)

    def _notify(self, key):
        changed = self.changed.pop(key, None)
        if changed is not None:
            changed.set()

    def cooldown(self, url, seconds, *, path_only=False):
        key = self.key(url)
        blocks = self.blocked_paths if path_only else self.blocked
        if path_only:
            key = (key, urlsplit(url).path or "/")
        blocks[key] = max(blocks.get(key, 0), time.monotonic() + seconds)
        self._notify(self.key(url))


class Collector:
    def __init__(self, args):
        self.args = args
        self.store = Store(Path(args.output))
        self.clock = Clock()
        self.rate = RateLimit(getattr(args, "sec_rps", 8))
        self.run_id = str(uuid.uuid4())
        self.proxy = args.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("ALL_PROXY")
        self.status = {}
        self.completed = {(x["symbol"], x["channel"]) for x in self.store.records("capture") if x.get("mode", "run") == "run"}
        self.captured_documents = {(r["symbol"], r["channel"], r.get("target_document_url", r.get("final_url", r["url"])))
                                   for r in self.store.records("capture") if r.get("mode", "run") == "run"}
        self.captured_documents.update((r["symbol"], r["channel"], r["url"])
                                       for r in self.store.records("inherited_document"))
        self.inspected_documents = {(r["symbol"], r["channel"], r.get("final_url", r["url"]))
                                    for r in self.store.records("attachment") if r.get("mode", "run") == "run"}
        self.cache = {}
        self.candidate_retry = {}
        self.active_candidates = set()
        self.first_discovered = {}
        self.candidate_attempts = {}
        self.child_tasks = set()
        self.archive_tasks = set()
        self.stop = asyncio.Event()
        self.sec_stream_session = None
        self.browser_session = None
        self.kkr_public_client = None

    async def kkr_authorization(self, session, event, record):
        """Reproduce the issuer's public browser client; retain keys only in memory."""
        if self.kkr_public_client is None:
            config_url = next(source["public_client_config_url"] for source in event["sources"]
                              if source.get("public_client_config_url"))
            started = time.perf_counter_ns()
            response = await session.get(config_url, follow_redirects=False,
                                         headers={"User-Agent": "EarningsWatch/1.0 automated-public-filings-research"})
            record["public_client_initialization_ms"] = (time.perf_counter_ns()-started)/1e6
            self.store.add("public_client_init", {"symbol": event["symbol"], "channel": "official",
                           "run_id": self.run_id, "mode": self.args.command, "url": config_url,
                           "status": response.status_code, "body_bytes": len(response.content),
                           "sha256": hashlib.sha256(response.content).hexdigest(),
                           "elapsed_ms": record["public_client_initialization_ms"],
                           "body_not_archived": "public client credentials are held only in memory"})
            if response.status_code != 200:
                raise ValueError(f"KKR public configuration HTTP {response.status_code}")
            values = {match[1]: json.loads(match[2]) for match in re.finditer(
                r'(?:const |,)([A-Za-z_$][\w$]*)=("(?:\\.|[^"\\])*")', response.text)}
            fields = {match[1]: values.get(match[2]) for match in re.finditer(
                r'(PUBLIC_[A-Z0-9_]+):([A-Za-z_$][\w$]*)', response.text)}
            if (fields.get("PUBLIC_API_ENDPOINT") != "https://tools.cms-eqs.com"
                    or fields.get("PUBLIC_API_PREFIX") != "fcf5b4"
                    or not fields.get("PUBLIC_AUTH_JWT_KEY") or not fields.get("PUBLIC_AUTH_JWT_SECRET")):
                raise ValueError("KKR public configuration does not match the verified issuer API")
            self.kkr_public_client = (fields["PUBLIC_AUTH_JWT_KEY"], fields["PUBLIC_AUTH_JWT_SECRET"])
        key, secret = self.kkr_public_client
        def encode(value):
            return base64.urlsafe_b64encode(value).rstrip(b"=")
        unsigned = encode(b'{"alg":"HS256","typ":"JWT"}') + b"." + encode(json.dumps(
            {"iss": key, "exp": time.time()+20}, separators=(",", ":")).encode())
        signature = hmac.new(secret.encode(), unsigned, hashlib.sha256).digest()
        return "Bearer " + (unsigned+b"."+encode(signature)).decode()

    async def fetch(self, session, url, event, channel, purpose, conditional=True, sec_exhibit=False, discovery_interval=None, method="GET", request_json=None):
        queued = time.perf_counter_ns()
        queue_details = await self.rate.wait(url, purpose, **(
            {"discovery_interval": discovery_interval} if discovery_interval is not None else {})) or {}
        started = time.perf_counter_ns()
        raw_start, start = self.clock.stamp()
        clock_snapshot = self.clock.state.copy()
        if clock_snapshot.get("calibrated_raw_utc"):
            clock_snapshot["sample_age_ms"] = max(0, (raw_start/1e9-epoch(clock_snapshot["calibrated_raw_utc"]))*1000)
        clock_snapshot["uncertainty_is_estimate_not_guaranteed_bound"] = True
        def frozen_stamp():
            raw = time.time_ns()
            return raw, raw + round((clock_snapshot.get("offset_ms") or 0)*1e6)
        chunks = bytearray()
        first_body = None
        first_body_mono = None
        trace_events = 0
        new_connections = 0
        async def trace(name, info):
            nonlocal trace_events, new_connections
            trace_events += 1
            if name.endswith("connect_tcp.started"):
                new_connections += 1
        def receive(chunk):
            nonlocal first_body, first_body_mono
            if first_body is None:
                first_body = frozen_stamp()[1]
                first_body_mono = time.perf_counter_ns()
            chunks.extend(chunk)
        user_agent = self.args.user_agent if RateLimit.key(url) == "sec.gov" else "EarningsWatch/1.0 automated-public-filings-research"
        headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if purpose == "discovery":
            headers["Cache-Control"] = "no-cache"
        if method == "POST" and urlsplit(url).hostname == "www.barrick.com":
            headers.update({"Content-Type": "application/json; charset=utf-8", "Origin": "https://www.barrick.com",
                            "Referer": "https://www.barrick.com/English/news/default.aspx"})
        cached = self.cache.get(url)
        if conditional and cached:
            if cached.get("etag"):
                headers["If-None-Match"] = cached["etag"]
            elif cached.get("last_modified"):
                headers["If-Modified-Since"] = cached["last_modified"]
        record = {"id": str(uuid.uuid4()), "run_id": self.run_id, "mode": self.args.command, "symbol": event["symbol"],
                  "channel": channel, "purpose": purpose, "url": url, "method": method,
                  "node": self.args.node, "route": "configured_proxy" if self.proxy else "direct",
                  "clock": clock_snapshot, "request_start_raw_ns": raw_start,
                  "queued_mono_ns": queued, **queue_details,
                  "request_start_mono_ns": started,
                  "request_start_ns": start, "request_start_utc": iso(start),
                  "queue_ms": (started-queued)/1e6, "timing_basis": "perf_counter_ns durations; SNTP-adjusted UTC observations"}
        body = b""
        exhibit = None
        extractor = None
        browser = urlsplit(url).hostname in ("investor.msgknicks.com", "www.barrick.com",
                                              "investors.archer.com", "investors.hims.com")
        kkr_api = (event.get("symbol") == "KKR" and urlsplit(url).scheme == "https"
                   and urlsplit(url).hostname == "tools.cms-eqs.com"
                   and urlsplit(url).path == "/fcf5b4/content/events/eventbox")
        if sec_exhibit:
            from sec_stream import IncrementalExhibit
            extractor = IncrementalExhibit()
        try:
            if kkr_api:
                headers.update({"Authorization": await self.kkr_authorization(session, event, record),
                                "Content-Type": "application/json"})
            if browser:
                from browser_transport import browser_response, browser_timing
                transfer = browser_response(self.browser_session, method, url, headers, request_json=request_json)
                record["transport"] = "curl_cffi_chrome"
            else:
                archive_session = (self.sec_stream_session if self.sec_stream_session is not None
                                   and urlsplit(url).hostname == "www.sec.gov"
                                   and urlsplit(url).path.startswith("/Archives/") else session)
                transfer = archive_session.stream(method, url, headers=headers, extensions={"trace": trace},
                                          **({"json": request_json} if request_json is not None else {}),
                                          **({"follow_redirects": False} if kkr_api else {}))
            async with transfer as response:
                headers_mono = None if browser else time.perf_counter_ns()
                headers_at = None if browser else frozen_stamp()[1]
                if browser:
                    chunks.extend(response.content)
                else:
                    async for chunk in response.aiter_bytes():
                        receive(chunk)
                        if extractor is not None:
                            exhibit = extractor.feed(chunk)
                            if exhibit is not None:
                                break
            done_mono = time.perf_counter_ns()
            raw_done, done = frozen_stamp()
            container_received = len(chunks)
            body = exhibit["body"] if exhibit is not None else bytes(chunks)
            record.update({"status": response.status_code, "final_url": str(response.url),
                           "response_headers": dict(response.headers), "body_bytes": len(body),
                           "body_complete_ns": done, "body_complete_raw_ns": raw_done,
                           "body_complete_mono_ns": done_mono,
                           "request_end_mono_ns": done_mono, "request_end_ns": done, "request_end_utc": iso(done),
                           "body_complete_utc": iso(done), "first_body_byte_ns": first_body,
                           "first_body_byte_mono_ns": first_body_mono,
                           "body_download_ms": (done_mono-first_body_mono)/1e6 if first_body_mono is not None else None,
                           "first_body_byte_utc": iso(first_body),
                           "first_body_callback_ms": (first_body_mono-started)/1e6 if first_body_mono else None,
                           "request_total_ms": (done_mono-started)/1e6,
                           "response_headers_received_ns": headers_at,
                           "response_headers_received_ms": (headers_mono-started)/1e6 if headers_mono is not None else None,
                           "first_byte_semantics": "application first decoded body chunk, not NIC/wire byte",
                           "raw_body_semantics": "HTTP content decoded body, original encoding in response headers",
                           "connection_reused": new_connections == 0 if trace_events else None,
                           "new_tcp_connections": new_connections,
                           "http_version": response.http_version})
            if browser:
                record.update(browser_timing(response), http_response_complete=True,
                              first_byte_semantics="No application first-chunk timestamp for eager transfer; native first_response_byte timing is recorded separately")
            if extractor is not None:
                record.update({"sec_stream_attempt": True, "target_document_complete": exhibit is not None,
                               "container_decoded_bytes_received": container_received,
                               "http_response_complete": exhibit is None,
                               "body_complete_semantics": "complete EX-99.1 HTML at SGML closing markers" if exhibit else "full submission without matched HTML EX-99.1"})
                if exhibit is not None:
                    record["target_document_url"] = urljoin(str(response.url), exhibit["filename"])
                    record["container_bytes_consumed_to_document_end"] = exhibit["container_bytes_consumed"]
                    record["extracted_form"] = exhibit["form"]
                else:
                    extractor.close_without_match()
            if body and (purpose == "discovery" or purpose == "candidate" and response.status_code == 200):
                record["sha256"] = hashlib.sha256(body).hexdigest()
                record["raw_path"] = str(Path("raw")/(record["sha256"]+".gz"))
                record["_deferred_evidence"] = True
            elif body:
                record["sha256"], record["raw_path"] = await asyncio.to_thread(self.store.raw, body)
            if response.status_code == 304 and cached:
                body = cached["body"]
                record["reused_sha256"] = cached["sha256"]
            elif response.status_code == 200:
                self.cache[url] = {"etag": response.headers.get("etag"),
                                   "last_modified": response.headers.get("last-modified"),
                                   "sha256": record.get("sha256"), "body": body,
                                   "content_type": response.headers.get("content-type", "")}
            if response.status_code in (403, 429):
                retry = response.headers.get("retry-after", "")
                seconds = 120
                if retry.isdigit():
                    seconds = max(120, int(retry))
                else:
                    try:
                        from email.utils import parsedate_to_datetime
                        seconds = max(120, parsedate_to_datetime(retry).timestamp()-time.time())
                    except (ValueError, TypeError):
                        pass
                self.rate.cooldown(url, seconds, path_only=response.status_code == 403)
                record["cooldown_seconds"] = seconds
                record["cooldown_scope"] = "path" if response.status_code == 403 else "host"
        except Exception as exc:
            failed_mono = time.perf_counter_ns()
            failed = frozen_stamp()[1]
            record.update({"status": None, "error": f"{type(exc).__name__}: {exc}",
                           "error_cause": repr(exc.__cause__),
                           "request_total_ms": (failed_mono-started)/1e6,
                           "request_end_mono_ns": failed_mono, "request_end_ns": failed, "request_end_utc": iso(failed),
                           "body_complete_ns": None, "first_body_byte_ns": first_body,
                           "first_body_byte_mono_ns": first_body_mono})
            if chunks:
                record["partial_sha256"], record["partial_raw_path"] = await asyncio.to_thread(self.store.raw, bytes(chunks))
        if purpose == "discovery":
            record["_deferred_evidence"] = True
        if not record.get("_deferred_evidence"):
            self.store.add("request", record)
        return record, body

    async def persist_request(self, record, body):
        if record.get("_deferred_evidence"):
            await asyncio.to_thread(self.store.raw, body)
            record.pop("_deferred_evidence")
            record["evidence_persisted_mono_ns"] = time.perf_counter_ns()
            self.store.add("request", record)

    async def validate_document(self, body, url, content_type, event):
        from sources import validate
        queued = time.perf_counter_ns()
        def parse():
            started = time.perf_counter_ns()
            result = validate(body, url, content_type, event)
            finished = time.perf_counter_ns()
            return result, {"validation_queued_mono_ns": queued, "validation_start_mono_ns": started,
                            "validated_mono_ns": finished, "validation_queue_ms": (started-queued)/1e6,
                            "parse_ms": (finished-started)/1e6}
        return await asyncio.to_thread(parse)

    async def candidate(self, session, event, channel, item, discovered_ns, last_negative, depth=0, existing=None,
                        discovered_mono_ns=None, last_negative_mono_ns=None):
        from sources import discover, sec_supporting_title
        url = item["url"]
        document_key = (event["symbol"], channel, url)
        key = (*document_key, bool(item.get("skip_sec_stream")))
        discovered_ns, last_negative, discovered_mono_ns, last_negative_mono_ns = self.first_discovered.setdefault(
            document_key, (discovered_ns, last_negative, discovered_mono_ns, last_negative_mono_ns))
        if self.args.command == "run" and (document_key in self.captured_documents
                or item.get("inspection_only") and document_key in self.inspected_documents):
            return
        if key in self.active_candidates or time.monotonic() < self.candidate_retry.get(key, 0):
            return
        self.active_candidates.add(key)
        attempt_started = time.perf_counter_ns()
        self.candidate_attempts[key] = self.candidate_attempts.get(key, 0) + 1
        attempt = self.candidate_attempts[key]
        self.candidate_retry[key] = time.monotonic() + 2
        rec, body = None, b""
        try:
            if existing is None:
                stream_index = (self.sec_stream_session is not None and channel == "sec" and not item.get("skip_sec_stream")
                                and item.get("role") == "filing_index" and item.get("title") in ("8-K", "6-K", "8-K/A", "6-K/A")
                                and url.endswith("-index.html"))
                if stream_index:
                    container_url = url[:-len("-index.html")] + ".txt"
                    rec, body = await self.fetch(self.sec_stream_session, container_url, event, channel,
                                                 "candidate", conditional=False, sec_exhibit=True)
                    if not rec.get("target_document_complete"):
                        await self.persist_request(rec, body)
                        rec, body = await self.fetch(session, url, event, channel, "candidate", conditional=False)
                else:
                    rec, body = await self.fetch(session, url, event, channel, "candidate", conditional=False)
            else:
                rec, body = existing[0], existing[1]
            if rec["status"] != 200:
                self.retry_candidate(session, event, channel, item, discovered_ns, last_negative,
                                     depth, discovered_mono_ns, last_negative_mono_ns)
                return
            ctype = "text/html" if rec.get("target_document_complete") else rec["response_headers"].get("content-type", "")
            document_url = rec.get("target_document_url", rec["final_url"])
            result = None
            parse_timing = None
            if channel == "sec" and not item.get("inspection_only"):
                result, parse_timing = await self.validate_document(body, document_url, ctype, event) if existing is None else existing[2:]
                supporting_title = sec_supporting_title(item.get("form"), item.get("title"),
                                                        body=body, event=event, validation=result)
                if supporting_title:
                    item = {**item, "inspection_only": True, "supporting_title": supporting_title,
                            "classification_basis": "validated_document_heading"}
            if channel == "sec" and item.get("inspection_only"):
                if not body:
                    self.retry_candidate(session, event, channel, item, discovered_ns, last_negative,
                                         depth, discovered_mono_ns, last_negative_mono_ns)
                    return
                await self.persist_request(rec, body)
                inspection_key = (event["symbol"], channel, document_url)
                if self.args.command != "run" or inspection_key not in self.inspected_documents:
                    self.store.add("attachment", {**rec, "form": item["form"], "inspection_only": True,
                                                  "http_response_complete": True,
                                                  "discovered_ns": discovered_ns,
                                                  "discovered_mono_ns": discovered_mono_ns,
                                                  "classification_basis": item.get("classification_basis"),
                                                  "supporting_title": item.get("supporting_title"),
                                                  "financial_validation": {k: v for k, v in result.items() if k not in ("text", "tables")} if result else None,
                                                  "completion_scope": "full_supporting_attachment_received",
                                                  "inspection_semantics": "original bytes archived; not validated as a financial report"})
                    self.inspected_documents.add(inspection_key)
                    self.summary()
                self.candidate_retry[key] = float("inf")
                return
            if result is None:
                result, parse_timing = await self.validate_document(body, document_url, ctype, event) if existing is None else existing[2:]
            validated_mono = parse_timing["validated_mono_ns"]
            validated = rec["body_complete_ns"] + (validated_mono-rec["body_complete_mono_ns"])
            discovery_to_parsed = (validated_mono-discovered_mono_ns)/1e6 if discovered_mono_ns is not None else None
            verdict = {k: v for k, v in result.items() if k not in ("text", "tables", "table_spans", "table_details", "page_diagnostics")}
            if "table_details" in result:
                verdict["pdf_table_count"] = len(result["table_details"])
                verdict["pdf_table_word_count"] = sum(t["source_word_count"] for t in result["table_details"])
                verdict["pdf_table_numeric_token_count"] = sum(t["numeric_tokens"] for t in result["table_details"])
            await self.persist_request(rec, body)
            self.store.add("validation", {"symbol": event["symbol"], "channel": channel,
                                         "run_id": self.run_id, "mode": self.args.command,
                                         "request_id": rec["id"], "url": url, "result": verdict,
                                         "discovered_ns": discovered_ns, "discovered_mono_ns": discovered_mono_ns,
                                         "discovery_to_parsed_ms": discovery_to_parsed,
                                         "validated_ns": validated, "validated_utc": iso(validated), **parse_timing,
                                         "candidate_attempt": attempt, "attempt_started_mono_ns": attempt_started,
                                         "attempt_to_parsed_ms": (validated_mono-attempt_started)/1e6 if existing is None else None})
            duplicate_document = self.args.command == "run" and (event["symbol"], channel, document_url) in self.captured_documents
            if result.get("accepted"):
                # A previously archived stream target is terminal for this URL too.
                self.candidate_retry[key] = float("inf")
            if result.get("accepted") and not duplicate_document:
                pub = result.get("publisher_timestamp") or {}
                comparison = publication_lag(pub, rec["body_complete_ns"], rec["clock"])
                captured = {**rec, "discovered_ns": discovered_ns, "discovered_utc": iso(discovered_ns),
                            "last_negative_listing_ns": last_negative,
                            "discovered_mono_ns": discovered_mono_ns,
                            "last_negative_listing_mono_ns": last_negative_mono_ns,
                            "listing_observation_gap_ms": (discovered_mono_ns-last_negative_mono_ns)/1e6 if discovered_mono_ns is not None and last_negative_mono_ns is not None else None,
                            "discovery_to_body_ms": (rec["body_complete_mono_ns"]-discovered_mono_ns)/1e6 if discovered_mono_ns is not None else None,
                            "listing_request_id": item.get("listing_request_id"),
                            "observation_gap_semantics": "listing visibility at this node; NOT origin publication or network-only latency",
                            "validated_ns": validated, "validated_utc": iso(validated),
                            "validated_mono_ns": validated_mono,
                            **parse_timing, "candidate_attempt": attempt, "retry": attempt > 1,
                            "attempt_to_parsed_ms": (validated_mono-attempt_started)/1e6 if existing is None else None,
                            "body_to_validation_ms": (validated_mono-rec["body_complete_mono_ns"])/1e6,
                            "discovery_to_parsed_ms": discovery_to_parsed,
                            "latency_budget_ms": LATENCY_BUDGET_MS,
                            "latency_budget_passed": discovery_to_parsed <= LATENCY_BUDGET_MS if discovery_to_parsed is not None else None,
                            "latency_metric": "per_document_discovery_to_parsed; includes queue, download, parse; excludes later archive writes",
                            "discovery_timestamp_semantics": item.get("discovery_timestamp_semantics", "listing_response_complete_not_earliest_candidate_byte"),
                            "publisher_timestamp": pub, "sec_accepted_at": item.get("sec_accepted_at"),
                            "discovery_route": item.get("discovery_route", "channel_listing"),
                            "discovery_url": url,
                            "form": item.get("form") or rec.get("extracted_form"), "inspection_only": False,
                            "completion_scope": "one_validated_document_not_all_filing_attachments",
                            "publication_lag": comparison,
                            "already_present_on_first_poll": last_negative is None,
                            "release_to_capture_ms": None,
                            "validation": verdict,
                            "validation_semantics": "automated identity/period/table checks; not an audited accounting opinion"}
                name = f"{event['symbol'].replace('.', '_')}_{channel}_{rec['sha256'][:12]}"
                target = self.store.root / "reports" / name
                original = target.with_suffix(".pdf" if body.startswith(b"%PDF") else ".html")
                original.write_bytes(body)
                captured["original_document_path"] = str(original.relative_to(self.store.root))
                target.with_suffix(".txt").write_text(result.get("text", ""), encoding="utf-8")
                atomic_json(target.with_suffix(".json"), {"metadata": captured, "tables": result.get("tables", []),
                            **{key: result[key] for key in ("table_spans", "table_details", "page_diagnostics") if key in result}})
                self.store.add("capture", captured)
                self.captured_documents.add((event["symbol"], channel, document_url))
                self.completed.add((event["symbol"], channel))
                logging.info("CAPTURE %s %s %s", event["symbol"], channel, url)
                if channel == "official" and not getattr(self.args, "candidate_url", None):
                    self.follow_original_wire(session, event, body, rec["body_complete_ns"], rec["body_complete_mono_ns"])
                self.summary()
            elif not result.get("accepted") and depth < 2:
                if not result.get("checks", {}).get("reporting_period", False) or not result.get("checks", {}).get("not_announcement", True):
                    self.candidate_retry[key] = time.monotonic() + 120
                children = await asyncio.to_thread(discover, body, rec["final_url"], ctype, event)
                if channel == "sec" and item.get("role") == "filing_index" and children:
                    self.store.add("filing_documents", {"symbol": event["symbol"], "channel": channel,
                                                       "run_id": self.run_id, "index_url": url,
                                                       "discovered_ns": discovered_ns, "discovered_mono_ns": discovered_mono_ns,
                                                        "documents": [c["url"] for c in children],
                                                        "document_requirements": [{"url": c["url"], "form": c.get("form"),
                                                                                   "inspection_only": c.get("inspection_only", False)}
                                                                                  for c in children]})
                    # Immutable filing index is checked once per run; each child
                    # has its own retry path and is not cancelled by another capture.
                    self.candidate_retry[key] = float("inf")
                for child in (children if channel == "sec" else children[:15]):
                    if child["url"] != url:
                        child.setdefault("sec_accepted_at", item.get("sec_accepted_at"))
                        child.setdefault("listing_request_id", item.get("listing_request_id"))
                        self.launch(self.candidate(session, event, channel, child, discovered_ns, last_negative, depth+1,
                                                   discovered_mono_ns=discovered_mono_ns, last_negative_mono_ns=last_negative_mono_ns))
                if not children and result.get("checks", {}).get("reporting_period") and result.get("checks", {}).get("identity"):
                    self.retry_candidate(session, event, channel, item, discovered_ns, last_negative,
                                         depth, discovered_mono_ns, last_negative_mono_ns)
            if rec.get("target_document_complete"):
                # A complete EX-99.1 is one document, not proof that later exhibits
                # or the quarterly filing have all been received. Audit the index
                # independently while retaining the original discovery clock.
                self.launch(self.candidate(session, event, channel, {**item, "skip_sec_stream": True},
                                           discovered_ns, last_negative, depth,
                                           discovered_mono_ns=discovered_mono_ns, last_negative_mono_ns=last_negative_mono_ns))
        except Exception as exc:
            ended = time.perf_counter_ns()
            self.store.add("candidate_error", {"symbol": event["symbol"], "channel": channel,
                "run_id": self.run_id, "url": url, "error_type": type(exc).__name__,
                "discovered_ns": discovered_ns, "discovered_mono_ns": discovered_mono_ns,
                "attempt_started_mono_ns": attempt_started, "attempt_ended_mono_ns": ended,
                "attempt_elapsed_ms": (ended-attempt_started)/1e6, "candidate_attempt": attempt})
            logging.exception("Candidate failed %s", url)
        finally:
            try:
                if rec is not None:
                    await self.persist_request(rec, body)
            finally:
                self.active_candidates.discard(key)

    def launch(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.child_tasks.add(task)
        task.add_done_callback(self.child_tasks.discard)
        return task

    def retry_candidate(self, session, event, channel, item, discovered_ns, last_negative, depth,
                        discovered_mono_ns, last_negative_mono_ns):
        if self.args.command != "run":
            return
        age = (time.perf_counter_ns()-discovered_mono_ns)/1e9 if discovered_mono_ns else (self.clock.stamp()[1]-discovered_ns)/1e9
        delay = 2 if age <= 300 else 60
        async def retry():
            await asyncio.sleep(delay)
            if self.stop.is_set() or self.clock.stamp()[1]/1e9 > epoch(event["window_end"])+86400:
                return
            await self.candidate(session, event, channel, item, discovered_ns, last_negative, depth,
                                 discovered_mono_ns=discovered_mono_ns, last_negative_mono_ns=last_negative_mono_ns)
        self.launch(retry())

    def follow_original_wire(self, session, event, body, observed_ns, observed_mono_ns):
        """Issuer pages often identify their original wire article even if search is blocked."""
        from lxml import etree
        if (event["symbol"], "newswire") in self.completed:
            return
        allowed = {"www.businesswire.com", "www.globenewswire.com", "www.prnewswire.com"}
        tree = etree.HTML(body)
        if tree is None:
            return
        for link in tree.xpath("//a[@href]"):
            url = link.get("href")
            parsed = urlsplit(url)
            if parsed.hostname in allowed and ("/news/home/" in parsed.path or "/news-release" in parsed.path):
                item = {"url": url, "discovery_route": "issuer_original_source_link"}
                self.launch(self.candidate(session, event, "newswire", item, observed_ns, None,
                                           discovered_mono_ns=observed_mono_ns))

    async def source_loop(self, session, event, source, once=False):
        from sources import discover, listing_structure
        channel, url = source["channel"], source["url"]
        key = (event["symbol"], channel)
        status_key = event["symbol"] + ":" + channel
        self.status[status_key] = {"state": "waiting_for_source_budget", "url": url}
        last_negative = None
        last_negative_mono = None
        last_sha = None
        last_listing_basis = None
        preflight_done = False
        while not self.stop.is_set():
            now = self.clock.stamp()[1]/1e9
            start, end = epoch(event["window_start"]), epoch(event["window_end"])
            if not once and now < start and preflight_done:
                self.status[status_key] = {"state": "scheduled", "url": url, "window_start": event["window_start"]}
                await asyncio.sleep(min(30, start-now))
                continue
            if not once and now > end + 86400:
                self.status.setdefault(status_key, {}).update({"state": "captured" if key in self.completed else "window_expired_without_capture", "url": url})
                return
            # Forecasts only select density; broad release windows remain monitored.
            target = epoch(event.get("forecast_at") or event["scheduled_at"])
            hot = abs(now-target) <= 1800
            hot_discovery = hot and channel in ("official", "newswire")
            interval = (1/3 if hot_discovery else 1) if hot else (2 if now <= end else 120)
            rec, body = None, b""
            preflight_done = True
            cycle_started_mono = time.perf_counter_ns()
            try:
                rec, body = await self.fetch(session, url, event, channel, "discovery",
                                             discovery_interval=interval if hot_discovery else None,
                                             **({"method": source["method"], "request_json": source["request_json"]}
                                                if source.get("method") == "POST" else {}))
                rec["configured_poll_interval_seconds"] = interval
                self.status[status_key] = {"state": ("captured_monitoring_later_filings" if channel == "sec" and key in self.completed else "polling") if rec["status"] in (200, 304) else "source_error",
                                          "status": rec["status"], "error": rec.get("error"), "url": url,
                                          "last_request_utc": rec["request_start_utc"], "total_ms": rec["request_total_ms"],
                                          "configured_poll_interval_seconds": interval}
                if rec["status"] in (200, 304):
                    digest = rec.get("sha256") or rec.get("reused_sha256")
                    ctype = rec.get("response_headers", {}).get("content-type") or self.cache.get(url, {}).get("content_type", "")
                    seen_at = rec["body_complete_ns"]
                    # Revisit unresolved candidates on unchanged lists; a title can precede its body.
                    found = await asyncio.to_thread(discover, body, rec.get("final_url", url), ctype, event)
                    if channel == "sec":
                        # A submissions entry already supplies the quarterly body.
                        # Its index must not consume the body's reserved request slot.
                        found.sort(key=lambda item: 0 if item.get("form") in ("10-Q", "10-K") and item.get("role") != "filing_index" else 1)
                    previous_negative = last_negative
                    previous_negative_mono = last_negative_mono
                    for item in (found if channel == "sec" else found[:20]):
                        item["listing_request_id"] = rec["id"]
                        self.launch(self.candidate(session, event, channel, item, seen_at, previous_negative,
                                                   discovered_mono_ns=rec["body_complete_mono_ns"], last_negative_mono_ns=previous_negative_mono))
                    is_report = False
                    if digest != last_sha:
                        last_sha = digest
                        # Some sources are permanent quarterly result URLs updated in place.
                        result, parse_timing = await self.validate_document(body, rec.get("final_url", url), ctype, event)
                        checks = result.get("checks", {})
                        permanent_report = (bool(checks) and result.get("tables_complete") is True
                                            and all(value for check, value in checks.items() if check != "reporting_period"))
                        last_listing_basis = ("Validated permanent financial report" if permanent_report else
                                              await asyncio.to_thread(listing_structure, body, rec.get("final_url", url), ctype, event))
                        if result.get("accepted"):
                            is_report = True
                            self.launch(self.candidate(session, event, channel, {"url": url, "listing_request_id": rec["id"]},
                                                       seen_at, previous_negative, existing=(rec, body, result, parse_timing),
                                                       discovered_mono_ns=rec["body_complete_mono_ns"], last_negative_mono_ns=previous_negative_mono))
                    basis = "Target-period announcement links parsed" if found else last_listing_basis
                    rec.update(valid_discovery=basis is not None, validity_basis=basis)
                    if found or is_report:
                        rec.update(last_negative_listing_ns=previous_negative,
                                   last_negative_listing_mono_ns=previous_negative_mono,
                                   listing_observation_gap_ms=(rec["body_complete_mono_ns"]-previous_negative_mono)/1e6
                                   if previous_negative_mono is not None else None)
                    if not found and not is_report and basis is not None:
                        last_negative = seen_at
                        last_negative_mono = rec["body_complete_mono_ns"]
                    elif basis is None:
                        self.status[status_key].update(state="source_error", error="unreadable_listing")
                    if not once and now < start:
                        self.status[status_key].update(state="scheduled", window_start=event["window_start"])
            except Exception as exc:
                self.store.add("worker_error", {"symbol": event["symbol"], "channel": channel, "error": repr(exc)})
                logging.exception("Source loop failed %s", status_key)
            finally:
                if rec is not None:
                    self.status[status_key].update({name: rec.get(name) for name in (
                        "request_start_utc", "request_end_utc", "request_start_mono_ns", "request_end_mono_ns",
                        "listing_observation_gap_ms", "valid_discovery", "validity_basis")},
                        last_negative_listing_ns=last_negative,
                        last_negative_listing_mono_ns=last_negative_mono)
                if rec is not None and rec.pop("_deferred_evidence", False):
                    # Candidate tasks have been dispatched with the original body
                    # observation clock. Persist the listing without delaying GETs.
                    archive = self.launch(asyncio.to_thread(self.store.archive_request, dict(rec), body))
                    self.archive_tasks.add(archive)
                    archive.add_done_callback(lambda done: self.archive_tasks.discard(done)
                                              if not done.cancelled() and done.exception() is None else None)
            if once:
                return
            request_started = rec["request_start_mono_ns"] if rec is not None else cycle_started_mono
            remaining = interval - (time.perf_counter_ns()-request_started)/1e9
            # Anchor each interval to its actual request, so missed deadlines
            # never accumulate catch-up requests. Yield even after an overrun;
            # fetch still applies the shared host pacing and cooldowns.
            await asyncio.sleep(max(0, remaining))

    def summary(self):
        captures = self.store.records("capture")
        attachments = self.store.records("attachment")
        rankings = {}
        for rec in captures:
            if rec.get("mode", "run") == "run" and not rec["already_present_on_first_poll"] and "body_complete_mono_ns" in rec:
                rankings.setdefault((rec["symbol"], rec["run_id"]), []).append(rec)
        comparisons = {}
        for (symbol, run_id), rows in rankings.items():
            rows.sort(key=lambda r: r["body_complete_mono_ns"])
            rows = list({r["channel"]: next(x for x in rows if x["channel"] == r["channel"]) for r in rows}.values())
            baseline = rows[0]["body_complete_mono_ns"]
            comparisons[symbol + ":" + run_id] = [{"channel": r["channel"], "body_complete_utc": r["body_complete_utc"],
                                    "arrival_gap_ms": (r["body_complete_mono_ns"]-baseline)/1e6,
                                    "timing_eligible": not r["already_present_on_first_poll"],
                                    "rank_semantics": "local full-body arrival only"} for r in rows]
        measured = [r for r in captures if r.get("discovery_to_parsed_ms") is not None]
        filing_completeness = {}
        for audit in self.store.records("filing_documents"):
            observed = {r.get("target_document_url", r.get("final_url", r["url"])): r for r in captures
                        if r["symbol"] == audit["symbol"] and r["channel"] == "sec"}
            inspected = {r.get("final_url", r["url"]): r for r in attachments
                         if r["symbol"] == audit["symbol"] and r["channel"] == "sec"}
            inspected.update(observed)  # A parsed financial document also has complete archived bytes.
            requirements = audit.get("document_requirements", [{"url": url, "inspection_only": False}
                                                               for url in audit["documents"]])
            requirements = [{**r, "inspection_only": True} if inspected.get(r["url"], {}).get("inspection_only") else r
                            for r in requirements]
            financial_urls = [r["url"] for r in requirements if not r["inspection_only"]]
            inspection_urls = [r["url"] for r in requirements if r["inspection_only"]]
            missing_financial = [url for url in financial_urls if url not in observed]
            missing_inspection = [url for url in inspection_urls if url not in inspected]
            missing = missing_financial + missing_inspection
            financial_received = [observed[url] for url in financial_urls if url in observed]
            ready = [(r, r.get("validated_mono_ns")) for r in financial_received]
            ready += [(inspected[url], inspected[url].get("body_complete_mono_ns"))
                      for url in inspection_urls if url in inspected]
            duration = financial_duration = None
            if not missing and ready and audit.get("discovered_mono_ns") is not None and all(
                    r["run_id"] == audit["run_id"] and at is not None for r, at in ready):
                duration = (max(at for _, at in ready)-audit["discovered_mono_ns"])/1e6
            if not missing_financial and financial_received and audit.get("discovered_mono_ns") is not None and all(
                    r["run_id"] == audit["run_id"] and r.get("validated_mono_ns") is not None for r in financial_received):
                financial_duration = (max(r["validated_mono_ns"] for r in financial_received)-audit["discovered_mono_ns"])/1e6
            filing_completeness[audit["index_url"]] = {
                "symbol": audit["symbol"], "expected_document_urls": audit["documents"],
                "document_requirements": requirements,
                "requirements_classified": "document_requirements" in audit,
                "pending_document_urls": missing, "all_candidates_validated": not missing,
                "pending_financial_document_urls": missing_financial,
                "pending_inspection_document_urls": missing_inspection,
                "all_financial_documents_parsed": not missing_financial,
                "all_inspection_documents_received": not missing_inspection,
                "all_required_files_complete": not missing,
                "discovery_to_financial_documents_parsed_ms": financial_duration,
                "discovery_to_all_documents_parsed_ms": financial_duration if not inspection_urls else None,
                "discovery_to_required_files_complete_ms": duration,
                "latency_budget_passed": duration <= LATENCY_BUDGET_MS if duration is not None else None,
                "scope": "required financial documents parsed and supporting attachments received; later filings monitored separately"}
        summary = {"updated_utc": iso(self.clock.stamp()[1]), "run_id": self.run_id, "pid": os.getpid(),
                   "node": self.args.node, "clock": self.clock.state, "capture_count": len(captures),
                   "source_status": self.status, "arrival_comparisons": comparisons,
                   "filing_completeness": filing_completeness,
                   "no_origin_millisecond_claim": True,
                   "latency_acceptance": {"budget_ms": LATENCY_BUDGET_MS,
                                           "metric": "per_document_discovery_to_parsed",
                                          "measured_captures": len(measured),
                                          "passed_captures": sum(r["latency_budget_passed"] for r in measured),
                                          "unmeasured_captures": len(captures)-len(measured),
                                          "failures_are_recorded_separately_not_latency_successes": True,
                                          "all_events_under_budget_proven": False},
                   "route": "local_collector_via_configured_proxy" if self.proxy else "local_direct"}
        atomic_json(self.store.root / "status.json", summary)
        fields = ["symbol", "channel", "url", "discovered_utc", "first_body_byte_utc", "body_complete_utc",
                  "body_complete_beijing", "publisher_declared_time", "publisher_time_precision",
                  "validated_utc", "response_headers_received_ms", "first_body_callback_ms", "request_total_ms", "body_to_validation_ms",
                  "queue_ms", "discovery_to_parsed_ms", "latency_budget_ms", "latency_budget_passed",
                  "source_timestamp_delta_lower_ms", "source_timestamp_delta_upper_ms", "release_to_capture_ms",
                  "clock_offset_ms", "clock_uncertainty_ms", "node", "route",
                  "already_present_on_first_poll", "sha256", "raw_path"]
        path = self.store.root / "captures.csv"
        with path.with_suffix(".csv.tmp").open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for capture in captures:
                pub = capture.get("publisher_timestamp", {})
                lag = capture.get("publication_lag") or {}
                calibration = capture.get("clock", {})
                writer.writerow({**capture, "body_complete_beijing": datetime.fromisoformat(capture["body_complete_utc"]).astimezone(BJ).isoformat(timespec="milliseconds"),
                                 "publisher_declared_time": pub.get("value"), "publisher_time_precision": pub.get("precision"),
                                 "source_timestamp_delta_lower_ms": lag.get("lower_ms"),
                                 "source_timestamp_delta_upper_ms": lag.get("upper_ms"),
                                 "clock_offset_ms": calibration.get("offset_ms"),
                                 "clock_uncertainty_ms": calibration.get("uncertainty_ms")})
        path.with_suffix(".csv.tmp").replace(path)
        status_path = self.store.root/"source_status.csv"
        with status_path.with_suffix(".csv.tmp").open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["source", "state", "status", "last_request_utc", "total_ms", "error", "url", "window_start"], extrasaction="ignore")
            writer.writeheader()
            writer.writerows({"source": key, **value} for key, value in sorted(self.status.items()))
        status_path.with_suffix(".csv.tmp").replace(status_path)

    async def maintenance(self):
        last_calibrated = time.monotonic()
        last_progress = 0.0
        progress_task = None
        try:
            while not self.stop.is_set():
                if time.monotonic()-last_calibrated > 1800:
                    await asyncio.to_thread(self.clock.calibrate)
                    self.store.add("clock", self.clock.state)
                    last_calibrated = time.monotonic()
                try:
                    self.summary()
                except OSError:
                    logging.exception("Report refresh failed; collection continues and next heartbeat will retry")
                if progress_task is not None and progress_task.done():
                    try:
                        progress_task.result()
                    except Exception:
                        logging.exception("Progress export failed; collection continues")
                    progress_task = None
                    last_progress = time.monotonic()
                if progress_task is None and time.monotonic()-last_progress >= 300:
                    # A slow export must not delay the heartbeat or start another export.
                    from progress import generate_progress
                    progress_task = asyncio.create_task(asyncio.to_thread(generate_progress, self.store.root))
                if (self.store.root / "STOP").exists() or self.clock.stamp()[1]/1e9 >= epoch(self.args.until):
                    self.stop.set()
                    return
                await asyncio.sleep(20)
        finally:
            if progress_task is not None:
                # The thread cannot be cancelled; collect its outcome during shutdown.
                try:
                    await asyncio.shield(progress_task)
                except Exception:
                    logging.exception("Progress export failed during shutdown")

    async def keep_sec_connection_warm(self, events):
        # The metadata API is a different origin and cannot warm www.sec.gov.
        while not self.stop.is_set():
            now = self.clock.stamp()[1]/1e9
            if self.sec_stream_session is not None and any(epoch(e["window_start"]) <= now <= epoch(e["window_end"]) for e in events):
                # Recheck after startup: a fresh Store may acquire its first
                # verified report while this task is already running.
                records = self.store.records("capture") + self.store.records("inherited_document")
                for prior in reversed(records):
                    validation = prior.get("validation") or prior
                    original = prior.get("target_document_url") or prior.get("final_url") or prior.get("url", "")
                    parsed = urlsplit(original)
                    if (prior.get("channel") != "sec" or validation.get("accepted") is not True
                            or validation.get("tables_complete") is not True or parsed.scheme != "https"
                            or parsed.netloc != "www.sec.gov"
                            or not re.fullmatch(r"/Archives/edgar/data/\d+/\d{18}/[^/]+", parsed.path)):
                        continue
                    directory = "https://www.sec.gov" + parsed.path.rsplit("/", 1)[0] + "/"
                    event = next((e for e in events if e["symbol"] == prior["symbol"]), {"symbol": prior["symbol"]})
                    await self.fetch(self.sec_stream_session, directory, event, "sec", "warmup", conditional=False, method="HEAD")
                    break
            await asyncio.sleep(20)

    async def run(self):
        from network import apply_proxy_tls_fix
        from browser_transport import browser_session
        apply_proxy_tls_fix()
        import sources  # Load the parsers before an announcement can be discovered.
        import fitz
        self.store.add("network_configuration", {"run_id": self.run_id,
                                                "proxy_tls_leak_fix": "httpcore_1.0.9_process_local_cleanup"})
        await asyncio.to_thread(self.clock.calibrate)
        self.store.add("clock", self.clock.state)
        self.store.add("run_start", {"run_id": self.run_id, "node": self.args.node,
                                    "proxy_endpoint": urlsplit(self.proxy).netloc if self.proxy else None,
                                    "pid": os.getpid(), "until": self.args.until,
                                    "code_sha256": {name: hashlib.sha256((BASE/name).read_bytes()).hexdigest()
                                                    for name in ("watch.py", "sources.py", "network.py", "sec_stream.py", "pdf_tables.py", "browser_transport.py")}})
        events = json.loads(Path(self.args.manifest).read_text(encoding="utf-8"))
        if self.args.symbols:
            events = [e for e in events if e["symbol"] in self.args.symbols.split(",")]
        from pdf_tables import prewarm_pdf_pool
        warmup = await asyncio.to_thread(prewarm_pdf_pool)
        self.store.add("pdf_parser_ready", {"run_id": self.run_id, **warmup,
                                           "target_document_preparsed": False})
        async with httpx.AsyncClient(proxy=self.proxy, trust_env=False, follow_redirects=True,
                                     max_redirects=5, timeout=httpx.Timeout(12, connect=5),
                                     limits=httpx.Limits(max_connections=32, max_keepalive_connections=24, keepalive_expiry=60)) as session, \
                   httpx.AsyncClient(proxy=self.proxy, trust_env=False, follow_redirects=True, http2=True,
                                     timeout=httpx.Timeout(12, connect=5),
                                     limits=httpx.Limits(max_connections=8, max_keepalive_connections=4, keepalive_expiry=60)) as sec_stream_session, \
                   browser_session(proxy=self.proxy) as browser_client:
            self.sec_stream_session = sec_stream_session
            self.browser_session = browser_client
            if self.args.command == "run":
                self.launch(self.keep_sec_connection_warm(events))
            by_symbol = {e["symbol"]: e for e in events}
            for capture in self.store.records("capture"):
                if capture["channel"] == "official" and capture["symbol"] in by_symbol:
                    with gzip.open(self.store.root/capture["raw_path"], "rb") as raw:
                        self.follow_original_wire(session, by_symbol[capture["symbol"]], raw.read(),
                                                  self.clock.stamp()[1], time.perf_counter_ns())
            if self.args.command == "probe" and getattr(self.args, "candidate_url", None):
                if len(events) != 1:
                    raise ValueError("Candidate latency replay requires exactly one --symbols value")
                event = events[0]
                channel = self.args.channel
                seed = next(s["url"] for s in event["sources"] if s["channel"] == channel)
                seed_record, seed_body = await self.fetch(session, seed, event, channel, "discovery")
                await self.persist_request(seed_record, seed_body)
                for sample in range(self.args.samples):
                    self.first_discovered.clear()
                    self.candidate_retry.clear()
                    observed_ns = self.clock.stamp()[1]
                    await self.candidate(session, event, channel,
                                         {"url": self.args.candidate_url, "discovery_route": "replay_existing_public_report_not_new_release",
                                          "discovery_timestamp_semantics": "replay_invocation_not_live_discovery"},
                                         observed_ns, None, discovered_mono_ns=time.perf_counter_ns())
                    await asyncio.sleep(1)
                self.summary()
                self.store.add("run_end", {"run_id": self.run_id, "replay_only": True})
                return
            tasks = [asyncio.create_task(self.source_loop(session, event, source, self.args.command == "probe"))
                     for event in events for source in event["sources"]]
            if self.args.command == "probe":
                await asyncio.gather(*tasks)
                while self.child_tasks:
                    await asyncio.gather(*list(self.child_tasks), return_exceptions=True)
                self.summary()
            else:
                maintain = asyncio.create_task(self.maintenance())
                await self.stop.wait()
                cancellable = [task for task in self.child_tasks if task not in self.archive_tasks]
                for task in tasks + cancellable + [maintain]:
                    task.cancel()
                await asyncio.gather(*tasks, *cancellable, maintain, return_exceptions=True)
                while self.archive_tasks:
                    await asyncio.gather(*list(self.archive_tasks))
                self.summary()
        self.store.add("run_end", {"run_id": self.run_id})


def publication_lag(pub, received_ns, clock):
    """Return an interval for source-declared time; never substitute HTTP Date/SEC acceptance."""
    value = pub.get("value")
    precision = pub.get("precision")
    if not value or precision not in ("second", "minute", "millisecond") or not clock.get("verified"):
        return {"available": False, "reason": "no_comparable_precise_publication_clock"}
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if when.tzinfo is None:
            return {"available": False, "reason": "publisher_timezone_unknown"}
        resolution = {"second": 1000, "minute": 60000, "millisecond": 1}[precision]
        lag = received_ns/1e6-when.timestamp()*1000
        uncertainty = clock["uncertainty_ms"]
        return {"available": True, "relative_to": "publisher_declared_timestamp_not_proven_release_instant",
                "lower_ms": lag-resolution-uncertainty, "upper_ms": lag+uncertainty,
                "publisher_clock_error_unknown": True, "source_precision": precision}
    except (ValueError, TypeError):
        return {"available": False, "reason": "unparseable_publisher_timestamp"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "probe", "report"])
    parser.add_argument("--manifest", default=str(BASE / "watchlist.json"))
    parser.add_argument("--output", default=str(BASE / "runtime"))
    parser.add_argument("--symbols", default="")
    parser.add_argument("--candidate-url", default=None, help="Replay a known public document through the actual capture pipeline; probe only")
    parser.add_argument("--channel", choices=["official", "sec", "newswire"], default="official")
    parser.add_argument("--samples", type=int, default=5, help="Bounded replay samples, including any cold connection")
    parser.add_argument("--sec-rps", type=int, choices=range(1, 9), default=8,
                        help="Shared SEC rolling budget for all discovery, documents and retries")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--node", default="windows-workstation-via-user-US-proxy")
    parser.add_argument("--until", default="2026-11-13T13:03:00+08:00")
    parser.add_argument("--user-agent", default=os.environ.get("SEC_USER_AGENT", "EarningsWatch/1.0 automated-public-filings-research"))
    args = parser.parse_args()
    Path(args.output).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(handlers=[RotatingFileHandler(Path(args.output)/"service.log", maxBytes=5_000_000,
                                                     backupCount=3, encoding="utf-8")], level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    lock = None
    if args.command == "run":
        lock = (Path(args.output)/"collector.lock").open("a+b")
        try:
            if sys.platform == "win32":
                import msvcrt
                lock.seek(0)
                lock.write(b"1")
                lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return
        if (Path(args.output)/"STOP").exists() or time.time() > epoch(args.until):
            return
    collector = Collector(args)
    if args.command == "report":
        status_file = Path(args.output)/"status.json"
        print(status_file.read_text(encoding="utf-8") if status_file.exists() else "No run status yet.")
    else:
        try:
            if sys.platform == "win32" and args.command == "run":
                import ctypes
                result = ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
                collector.store.add("power_request", {"prevent_idle_sleep_while_running": bool(result),
                                                       "display_kept_on": False})
            asyncio.run(collector.run())
        finally:
            if sys.platform == "win32" and args.command == "run":
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)


if __name__ == "__main__":
    main()
