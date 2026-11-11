"""Collector evidence storage: one writer, complete event logs, compact unchanged polls."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import time


class _ReaderConnection(sqlite3.Connection):
    before_close = None

    def close(self):
        callback, self.before_close = self.before_close, None
        try:
            if callback:
                callback()
        finally:
            super().close()


class Store:
    def __init__(self, directory: Path):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("raw", "reports"):
            (self.root / name).mkdir(exist_ok=True)
        self.path = self.root / "observations.sqlite3"
        self.db = sqlite3.connect(self.path, timeout=5, factory=_ReaderConnection)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, kind TEXT, symbol TEXT,
            channel TEXT, at_ns INTEGER, payload TEXT);
          CREATE INDEX IF NOT EXISTS log_kind ON log(kind,symbol,channel);
          CREATE INDEX IF NOT EXISTS log_request_stats
            ON log(kind,symbol,channel,coalesce(json_extract(payload,'$.status'),NULL),at_ns) WHERE kind='request';
          CREATE TABLE IF NOT EXISTS source_latest(
            symbol TEXT,channel TEXT,url TEXT,run_id TEXT,at_ns INTEGER,payload TEXT,
            PRIMARY KEY(symbol,channel,url));
          CREATE TABLE IF NOT EXISTS poll_rollups(
            id INTEGER PRIMARY KEY,rollup_key TEXT UNIQUE,run_id TEXT,symbol TEXT,channel TEXT,url TEXT,
            bucket_start_ns INTEGER,status INTEGER,body_sha256 TEXT,timing_fields TEXT,
            request_count INTEGER,first_at_ns INTEGER,last_at_ns INTEGER,
            request_total_ms_min REAL,request_total_ms_max REAL,request_total_ms_sum REAL);
          CREATE INDEX IF NOT EXISTS poll_rollup_stats
            ON poll_rollups(symbol,channel,status,request_count,last_at_ns);
          CREATE TABLE IF NOT EXISTS poll_samples(
            id INTEGER PRIMARY KEY,rollup_id INTEGER NOT NULL,timing_values TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS poll_samples_rollup ON poll_samples(rollup_id,id);
        """)
        self.db.commit()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="observation-writer")
        self._writer = None
        self._closed = False
        self.db.before_close = self._close_writer

    def _connection(self):
        if self._writer is None:
            self._writer = sqlite3.connect(self.path, timeout=5)
            self._writer.execute("PRAGMA synchronous=NORMAL")
            self._writer.execute("PRAGMA busy_timeout=5000")
        return self._writer

    def _submit(self, function, *args):
        if self._closed:
            raise RuntimeError("observation_store_closed")
        return self._executor.submit(function, *args)

    def _close_writer(self):
        if self._closed:
            return
        self._closed = True
        def finish():
            if self._writer is not None:
                self._writer.close()
                self._writer = None
        try:
            self._executor.submit(finish).result()
        finally:
            self._executor.shutdown(wait=True)

    def close(self):
        self.db.close()

    @staticmethod
    def _latest(connection, record, at_ns):
        if record.get("purpose") != "discovery":
            return
        connection.execute("""INSERT INTO source_latest VALUES(?,?,?,?,?,?)
            ON CONFLICT(symbol,channel,url) DO UPDATE SET run_id=excluded.run_id,
              at_ns=excluded.at_ns,payload=excluded.payload WHERE excluded.at_ns>=source_latest.at_ns""",
            (record.get("symbol"), record.get("channel"), record.get("url"), record.get("run_id"), at_ns,
             json.dumps(record, ensure_ascii=False, separators=(",", ":"))))

    @classmethod
    def _insert(cls, connection, kind, payload, at_ns):
        cursor = connection.execute("INSERT INTO log(kind,symbol,channel,at_ns,payload) VALUES(?,?,?,?,?)",
            (kind, payload.get("symbol"), payload.get("channel"), at_ns,
             json.dumps(payload, ensure_ascii=False, separators=(",", ":"))))
        if kind == "request":
            cls._latest(connection, payload, at_ns)
        return cursor.lastrowid

    def _write(self, kind, payload, at_ns):
        connection = self._connection()
        with connection:
            return self._insert(connection, kind, payload, at_ns)

    def add(self, kind, payload, connection=None):
        """Synchronous durable API for startup and explicit callers; use add_async in the loop."""
        if connection is not None:
            with connection:
                return self._insert(connection, kind, payload, time.time_ns())
        return self._submit(self._write, kind, copy.deepcopy(payload), time.time_ns()).result()

    async def add_async(self, kind, payload):
        return await asyncio.wrap_future(self._submit(self._write, kind, copy.deepcopy(payload), time.time_ns()))

    @staticmethod
    def _poll_signature(record):
        return (record.get("run_id"), record.get("status"), record.get("sha256") or record.get("reused_sha256"),
                record.get("method", "GET"), record.get("final_url") or record.get("url"), record.get("valid_discovery"))

    def _archive(self, record, body, unchanged_poll, at_ns):
        if record.get("raw_path"):
            self.raw(body)
        record["evidence_write_started_mono_ns"] = time.perf_counter_ns()
        connection = self._connection()
        with connection:
            eligible = (unchanged_poll is True and record.get("purpose") == "discovery"
                and record.get("status") in (200, 304) and record.get("valid_discovery") is True
                and not record.get("error") and record.get("run_id")
                and re.fullmatch(r"[a-f0-9]{64}", str(record.get("sha256") or record.get("reused_sha256") or "")))
            previous = connection.execute("SELECT payload FROM source_latest WHERE symbol=? AND channel=? AND url=?",
                (record.get("symbol"), record.get("channel"), record.get("url"))).fetchone() if eligible else None
            if not previous or self._poll_signature(json.loads(previous[0])) != self._poll_signature(record):
                return self._insert(connection, "request", record, at_ns)
            fields = sorted(key for key in record if key == "id" or key == "clock" or
                            key.endswith(("_ns", "_utc", "_ms")) or
                            key in ("connection_reused", "new_tcp_connections", "http_version", "body_bytes"))
            schema = json.dumps(fields, separators=(",", ":"))
            values = json.dumps([record[key] for key in fields], ensure_ascii=False, separators=(",", ":"))
            bucket = at_ns // 60_000_000_000 * 60_000_000_000
            identity = (record["run_id"], record["symbol"], record["channel"], record["url"], bucket,
                        record["status"], self._poll_signature(record)[2], schema)
            rollup_key = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            elapsed = record.get("request_total_ms")
            row = connection.execute("""INSERT INTO poll_rollups(
                rollup_key,run_id,symbol,channel,url,bucket_start_ns,status,body_sha256,timing_fields,
                request_count,first_at_ns,last_at_ns,request_total_ms_min,request_total_ms_max,request_total_ms_sum)
                VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?) ON CONFLICT(rollup_key) DO UPDATE SET
                  request_count=request_count+1,last_at_ns=excluded.last_at_ns,
                  request_total_ms_min=min(request_total_ms_min,excluded.request_total_ms_min),
                  request_total_ms_max=max(request_total_ms_max,excluded.request_total_ms_max),
                  request_total_ms_sum=request_total_ms_sum+excluded.request_total_ms_sum RETURNING id""",
                (rollup_key, *identity[:7], schema, at_ns, at_ns, elapsed, elapsed, elapsed)).fetchone()
            connection.execute("INSERT INTO poll_samples(rollup_id,timing_values) VALUES(?,?)", (row[0], values))
            self._latest(connection, record, at_ns)
            return None  # No fictitious log row ID for a compact observation.

    def archive_request(self, record, body, *, unchanged_poll=False):
        return self._submit(self._archive, copy.deepcopy(record), body, unchanged_poll, time.time_ns()).result()

    async def archive_request_async(self, record, body, *, unchanged_poll=False):
        return await asyncio.wrap_future(self._submit(self._archive, copy.deepcopy(record), body, unchanged_poll, time.time_ns()))

    def raw(self, body):
        digest = hashlib.sha256(body).hexdigest()
        dest = self.root / "raw" / (digest + ".gz")
        if not dest.exists():
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=dest.parent, suffix=".tmp", delete=False) as stream:
                    temporary = Path(stream.name)
                    with gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=1) as compressed:
                        compressed.write(body)
                temporary.replace(dest)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        return digest, str(dest.relative_to(self.root))

    def records(self, kind):
        # Read connections are thread-local, so the heartbeat can move off the event loop.
        with closing(sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            return [json.loads(row[0]) for row in connection.execute(
                "SELECT payload FROM log WHERE kind=? ORDER BY id", (kind,))]

    def poll_observations(self, symbol, channel, url):
        """Recover every compact observation's actual clocks, without inventing historical headers."""
        with closing(sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            return [{"symbol": symbol, "channel": channel, "url": url, "run_id": run_id,
                     "status": status, "body_sha256": digest, "evidence_kind": "unchanged_listing_clock_sample",
                     **dict(zip(json.loads(fields), json.loads(values)))}
                    for run_id, status, digest, fields, values in connection.execute("""
                      SELECT r.run_id,r.status,r.body_sha256,r.timing_fields,s.timing_values
                      FROM poll_samples s JOIN poll_rollups r ON r.id=s.rollup_id
                      WHERE r.symbol=? AND r.channel=? AND r.url=? ORDER BY s.id""", (symbol, channel, url))]


def poll_statistics(connection):
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='poll_rollups'").fetchone():
        return []
    return connection.execute("SELECT symbol,channel,status,SUM(request_count),MAX(last_at_ns) FROM poll_rollups GROUP BY symbol,channel,status").fetchall()


def latest_sources(connection):
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_latest'").fetchone():
        return []
    return [json.loads(row[0]) for row in connection.execute("SELECT payload FROM source_latest")]
