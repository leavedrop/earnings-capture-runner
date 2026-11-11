"""One public feed request shared by every configured issuer.

Rolling-feed absence is never a company-level negative observation. The existing
company discovery loops remain the fallback and the complete-document gate stays
in Collector.candidate.
"""

import asyncio
import time
from datetime import datetime

from sources import discover_shared_feed


SHARED_FEEDS = (
    {"key": "sec_current", "provider": "sec", "channel": "sec", "interval": 1/3, "offset": 0.0,
     "url": "https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&count=100&owner=exclude&output=atom"},
    {"key": "businesswire", "provider": "businesswire.com", "channel": "newswire", "interval": 300.0, "offset": 0.0,
     "url": "https://feed.businesswire.com/rss/home/?rss=G1QFDERJXkJeEF9YXA=="},
    {"key": "prnewswire", "provider": "prnewswire.com", "channel": "newswire", "interval": 60.0, "offset": 0.0,
     "url": "https://www.prnewswire.com/rss/news-releases-list.rss"},
)


async def _pause(stop, seconds):
    if seconds <= 0:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(stop.wait(), seconds)
    except asyncio.TimeoutError:
        pass


def _interval(feed, record):
    # Respect the observed cache lifetime; a cached RSS is a backup, not a
    # millisecond publication feed. SEC still shares Collector.rate with filings.
    interval = feed["interval"]
    headers = record.get("response_headers", {})
    for directive in headers.get("cache-control", "").lower().split(","):
        name, _, value = directive.strip().partition("=")
        if name in ("max-age", "s-maxage") and value.strip('"').isdigit():
            interval = max(interval, int(value.strip('"')))
    return max(interval, record.get("cooldown_seconds") or 0)


async def _feed_loop(collector, session, events, feed, seen):
    state = collector.shared_discovery[feed["key"]]
    by_symbol = {event["symbol"]: event for event in events}
    previous_window = None
    until = datetime.fromisoformat(collector.args.until).timestamp()
    await _pause(collector.stop, feed["offset"])
    while not collector.stop.is_set() and collector.clock.stamp()[1] / 1e9 < until:
        record, body = None, b""
        started = time.perf_counter_ns()
        interval = feed["interval"]
        try:
            # The pseudo issuer labels this one shared request; actual candidates
            # always receive their original event and issuer-specific validator.
            record, body = await collector.fetch(
                session, feed["url"], {"symbol": "__shared__"}, feed["channel"], "discovery",
                **({"shared_feed": True} if feed["provider"] == "sec" else {}))
            interval = _interval(feed, record)
            state.update(last_request_id=record["id"], status=record.get("status"),
                         request_start_utc=record.get("request_start_utc"),
                         request_end_utc=record.get("request_end_utc"), interval_seconds=interval)
            http_complete = (record.get("status") == 200 and record.get("http_response_complete") is not False
                             or record.get("status") == 304 and bool(record.get("reused_sha256")))
            if not http_complete:
                raise ValueError("shared_feed_http_error")
            if record.get("body_complete_ns") is None or record.get("body_complete_mono_ns") is None:
                raise ValueError("shared_feed_observation_clock_missing")
            ctype = record.get("response_headers", {}).get("content-type", "")
            parsed = await asyncio.to_thread(discover_shared_feed, body, feed["url"], ctype, events)
            window = set(parsed["window_entry_ids"])
            if not parsed["valid"] or parsed["provider"] != feed["provider"] or not window:
                raise ValueError("shared_feed_unreadable_window")
            first_batch = previous_window is None
            overlap = len(window & previous_window) if previous_window is not None else None
            gap = previous_window is not None and overlap == 0
            previous_window = window
            state.update(ready=not gap, gap=gap, error=None, entry_count=parsed["entry_count"],
                         overlap_count=overlap, feed_updated_at=parsed["feed_updated_at"],
                         last_success_mono_ns=record["body_complete_mono_ns"],
                         last_success_utc=record.get("body_complete_utc"), new_candidates=0)
            if gap:
                state["gap_count"] += 1
                state["fallback_required"] = True
                state["fallback_generation"] += 1
            logs = []
            for entry in parsed["entries"]:
                identity = (feed["provider"], entry["discovery_entry_id"])
                if identity in seen:
                    continue
                seen.add(identity)
                context = "initially_present" if first_batch else "unknown"
                item = {**entry, "listing_request_id": record["id"], "discovery_context": context,
                        "already_present_on_first_poll": first_batch,
                        "discovery_route": "shared_feed", "shared_feed_key": feed["key"],
                        "source_freshness_proven": False, "absence_proven": False}
                collector.launch(collector.candidate(
                    session, by_symbol[entry["symbol"]], entry["channel"], item,
                    record["body_complete_ns"], None,
                    discovered_mono_ns=record["body_complete_mono_ns"], last_negative_mono_ns=None))
                state["new_candidates"] += 1
                logs.append({**item, "run_id": collector.run_id,
                             "discovered_ns": record["body_complete_ns"],
                             "discovered_mono_ns": record["body_complete_mono_ns"],
                             "discovered_utc": record.get("body_complete_utc")})
            # Dispatch all candidates before any SQLite/RAW persistence.
            for payload in logs:
                await collector.store.add_async("shared_candidate", payload)
            if gap:
                await collector.store.add_async("shared_discovery_gap", {
                    "run_id": collector.run_id, "channel": feed["channel"], "provider": feed["key"],
                    "url": feed["url"], "listing_request_id": record["id"], "overlap_count": 0,
                    "entry_count": parsed["entry_count"], "fallback_generation": state["fallback_generation"],
                    "observed_ns": record["body_complete_ns"], "observed_mono_ns": record["body_complete_mono_ns"]})
            record.update(shared_feed_key=feed["key"], valid_discovery=True,
                          validity_basis="Public rolling feed; absence not established",
                          shared_feed_gap=gap, absence_proven=False)
        except Exception as exc:
            state.update(ready=False, error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__,
                         fallback_required=True)
            state["fallback_generation"] += 1
            interval = max(interval, 5.0)
            await collector.store.add_async("shared_discovery_error", {
                "run_id": collector.run_id, "channel": feed["channel"], "provider": feed["key"],
                "url": feed["url"], "listing_request_id": record.get("id") if record else None,
                "status": record.get("status") if record else None, "error_type": type(exc).__name__,
                "reason": state["error"], "fallback_generation": state["fallback_generation"]})
        finally:
            if record is not None and record.pop("_deferred_evidence", False):
                await collector.store.archive_request_async(record, body)
        # No catch-up burst after slow requests or cooldown. Candidate GETs have
        # no added scheduling delay, and fetch remains the only rate-budget owner.
        request_started = record.get("request_start_mono_ns", started) if record else started
        await _pause(collector.stop, interval - (time.perf_counter_ns() - request_started) / 1e9)


async def run_shared_discovery(collector, session, events):
    """Run shared feeds until the collector STOP/deadline; company loops survive gaps.

    ``fallback_required`` is sticky until the owning collector acknowledges its
    company-level checks. ``fallback_generation`` lets it notice a recovered gap
    even if no individual source loop ran during the single failed feed interval.
    """
    collector.shared_discovery = {
        feed["key"]: {"provider": feed["provider"], "channel": feed["channel"], "url": feed["url"],
                      "interval_seconds": feed["interval"], "ready": False, "gap": False,
                      "gap_count": 0, "fallback_required": False, "fallback_generation": 0,
                      "last_success_mono_ns": None, "last_success_utc": None}
        for feed in SHARED_FEEDS}
    seen = set()
    workers = [asyncio.create_task(_feed_loop(collector, session, events, feed, seen)) for feed in SHARED_FEEDS]
    try:
        await asyncio.gather(*workers)
    finally:
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
