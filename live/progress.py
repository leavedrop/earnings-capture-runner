"""Export a read-only, redacted earnings progress snapshot for local or static viewing."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import html
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tempfile
import time
from urllib.parse import quote, urlsplit, urlunsplit


BASE = Path(__file__).resolve().parent
BEIJING = timezone(timedelta(hours=8))
BUDGET_MS = 300
SITES_ORIGIN = "https://earnings-watch-latency-zwh-20261108.yummymerit.chatgpt.site"
CHANNELS = {"official": "公司官网", "sec": "SEC", "newswire": "财经发布渠道"}
CONTEXTS = {
    "live": "实时观察到新增",
    "initially_present": "首次轮询已存在",
    "backfill": "事后补采",
    "replay": "旧公开文档重放",
    "unknown": "采集时机未记录",
    "retry": "重试取得",
    "recovery": "已下载文件补齐解析",
}
OBSERVATION_FIELDS = (
    "last_negative_listing_ns", "last_negative_listing_mono_ns",
    "last_negative_listing_utc", "last_negative_listing_at_beijing",
    "listing_observation_gap_ms", "last_negative_to_parsed_ms", "observation_gap_semantics",
)


def date_value(value):
    if not value:
        return None
    try:
        value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo is not None else None


def beijing(value):
    value = date_value(value) if not isinstance(value, datetime) else value
    return value.astimezone(BEIJING).isoformat(timespec="milliseconds") if value else None


def milliseconds(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None


def public_url(value):
    """Only public hostnames; never export credentials, query parameters or fragments."""
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        if parts.scheme not in ("https", "http") or not host or "." not in host or host.endswith((".local", ".localhost")):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except ValueError:
        return None


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def cloud_artifacts(values):
    artifacts = []
    for value in values or []:
        if not isinstance(value, str):
            continue
        parts = urlsplit(value)
        if parts.netloc and (parts.scheme != "https" or parts.netloc != urlsplit(SITES_ORIGIN).netloc):
            continue
        match = re.fullmatch(r"/artifacts/reports/[A-Za-z0-9._-]+/[a-fA-F0-9]{64}\.(html|pdf|txt|json)", parts.path)
        if not match:
            continue
        label = {"html": "私人原文", "pdf": "私人原文 PDF", "txt": "私人提取文本", "json": "私人表格 JSON"}[match[1]]
        artifacts.append({"label": label, "url": SITES_ORIGIN + parts.path, "requires_site_access": True})
    return artifacts


def source_patrols(status, observer):
    rows = []
    labels = {"captured": "已取得文档", "scheduled": "等待监测窗口", "polling": "巡视中",
              "source_error": "来源请求失败", "window_expired_without_capture": "窗口结束，未取得文档",
              "no_new": "已巡视，暂无新稿", "ok": "巡视完成", "requesting": "正在巡视",
              "cooldown": "远端暂缓，等待下次巡视", "backoff": "巡视失败，等待重试"}
    for key, source in status.get("source_status", {}).items():
        symbol, _, channel = key.partition(":")
        url = public_url(source.get("listing_url") or source.get("url"))
        new_count = source.get("new_count")
        state = labels.get(source.get("state"), "状态未记录")
        http_status = source.get("status")
        if source.get("state") in ("requesting", "cooldown"):
            pass
        elif isinstance(http_status, int) and http_status >= 400 or source.get("error_code"):
            state = "巡视失败"
        elif new_count == 0 and source.get("last_request_utc"):
            state = "巡视完成，本次未新增记录"
        elif isinstance(new_count, int) and new_count > 0:
            state = f"本次记录 {new_count} 份文档"
        negative_ns = source.get("last_negative_listing_ns")
        negative_at = (datetime.fromtimestamp(negative_ns // 1_000_000_000, timezone.utc)
                       .replace(microsecond=negative_ns % 1_000_000_000 // 1_000)
                       if type(negative_ns) is int and negative_ns > 0 else None)
        rows.append({"observer": observer, "symbol": symbol, "channel": channel,
                     "channel_label": CHANNELS.get(channel, "其他来源"), "url": url,
                     "site": urlsplit(url).hostname if url else None, "state": state,
                     "status": http_status if isinstance(http_status, int) else None,
                     "last_patrol_at_beijing": beijing(source.get("request_end_utc") or source.get("last_completed_utc") or source.get("last_request_utc")),
                     "request_start_utc": source.get("request_start_utc"),
                     "request_end_utc": source.get("request_end_utc"),
                     "request_start_mono_ns": source.get("request_start_mono_ns"),
                     "request_end_mono_ns": source.get("request_end_mono_ns"),
                     "request_start_at_beijing": beijing(source.get("request_start_utc")),
                     "request_end_at_beijing": beijing(source.get("request_end_utc")),
                     "last_negative_listing_ns": negative_ns,
                     "last_negative_listing_mono_ns": source.get("last_negative_listing_mono_ns"),
                     "last_negative_listing_utc": negative_at.isoformat(timespec="microseconds") if negative_at else None,
                     "last_negative_listing_at_beijing": beijing(negative_at),
                     "listing_observation_gap_ms": source.get("listing_observation_gap_ms"),
                     "new_count": new_count if isinstance(new_count, int) else None,
                     "bridge_roundtrip_ms": milliseconds(source.get("bridge_roundtrip_ms"))})
    return rows


def has_negative_observation(record):
    observed = record.get("last_negative_listing_ns")
    return record.get("already_present_on_first_poll") is False and type(observed) is int and observed > 0


def context(record, run_started, replay):
    if record.get("mode") == "recovery":
        return "recovery", "原件早前已经下载，本次补齐解析；两次操作之间没有连续计时。"
    if replay or record.get("mode") == "probe" or "replay" in str(record.get("discovery_route", "")):
        return "replay", "旧公告的采集链路性能重放，不属于新公告首发。"
    first = record.get("already_present_on_first_poll")
    published = date_value((record.get("publisher_timestamp") or {}).get("value")) or date_value(record.get("sec_accepted_at"))
    if first is True:
        if published and run_started and published < run_started:
            return "backfill", "首次轮询已存在，且来源发布标时早于本次运行启动；据此归为补采。"
        return "initially_present", "首次轮询即存在，缺少此前未发布的观察证据。"
    if has_negative_observation(record):
        return "live", "记录包含此前未出现该公告的观察；不等于发布端毫秒级时刻已知。"
    if first is False:
        return "unknown", "缺少此前未见公告的原始观察时间，不能认作首发记录。"
    return "unknown", "日志未记录首次轮询或重放属性。"


def artifact_path(root, relative, output_root):
    relative = PurePosixPath(str(relative).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts or ":" in str(relative):
        return None
    path = (root / str(relative)).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        return None
    return Path(os.path.relpath(path, output_root)).as_posix()


def capture_timing(record):
    if record.get("mode") == "recovery":
        return None, "separate_recovery", "原件早前已下载，后来补齐解析；没有连续计时，不能算一次实时抓取。"
    duration = milliseconds(record.get("discovery_to_parsed_ms"))
    if duration is not None:
        return duration, "recorded", "原始日志记录的发现至全文解析耗时。"
    for start, end, basis, note in (
        ("discovered_mono_ns", "validated_mono_ns", "reconstructed_monotonic", "早期程序漏存总耗时，现按原日志中同次运行的计时起止点补算。"),
        ("discovered_ns", "validated_ns", "reconstructed_utc", "早期程序漏存总耗时，现按原日志系统时钟估算；不作为精确300ms验收成绩。"),
    ):
        first, last = record.get(start), record.get(end)
        if type(first) is int and type(last) is int and last >= first:
            return (last - first) / 1_000_000, basis, note
    return None, "missing", "原日志缺少完整计时起止点，无法还原这次总耗时。"


@lru_cache(maxsize=128)
def archived_table_check(original, report_path, original_mtime, report_mtime, msgk_issuer=False):
    """Check the saved product against its own HTML, not an old acceptance flag."""
    from sources import _clean, _document, _drop_content, _text
    tree = _document(Path(original).read_bytes())
    root = None
    if msgk_issuer:
        root = next((node for node in tree.iter("div") if
                     {"evergreen-news-details", "module-news-details"}.intersection(node.get("class", "").split())), None)
        if root is None:
            return False, "未找到公司官网的财报正文范围。"
    if root is None:
        root = next(tree.iter("article"), None)
    if root is None:
        root = next(tree.iter("main"), tree)
    _drop_content(root, "script", "style", "nav", "header", "footer")
    expected = []
    for table in root.iter("table"):
        rows = [[_clean(_text(cell)) for cell in row if cell.tag in ("td", "th")]
                for row in table.iter("tr")]
        rows = [row for row in rows if any(row)]
        if rows:
            expected.append(rows)
    saved = read_json(Path(report_path)).get("tables", [])
    def signature(table):
        return tuple(tuple(re.sub(r"\s+", " ", str(cell or "")).strip() for cell in row) for row in table)
    absent = Counter(signature(table) for table in expected) - Counter(signature(table) for table in saved)
    complete = not absent
    note = (f"核对原始HTML发现有{len(expected)}张表，旧产物保存{len(saved)}张，其中{sum(absent.values())}张未完整保留；该次不算全文和表格完整达标。"
            if not complete else "")
    return complete, note


def capture_row(record, root, output_root, run_started, replay=False):
    category, explanation = context(record, run_started, replay)
    validation = record.get("validation") or {}
    duration, timing_basis, timing_note = capture_timing(record)
    accepted = validation.get("accepted") is True
    url = public_url(record.get("target_document_url") or record.get("final_url") or record.get("url"))
    symbol = str(record.get("symbol", ""))
    channel = record.get("channel", "")
    digest = str(record.get("sha256", ""))
    artifacts = []
    table_count = None
    tables_complete = validation.get("tables_complete")
    quality_note = ""
    if re.fullmatch(r"[A-Za-z0-9._-]+", symbol) and channel in CHANNELS and re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        stem = f"reports/{symbol.replace('.', '_')}_{channel}_{digest[:12]}"
        original = record.get("original_document_path")
        candidates = [(original, "原文") ] if original else [(stem + ".html", "原文 HTML"), (stem + ".pdf", "原文 PDF")]
        candidates.append((stem + ".txt", "提取文本"))
        for relative, label in candidates:
            path = artifact_path(root, relative, output_root)
            if path:
                artifacts.append({"label": label, "path": path, "local_only": True})
        report_path = artifact_path(root, stem + ".json", root)
        if report_path:
            report = read_json(root / report_path)
            table_count = len(report.get("tables", []))
            saved_html = artifact_path(root, stem + ".html", root)
            if saved_html:
                original_html = root / saved_html
                complete, quality_note = archived_table_check(str(original_html), str(root / report_path),
                    original_html.stat().st_mtime_ns, (root / report_path).stat().st_mtime_ns,
                    symbol == "MSGK" and urlsplit(url or "").hostname == "investor.msgknicks.com")
                if not complete:
                    tables_complete = False
    semantics = record.get("discovery_timestamp_semantics")
    if category == "replay":
        timing_start = "重放调用开始"
    elif semantics == "listing_response_complete_not_earliest_candidate_byte":
        timing_start = "列表响应完整后识别"
    elif semantics:
        timing_start = "采集器记录的发现时刻"
    else:
        timing_start = "计时起点细节未记录"
    negative_ns = record.get("last_negative_listing_ns")
    negative_at = (datetime.fromtimestamp(negative_ns // 1_000_000_000, timezone.utc)
                   .replace(microsecond=negative_ns % 1_000_000_000 // 1_000)
                   if type(negative_ns) is int and negative_ns > 0 else None)
    return {
        "symbol": symbol,
        "channel": channel,
        "channel_label": CHANNELS.get(channel, "其他来源"),
        "site": urlsplit(url).hostname if url else None,
        "title": validation.get("title") or record.get("title") or f"{symbol} 财报文档",
        "url": url,
        "url_parameters_removed": bool(url and url != (record.get("target_document_url") or record.get("final_url") or record.get("url"))),
        "context": category,
        "context_label": CONTEXTS[category],
        "context_explanation": explanation,
        "already_present_on_first_poll": record.get("already_present_on_first_poll"),
        "last_negative_listing_ns": negative_ns,
        "last_negative_listing_mono_ns": record.get("last_negative_listing_mono_ns"),
        "last_negative_listing_utc": negative_at.isoformat(timespec="microseconds") if negative_at else None,
        "last_negative_listing_at_beijing": beijing(negative_at),
        "listing_observation_gap_ms": record.get("listing_observation_gap_ms"),
        "last_negative_to_parsed_ms": record.get("last_negative_to_parsed_ms"),
        "observation_gap_semantics": record.get("observation_gap_semantics"),
        "discovered_at_beijing": beijing(record.get("discovered_utc")),
        "parsed_at_beijing": beijing(record.get("validated_utc")),
        "discovery_to_parsed_ms": duration,
        "timing_basis": timing_basis,
        "timing_note": timing_note,
        "request_total_ms": milliseconds(record.get("request_total_ms")),
        "body_to_validation_ms": milliseconds(record.get("body_to_validation_ms")),
        "timing_start": timing_start,
        "latency_budget_passed": (duration <= BUDGET_MS and accepted
                                  and tables_complete is True
                                  and timing_basis != "reconstructed_utc") if duration is not None else None,
        "accepted": accepted,
        "tables_complete": tables_complete,
        "quality_note": quality_note,
        "table_count": table_count,
        "pdf_pages_processed": validation.get("pdf_pages_processed"),
        "artifacts": artifacts,
    }


def read_database(root, output_root, replay=False):
    uri = (root / "observations.sqlite3").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        starts = {
            json.loads(payload).get("run_id"): datetime.fromtimestamp(at_ns / 1e9, timezone.utc)
            for at_ns, payload in connection.execute("SELECT at_ns,payload FROM log WHERE kind='run_start'")
        }
        captures = []
        for (payload,) in connection.execute("SELECT payload FROM log WHERE kind='capture' ORDER BY id DESC"):
            record = json.loads(payload)
            captures.append(capture_row(record, root, output_root, starts.get(record.get("run_id")), replay))
        groups = connection.execute("""
            SELECT symbol,channel,json_extract(payload,'$.status'),COUNT(*),MAX(at_ns)
            FROM log WHERE kind='request'
            GROUP BY symbol,channel,json_extract(payload,'$.status')
        """).fetchall()
    request_total = sum(row[3] for row in groups)
    failed = [row for row in groups if row[2] is None or row[2] >= 400]
    failures = [{"symbol": symbol, "channel_label": CHANNELS.get(channel, "其他来源"),
                 "failure_type": f"HTTP {status}" if status is not None else "网络或请求异常",
                 "count": count,
                 "last_seen_beijing": beijing(datetime.fromtimestamp(at_ns / 1e9, timezone.utc))}
                for symbol, channel, status, count, at_ns in failed]
    failures.sort(key=lambda item: item["count"], reverse=True)
    return captures, {"requests": request_total, "failed_requests": sum(row[3] for row in failed), "groups": failures}


def counts(rows):
    measured = [row for row in rows if row["discovery_to_parsed_ms"] is not None]
    passed = sum(row["latency_budget_passed"] is True for row in measured)
    return {"documents": len(rows), "measured": len(measured), "passed": passed,
            "not_passed": len(measured) - passed, "timing_missing": len(rows) - len(measured)}


def cloud_country(node):
    return (node.get("egress_country") or node.get("country")) if isinstance(node, dict) else None


def cloud_region(node):
    if isinstance(node, dict):
        country = cloud_country(node)
        colo = node.get("egress_colo", node.get("colo", ""))
        return " · ".join(str(value) for value, pattern in ((country, r"[A-Z]{2}"), (colo, r"[A-Z]{3}")) if re.fullmatch(pattern, str(value))) or "地区未记录"
    if isinstance(node, str) and re.fullmatch(r"[A-Z]{2}[ /·-]+[A-Z]{3}", node):
        return node
    return "地区未记录"


def read_cloud(root):
    rows = []
    inputs = [("cloud_probe_verified.json", "old_document_download_replay", "旧文档直链重放"),
              ("cloud_discovery_verified.json", "listing_discovery_replay", "列表发现重放")]
    for filename, scope, label in inputs:
        data = read_json(root / filename)
        for probe in data.get("probes", []):
            reference = probe.get("reference") or data.get("reference") or {}
            expected_hash = reference.get("tables_sha256")
            for index, sample in enumerate(probe.get("results", []), 1):
                elapsed = milliseconds(sample.get("discovery_to_parsed_upper_ms"))
                archived = milliseconds(sample.get("discovery_to_archived_ms"))
                complete = data.get("completeness_verified") is True and bool(expected_hash) and sample.get("tables_sha256") == expected_hash
                accepted = sample.get("accepted") is True
                rows.append({
                    "symbol": probe.get("symbol"), "channel": probe.get("channel"), "case": probe.get("case"), "sample": index,
                    "node_region": cloud_region(sample.get("node") or probe.get("node")),
                    "url": public_url(sample.get("final_url") or sample.get("url") or probe.get("url")),
                    "scope": scope,
                    "metric_scope": "云端重放调用至单文档全文解析，不含结果传回国内的耗时。",
                    "started_at_beijing": beijing(sample.get("started_utc") or sample.get("bridge_first_request_utc")),
                    "parsed_at_beijing": beijing(sample.get("parsed_utc")),
                    "status": sample.get("status"),
                    "error_type": "HTTP_" + str(sample["status"]) if (sample.get("status") or 0) >= 400 else None,
                    "attempt_elapsed_ms": milliseconds(sample.get("bridge_roundtrip_ms")) if not accepted else None,
                    "context_label": label,
                    "discovery_to_parsed_ms": elapsed,
                    "request_to_parsed_upper_ms": milliseconds(sample.get("request_to_parsed_upper_ms")),
                    "discovery_to_archived_ms": archived,
                    "archive_readback_verified": data.get("archive_readback_verified") is True if archived is not None else None,
                    "timing_bound": "upper_bound",
                    "accepted": accepted, "completeness_verified": complete,
                    "latency_budget_passed": accepted and complete and elapsed <= BUDGET_MS if elapsed is not None else None,
                    "bytes": sample.get("bytes"),
                    "table_count": len(sample["all_tables"]) if isinstance(sample.get("all_tables"), list) else sample.get("all_tables"),
                })
    return rows


def read_us_runner(root):
    """Keep every archived runner attempt; verify artifacts before accepting its result."""
    rows = []
    for path in sorted(root.glob("us_runner_*/results.ndjson")):
        run = read_json(path.parent / "run.json")
        prior_profile_urls = set()
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            target = record["target_id"]
            issuer_copy = (record.get("symbol") == "MSGK" and record.get("channel") == "official"
                           and record.get("document_variant") == "issuer_copy"
                           and urlsplit(record.get("url", "")).hostname == "investor.msgknicks.com")
            artifacts = record.get("artifacts", [])
            raw_name = next((name for name in artifacts if name in (f"raw/{target}.html", f"raw/{target}.pdf")), None)
            pipeline = record.get("pipeline")
            candidate, seed = {}, {}
            response_complete = record.get("http_response_complete") is True
            if pipeline == "production_watch_list_seed":
                request_name = f"requests_{target}.ndjson"
                request_path = artifact_path(path.parent, request_name, path.parent) if request_name in artifacts else None
                requests = [json.loads(value) for value in (path.parent / request_path).read_text(encoding="utf-8").splitlines() if value.strip()] if request_path else []
                seed = next((item for item in requests if item.get("purpose") == "discovery"
                             and item.get("id") == record.get("seed", {}).get("id")), {})
                candidate = next((item for item in requests if item.get("purpose") == "candidate"
                    and item.get("symbol") == record.get("symbol") and item.get("channel") == record.get("channel")
                    and item.get("url") == record.get("url") and item.get("final_url") == record.get("url")
                    and item.get("status") == 200 and item.get("sha256") == record.get("sha256")
                    and item.get("body_bytes") == record.get("bytes")), {})
                artifact = candidate.get("artifact", "")
                raw_name = artifact if artifact in artifacts and re.fullmatch(r"raw/" + re.escape(target) + r"_\d+_candidate\.(?:html|pdf)", artifact) else None
                times = [date_value(candidate.get(key)) for key in ("request_start_utc", "body_complete_utc", "request_end_utc")]
                parsed_at = date_value(record.get("parsed_utc"))
                monotonic = [candidate.get(key) for key in ("queued_mono_ns", "request_start_mono_ns", "body_complete_mono_ns", "request_end_mono_ns")]
                response_complete = bool(raw_name and all(times) and parsed_at and times[0] <= times[1] <= times[2] <= parsed_at
                    and all(type(value) is int for value in monotonic) and 0 <= monotonic[0] <= monotonic[1] <= monotonic[2] <= monotonic[3])
            parsed_name = f"parsed/{target}.json"
            raw_path = artifact_path(path.parent, raw_name, path.parent) if raw_name else None
            parsed_path = artifact_path(path.parent, parsed_name, path.parent) if parsed_name in artifacts else None
            raw = (path.parent / raw_path).read_bytes() if raw_path else None
            parsed = read_json(path.parent / parsed_path) if parsed_path else {}
            raw_verified = (raw is not None and hashlib.sha256(raw).hexdigest() == record.get("sha256")
                            and len(raw) == record.get("bytes"))
            tables = parsed.get("tables", [])
            tables_verified = bool(parsed) and hashlib.sha256(json.dumps(tables, ensure_ascii=False,
                separators=(",", ":")).encode("utf-8")).hexdigest() == record.get("tables_sha256")
            text_verified = bool(parsed.get("text")) and len(parsed["text"]) == record.get("text_characters")
            if pipeline == "production_watch_list_seed" or record.get("transport") == "curl_cffi_chrome":
                text_verified = text_verified and hashlib.sha256(parsed["text"].encode("utf-8")).hexdigest() == record.get("text_sha256")
                tables_verified = tables_verified and [hashlib.sha256(json.dumps(table, ensure_ascii=False,
                    separators=(",", ":")).encode("utf-8")).hexdigest() for table in tables] == record.get("table_sha256")
            checks = parsed.get("checks", {})
            accepted = (record.get("status") == 200 and response_complete
                        and parsed.get("accepted") is True and all(checks.get(key) is True for key in
                        ("identity", "reporting_period", "not_announcement", "financial_body", "financial_tables")))
            table_complete = (parsed.get("tables_complete") is True and bool(tables)
                              and len(tables) == record.get("table_count"))
            if table_complete and raw_verified:
                if raw.startswith(b"%PDF"):
                    pages = parsed.get("pdf_pages_total")
                    table_complete = (type(pages) is int and pages > 0
                        and parsed.get("pdf_pages_processed") == pages and parsed.get("pdf_pages_text_extracted") == pages
                        and all(parsed.get("pdf_structure_checks", {}).get(key) is True for key in
                            ("all_pages_extracted", "native_layout", "all_table_words_assigned", "numeric_tokens_preserved")))
                else:
                    raw_file, parsed_file = path.parent / raw_path, path.parent / parsed_path
                    table_complete = archived_table_check(str(raw_file), str(parsed_file),
                        raw_file.stat().st_mtime_ns, parsed_file.stat().st_mtime_ns, issuer_copy)[0]
            complete = (record.get("complete") is True and accepted and raw_verified and tables_verified
                        and text_verified and table_complete)
            node = record.get("node") or run.get("node") or {}
            is_us = node.get("loc") == "US" and node.get("is_us") is True and node.get("status") == 200
            error = record.get("error_type")
            error = error if isinstance(error, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error) else None
            if not error and not complete:
                error = ("raw_sha256_mismatch" if not raw_verified else "tables_sha256_mismatch" if not tables_verified
                         else "document_incomplete")
            if not error and not is_us:
                error = "us_node_not_verified"
            elapsed = milliseconds(record.get("discovery_to_parsed_ms")) if record.get("parsed_utc") else None
            archived = record.get("archived") is True
            readback = archived and raw_verified and (tables_verified if record.get("parsed_utc") else True)
            route_note = "发布网站提供的打印入口（print=1）；原发布页状态单独记录。" if urlsplit(record.get("url", "")).query == "print=1" else ""
            pdf_alternative = (record.get("symbol") == "BAM" and record.get("channel") == "newswire"
                               and record.get("document_variant") == "official_pdf_alternative")
            if pdf_alternative:
                route_note = "财经稿（官方PDF备用）"
            elif issuer_copy:
                route_note = "公司官网副本"
            replay_artifacts, report_url, parsed_artifact = [], None, None
            if complete and (pdf_alternative and raw.startswith(b"%PDF") or issuer_copy):
                stem = f"reports/replay_us_{path.parent.name.removeprefix('us_runner_')}_{target}_{record['sha256'][:12]}"
                replay_artifacts = [{"path": stem + suffix, "label": label, "local_only": False}
                                    for suffix, label in ((".html", "公司官网副本解析HTML" if issuer_copy else "官方PDF解析HTML"), (".txt", "全文文本"), (".json", "文本与表格JSON"))]
                report_url = "/employer-files/" + stem + ".html"
                parsed_artifact = (path.parent / parsed_path).relative_to(root).as_posix()
            metric_scope = ("先请求列表，再调用已知旧文档地址并经过生产队列、下载与全文解析；正文耗时从旧URL调用起计，列表请求与归档另列，不代表实时发现。"
                            if pipeline == "production_watch_list_seed" else
                            "美国节点调用已知文档地址起，包含限速排队、真实下载、哈希与全文解析；不含列表发现、归档和传回国内。")
            rows.append({
                "run_id": path.parent.name.removeprefix("us_runner_"), "target_id": target,
                "symbol": record.get("symbol"), "channel": record.get("channel"), "case": target, "sample": index,
                "node_region": cloud_region({"country": node.get("loc"), "colo": node.get("colo")}), "us_node_verified": is_us,
                "url": public_url(record.get("final_url") or record.get("url")),
                "scope": "us_runner_document_replay", "context": "replay", "context_label": "美国节点旧报告重抓", "mode": "replay",
                "metric_scope": metric_scope + route_note,
                "route_note": route_note, "pipeline": pipeline,
                "document_variant": "official_pdf_alternative" if pdf_alternative else "issuer_copy" if issuer_copy else None,
                "actual_source_url": public_url(record.get("final_url") or record.get("url")),
                "pdf_pages_total": parsed.get("pdf_pages_total"),
                "report_url": report_url, "replay_artifacts": replay_artifacts, "parsed_artifact": parsed_artifact,
                "canonical_url": public_url(record.get("canonical_url")), "canonical_previous_status": record.get("canonical_previous_status"),
                "canonical_channel": "newswire" if pdf_alternative or issuer_copy else None,
                "http_response_complete": response_complete, "request_eof_verified": response_complete if pipeline == "production_watch_list_seed" else None,
                "seed_status": seed.get("status"), "seed_url": public_url(seed.get("url")),
                "seed_request_total_ms": milliseconds(seed.get("request_total_ms")),
                "seed_listing_contains_candidate": record.get("seed_listing_contains_candidate"),
                "seed_request_to_parsed_ms": milliseconds(record.get("seed_request_to_parsed_ms")),
                "connection_reused": candidate.get("connection_reused") if pipeline == "production_watch_list_seed" else record.get("connection_reused"),
                "new_tcp_connections": record.get("new_tcp_connections"),
                "transport": record.get("transport") if record.get("transport") == "curl_cffi_chrome" else None,
                "transport_version": record.get("transport_version") if record.get("transport") == "curl_cffi_chrome" else None,
                "curl_cumulative_ms": {key: milliseconds(value) for key, value in record.get("curl_cumulative_ms", {}).items()
                                       if key in ("dns_done", "connect_done", "tls_done", "pretransfer_done", "first_response_byte", "transfer_done")},
                "response_cache_headers": {key: value for key, value in record.get("response_cache_headers", {}).items()
                                           if key in ("age", "x-cache", "cf-cache-status") and isinstance(value, str)},
                "cli_start_to_archived_upper_ms": milliseconds(record.get("cli_start_to_archived_upper_ms")),
                "archive_timing_note": "归档结束没有连续计时；CLI结束只提供上界。" if record.get("archive_timing_note") else None,
                "started_at_beijing": beijing(record.get("started_utc")), "parsed_at_beijing": beijing(record.get("parsed_utc")),
                "ended_at_beijing": beijing(record.get("ended_utc")), "status": record.get("status"), "error_type": error,
                "attempt_elapsed_ms": milliseconds(record.get("invocation_to_end_ms")),
                "invocation_to_end_ms": milliseconds(record.get("invocation_to_end_ms")),
                "discovery_to_parsed_ms": elapsed, "request_to_parsed_upper_ms": None,
                "discovery_to_archived_ms": milliseconds(record.get("invocation_to_archived_ms")) if archived else None,
                "invocation_to_archived_ms": milliseconds(record.get("invocation_to_archived_ms")),
                "archived": archived, "archive_readback_verified": readback,
                "archive_state": "verified" if readback else "unverified" if archived else "failed",
                "timing_basis": "monotonic", "timing_bound": "measured",
                "accepted": accepted, "tables_complete": table_complete, "completeness_verified": complete,
                "latency_budget_passed": bool(complete and is_us and not error and elapsed is not None and elapsed <= BUDGET_MS),
                "bytes": record.get("bytes"), "table_count": record.get("table_count"),
                "sha256": record.get("sha256"), "tables_sha256": record.get("tables_sha256"),
                "raw_sha256_verified": raw_verified, "tables_sha256_verified": tables_verified,
                "text_length_verified": text_verified,
            })
            if record.get("cache_profile") in ("ordinary", "no_cache"):
                profile_url = record.get("url")
                rows[-1].update(cache_profile=record["cache_profile"], prior_target_fetch=profile_url in prior_profile_urls)
                prior_profile_urls.add(profile_url)
    return rows


def read_cloud_observations(root):
    database = root / "cloud_observations.sqlite3"
    if not database.exists():
        return [], {"failed_records": 0, "groups": []}
    captures = []
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        for (payload,) in connection.execute("SELECT payload FROM log WHERE kind='cloud_capture' ORDER BY id DESC"):
            record = json.loads(payload)
            mode = record.get("mode")
            first = record.get("already_present_on_first_poll")
            retry = record.get("retry") is True
            category = ("replay" if mode == "replay" else "retry" if retry else "initially_present" if first is True
                        else "live" if mode == "live" and first is False else "unknown")
            elapsed = milliseconds(record.get("discovery_to_parsed_upper_ms"))
            archived = record.get("archived")
            archive_failed = archived is False or bool(record.get("archive_error"))
            accepted = record.get("accepted") is True
            complete = record.get("tables_complete") is True
            us_qualified = cloud_country(record.get("node")) == "US"
            url = public_url(record.get("url"))
            all_tables = record.get("all_tables")
            captures.append({
                "capture_id": record.get("capture_id"), "symbol": record.get("symbol"),
                "channel": record.get("channel"), "channel_label": CHANNELS.get(record.get("channel"), "其他来源"),
                "mode": mode if mode in ("live", "replay") else None,
                "context": category, "context_label": CONTEXTS[category], "retry": retry,
                "already_present_on_first_poll": first if isinstance(first, bool) else None,
                "title": record.get("title") or f"{record.get('symbol', '')} 财报文档", "url": url,
                "site": urlsplit(url).hostname if url else None, "node_region": cloud_region(record.get("node")),
                # Worker contract: started_utc is the original discovery time, retained across retries.
                "discovered_at_beijing": beijing(record.get("started_utc")),
                "parsed_at_beijing": beijing(record.get("parsed_utc")),
                "bridge_received_at_beijing": beijing(record.get("bridge_received_utc")),
                "discovery_to_parsed_ms": elapsed,
                "request_to_parsed_upper_ms": milliseconds(record.get("request_to_parsed_upper_ms")),
                "discovery_to_archived_ms": milliseconds(record.get("discovery_to_archived_ms")),
                "bridge_roundtrip_ms": milliseconds(record.get("bridge_roundtrip_ms")),
                "attempt_to_parsed_upper_ms": milliseconds(record.get("attempt_to_parsed_upper_ms")),
                "retry_wall_elapsed_ms": milliseconds(record.get("retry_wall_elapsed_ms")),
                "latency_budget_passed": False if retry or not us_qualified else accepted and complete and elapsed <= BUDGET_MS if elapsed is not None else None,
                "us_execution_qualified": us_qualified,
                "accepted": accepted, "tables_complete": complete,
                "table_count": len(all_tables) if isinstance(all_tables, list) else all_tables if isinstance(all_tables, int) else None,
                "archive_state": "failed" if archive_failed else "saved" if archived is True else "unknown",
                "artifacts": cloud_artifacts(record.get("artifacts")) if not archive_failed else [],
            })
        failure_groups = connection.execute("""
            SELECT symbol,channel,json_extract(payload,'$.status'),json_extract(payload,'$.stage'),COUNT(*),MAX(at_ns)
            FROM log WHERE kind='cloud_failure'
            GROUP BY symbol,channel,json_extract(payload,'$.status'),json_extract(payload,'$.stage')
        """).fetchall()
    failures = [{"symbol": symbol, "channel_label": CHANNELS.get(channel, "其他来源"),
                 "failure_type": "归档失败" if stage == "archive" else "云端处理未通过" if status == 200 else f"HTTP {status}" if status is not None else "网络或云端采集异常",
                 "count": count, "last_seen_beijing": beijing(datetime.fromtimestamp(at_ns / 1e9, timezone.utc))}
                for symbol, channel, status, stage, count, at_ns in failure_groups]
    return captures, {"failed_records": sum(row[4] for row in failure_groups), "groups": failures}


def read_attachments(root):
    rows = []
    with closing(sqlite3.connect((root / "observations.sqlite3").resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        for (payload,) in connection.execute("SELECT payload FROM log WHERE kind='attachment' ORDER BY id DESC"):
            record = json.loads(payload)
            symbol = str(record.get("symbol", ""))
            relative = PurePosixPath(str(record.get("original_document_path", "")).replace("\\", "/"))
            path = None
            if (len(relative.parts) >= 4 and relative.parts[:2] == ("attachments", symbol)
                    and re.fullmatch(r"\d{18}", relative.parts[2])):
                path = artifact_path(root, str(relative), root)
                if path and not (root / path).resolve().is_relative_to((root / "attachments").resolve()):
                    path = None
            url = public_url(record.get("url"))
            if url and urlsplit(url).hostname not in ("www.sec.gov", "sec.gov"):
                url = None
            digest = record.get("sha256")
            size = record.get("body_bytes")
            rows.append({
                "symbol": symbol, "form": record.get("form"), "url": url,
                "received_at_beijing": beijing(record.get("original_body_complete_utc") or record.get("body_complete_utc")),
                "archived_at_beijing": beijing(record.get("recovered_utc")),
                "bytes": size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                "sha256": digest if isinstance(digest, str) and re.fullmatch(r"[a-fA-F0-9]{64}", digest) else None,
                "path": path,
                "discovery_to_parsed_ms": None, "latency_budget_passed": None,
            })
    return rows


def read_us_live(root):
    database = root / "us_live_observations.sqlite3"
    if not database.is_file():
        return [], {}, [], {"failed_records": 0, "groups": []}
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        captures = [json.loads(row[0]) for row in connection.execute("SELECT payload FROM captures")]
        runs = [json.loads(row[0]) for row in connection.execute("SELECT payload FROM runs")]
    for row in captures:
        for key in OBSERVATION_FIELDS:
            row.setdefault(key, None)
        if row.get("context") == "live" and not has_negative_observation(row):
            row.update(context="unknown", context_label=CONTEXTS["unknown"],
                       context_explanation="缺少此前未见公告的原始观察时间，不能认作首发记录。")
    captures.sort(key=lambda row: row.get("parsed_at_beijing") or "", reverse=True)
    latest = max(runs, key=lambda row: row.get("updated_utc") or "", default={})
    info = {"run_id": latest.get("run_id"), "state": latest.get("state"), "node_region": latest.get("node_region"),
            "us_execution_qualified": latest.get("us_execution_qualified") is True,
            "heartbeat_at_beijing": beijing(latest.get("collector_heartbeat_utc")),
            "updated_at_beijing": beijing(latest.get("updated_utc")), "until_at_beijing": beijing(latest.get("until_utc")),
            "requests": sum(run.get("request_failures", {}).get("requests", 0) for run in runs),
            "failed_requests": sum(run.get("request_failures", {}).get("failed_requests", 0) for run in runs)}
    failures = [{"symbol": row.get("symbol"), "channel_label": "美国采集器 / " + CHANNELS.get(row.get("channel"), "其他来源"),
                 "failure_type": row.get("failure_type"), "count": row.get("count", 0),
                 "last_seen_beijing": beijing(row.get("lastseen"))}
                for run in runs for row in run.get("failure_groups", [])]
    return captures, info, latest.get("source_patrols", []), {"failed_records": info["failed_requests"], "groups": failures}


def build_progress(runtime, replay_runtimes=None, now=None):
    runtime = Path(runtime).resolve()
    now = now or datetime.now(timezone.utc)
    captures, failures = read_database(runtime, runtime)
    if replay_runtimes is None:
        replay_runtimes = sorted(path for path in runtime.parent.glob("runtime_latency*") if (path / "observations.sqlite3").is_file())
    replays = []
    replay_failures = 0
    for root in replay_runtimes:
        rows, stats = read_database(Path(root).resolve(), runtime, replay=True)
        replays.extend(rows)
        replay_failures += stats["failed_requests"]
    # A replay written into the main database still never becomes live evidence.
    replays.extend(row for row in captures if row["context"] == "replay")
    captures = [row for row in captures if row["context"] != "replay"]
    local_captures = captures
    us_captures, us_live, us_patrols, us_failures = read_us_live(runtime)
    replays.extend(row for row in us_captures if row["context"] == "replay")
    us_captures = [row for row in us_captures if row["context"] != "replay"]
    captures = local_captures + us_captures
    status = read_json(runtime / "status.json")
    heartbeat = date_value(status.get("updated_utc"))
    age = max(0, (now - heartbeat).total_seconds()) if heartbeat else None
    cloud = read_cloud(runtime) + read_us_runner(runtime)
    cloud_captures, cloud_failures = read_cloud_observations(runtime)
    cloud_failures["groups"].extend(us_failures["groups"])
    cloud_failures["failed_records"] += us_failures["failed_records"]
    real_cloud_captures = [row for row in cloud_captures if row["context"] != "replay"]
    actual = captures + real_cloud_captures
    cloud_status = read_json(runtime / "cloud_status.json")
    patrols = source_patrols(status, "本地") + source_patrols(cloud_status, "云端") + us_patrols
    patrols.sort(key=lambda row: row["last_patrol_at_beijing"] or "", reverse=True)
    attachments = read_attachments(runtime)
    return {
        "schema_version": 1,
        "generated_at_beijing": beijing(now),
        "timezone": "Asia/Shanghai",
        "budget_ms": BUDGET_MS,
        "metric": "发现文档至全文解析完成：包含排队、下载和解析；不含后续归档写入。每份文档单独计时，不代表同一财报的全部附件收齐。",
        "heartbeat": {"at_beijing": beijing(heartbeat), "age_seconds": round(age, 1) if age is not None else None,
                      "state": "missing" if age is None else "stale" if age > 120 else "recent"},
        "summary": {"captures": counts(actual), "local_captures": counts(local_captures), "cloud_captures": counts(real_cloud_captures + us_captures),
                    "live": counts([row for row in actual if row["context"] == "live"]),
                    "local_live": counts([row for row in local_captures if row["context"] == "live"]),
                    "cloud_live": counts([row for row in real_cloud_captures + us_captures if row["context"] == "live"]),
                    "contexts": dict(Counter(row["context"] for row in actual)),
                    "companies": len({row["symbol"] for row in actual}), "replays": counts(replays),
                    "cloud_replays": counts(cloud), "replay_failed_requests": replay_failures,
                    "cloud_failed_records": cloud_failures["failed_records"],
                    "support_attachments": len(attachments),
                    "counts_semantics": "本机、美国采集器和云端记录相加，不跨端去重；涉及公司数不表示该公司全部资料已收齐。",
                    "all_new_releases_under_budget_proven": False},
        "captures": captures,
        "attachments": attachments,
        "cloud_captures": cloud_captures,
        "us_live": us_live,
        "cloud_heartbeat_at_beijing": beijing(cloud_status.get("updated_utc")),
        "source_patrols": patrols,
        "cloud_failures": cloud_failures,
        "local_replays": replays,
        "cloud_replays": cloud,
        "request_failures": failures,
        "privacy": "只导出允许展示的字段；无请求头、Cookie、Token、代理地址、本机IP或用户原始文件路径。原文URL的查询参数和片段已移除。",
    }


def esc(value):
    return html.escape(str(value), quote=True)


def time_text(value):
    return value.replace("T", " ").replace("+08:00", "") if value else "—"


def duration_text(value):
    return f"{value:,.3f}" if value is not None else "—"


def result_badge(row):
    if row["latency_budget_passed"] is None:
        return '<span class="badge neutral">计时缺失</span>'
    if row["latency_budget_passed"]:
        return '<span class="badge pass">≤ 300ms</span>'
    return '<span class="badge fail">未达标</span>'


def document_table(rows):
    output = []
    for row in rows:
        link = f'<a href="{esc(row["url"])}" target="_blank" rel="noreferrer noopener">查看公开原文 ↗</a>' if row["url"] else "原文链接未提供"
        artifacts = ' · '.join(f'<a class="local-artifact" href="{esc(quote(item["path"], safe="/._-"))}">{esc(item["label"])}</a><span class="artifact-path">{esc(item["path"])}</span>' for item in row["artifacts"])
        products = (f'{row["table_count"]} 张已提取表格' if row["table_count"] is not None else "表格数量未记录")
        if row["pdf_pages_processed"] is not None:
            products += f' · {row["pdf_pages_processed"]} 页'
        quality = '<span class="badge fail">解析质量未通过 / 表格待核验</span>' if row["accepted"] is False or row["tables_complete"] is False else ""
        output.append(f'''<tr><td class="symbol">{esc(row['symbol'])}</td>
<td>{esc(row['channel_label'])}<span class="sub">{esc(row['site'] or '网站未记录')}</span></td>
<td class="document"><div>{esc(row['title'])}</div><div class="links">{link}</div>{quality}<span class="sub">{esc(products)}</span><div class="links">{artifacts or '本地产物未找到'}</div></td>
<td><span class="badge {row['context']}">{esc(row['context_label'])}</span><details><summary>判定依据</summary>{esc(row['context_explanation'])}</details></td>
<td class="time">{esc(time_text(row['parsed_at_beijing']))}<span class="sub">发现 {esc(time_text(row['discovered_at_beijing']))}</span></td>
<td class="number">{duration_text(row['discovery_to_parsed_ms'])}<span class="sub">{esc(row['timing_start'])}</span></td><td>{result_badge(row)}</td></tr>''')
    return '''<div class="table-scroll"><table><thead><tr><th>公司</th><th>来源网站</th><th>资料与产物</th><th>采集性质</th><th>解析完成 · 北京时间</th><th class="number">发现→全文解析 / ms</th><th>300ms 检查</th></tr></thead><tbody>''' + "".join(output) + ("" if rows else '<tr><td colspan="7" class="empty">暂无记录</td></tr>') + "</tbody></table></div>"


def cloud_capture_table(rows):
    output = []
    for row in rows:
        source = f'<a href="{esc(row["url"])}" target="_blank" rel="noreferrer noopener">公开原文 ↗</a>' if row["url"] else "公开原文未提供"
        artifacts = ' · '.join(f'<a href="{esc(item["url"])}" target="_blank" rel="noreferrer noopener">{esc(item["label"])}</a>' for item in row["artifacts"])
        archive_label = {"saved": "已归档", "failed": "归档失败，未展示产物", "unknown": "归档状态未记录"}[row["archive_state"]]
        total = f'<span class="sub">含列表请求 {duration_text(row["request_to_parsed_upper_ms"])} ms</span>' if row["request_to_parsed_upper_ms"] is not None else ""
        retry = (f'<span class="sub">本次尝试 {duration_text(row["attempt_to_parsed_upper_ms"])} ms<br>重试累计 {duration_text(row["retry_wall_elapsed_ms"])} ms</span>' if row["retry"] else "")
        check = '<span class="badge fail">重试，不计首次达标</span>' if row["retry"] else result_badge(row)
        output.append(f'''<tr><td class="symbol">{esc(row['symbol'] or '—')}</td><td>{esc(row['channel_label'])}<span class="sub">{esc(row['site'] or '网站未记录')}<br>{esc(row['node_region'])}<br>本机往返 {duration_text(row['bridge_roundtrip_ms'])} ms</span></td>
<td class="document">{esc(row['title'])}<div class="links">{source}</div><span class="sub">{esc(row['table_count'] if row['table_count'] is not None else '—')} 张已提取表格 · {esc(archive_label)}</span><div class="links">{artifacts}</div></td>
<td><span class="badge {row['context']}">{esc(row['context_label'])}</span></td><td class="time">{esc(time_text(row['parsed_at_beijing']))}<span class="sub">发现 {esc(time_text(row['discovered_at_beijing']))}</span></td>
<td class="number">{duration_text(row['discovery_to_parsed_ms'])}{total}{retry}</td><td class="number">{duration_text(row['discovery_to_archived_ms'])}</td><td>{check}</td></tr>''')
    return '<div class="table-scroll"><table><thead><tr><th>公司</th><th>来源 / 执行地区</th><th>资料与私人产物</th><th>采集性质</th><th>解析完成 · 北京时间</th><th class="number">发现→解析 / ms</th><th class="number">发现→归档 / ms</th><th>解析 300ms 检查</th></tr></thead><tbody>' + ''.join(output) + ('' if rows else '<tr><td colspan="8" class="empty">尚无云端采集记录；来源巡视状态见下表</td></tr>') + '</tbody></table></div>'


def patrol_table(rows):
    output = []
    for row in rows:
        site = f'<a href="{esc(row["url"])}" target="_blank" rel="noreferrer noopener">{esc(row["site"])}</a>' if row["url"] else "—"
        output.append(f'<tr><td>{esc(row["observer"])}</td><td>{esc(row["symbol"])}</td><td>{esc(row["channel_label"])}</td><td>{site}</td><td>{esc(time_text(row["last_patrol_at_beijing"]))}</td><td>{esc(row["state"])}</td><td>{esc(row["status"] if row["status"] is not None else "—")}</td></tr>')
    return '<div class="table-scroll" style="max-height:340px"><table><thead><tr><th>采集端</th><th>公司</th><th>渠道</th><th>巡视网站</th><th>最近巡视 · 北京时间</th><th>状态</th><th>HTTP</th></tr></thead><tbody>' + ''.join(output) + ('' if rows else '<tr><td colspan="7" class="empty">尚无来源巡视记录</td></tr>') + '</tbody></table></div>'


def attachment_table(rows):
    output = []
    for row in rows:
        public = f'<a href="{esc(row["url"])}" target="_blank" rel="noreferrer noopener">SEC 公开原文 ↗</a>' if row["url"] else "公开原文未提供"
        local = (f'<a class="local-artifact" href="{esc(quote(row["path"], safe="/._-"))}">本机原件</a><span class="sub">{esc(row["path"])}</span>' if row["path"] else "本机原件未找到或路径未通过检查")
        size = f'{row["bytes"]:,}' if row["bytes"] is not None else "—"
        output.append(f'<tr><td class="symbol">{esc(row["symbol"])}</td><td>{esc(row["form"] or "—")}</td><td class="document">{public}<div class="links">{local}</div><details><summary>SHA-256</summary><span style="overflow-wrap:anywhere">{esc(row["sha256"] or "未记录")}</span></details></td><td class="time">{esc(time_text(row["received_at_beijing"]))}</td><td class="time">{esc(time_text(row["archived_at_beijing"]))}</td><td class="number">{size}</td></tr>')
    return '<div class="table-scroll" style="max-height:520px"><table><thead><tr><th>公司</th><th>附件类型</th><th>原文与本机原件</th><th>原始接收 · 北京时间</th><th>恢复归档 · 北京时间</th><th class="number">字节数</th></tr></thead><tbody>' + ''.join(output) + ('' if rows else '<tr><td colspan="6" class="empty">暂无支持附件记录</td></tr>') + '</tbody></table></div>'


def render_html(data):
    summary = data["summary"]
    live = summary["live"]
    heartbeat = data["heartbeat"]
    heartbeat_note = {"recent": "最近两分钟有心跳", "stale": "心跳已超过两分钟，请核查采集器", "missing": "未找到采集器心跳"}[heartbeat["state"]]
    cloud_rows = []
    for row in data["cloud_replays"]:
        content = "正文及表格一致性已验证" if row["accepted"] and row["completeness_verified"] else "全文或一致性未通过"
        if row.get("error_type"):
            content = "错误：" + row["error_type"]
        link = f'<a href="{esc(row["url"])}" target="_blank" rel="noreferrer noopener">公开文档 ↗</a>' if row["url"] else "—"
        total = f'<span class="sub">含列表请求 {duration_text(row["request_to_parsed_upper_ms"])} ms</span>' if row["request_to_parsed_upper_ms"] is not None else ""
        archived = '<span class="sub">归档回读已验证</span>' if row["archive_readback_verified"] else ""
        cloud_rows.append(f'<tr><td>{esc(row["symbol"] or "—")}</td><td>{esc(row["node_region"])}</td><td>{row["sample"]}</td><td>{esc(time_text(row["started_at_beijing"]))}</td><td><span class="badge replay">{esc(row["context_label"])}</span><div>{link}</div><span class="sub">{esc(content)}</span></td><td class="number">{duration_text(row["discovery_to_parsed_ms"])}{total}</td><td class="number">{duration_text(row["discovery_to_archived_ms"])}{archived}</td><td>{result_badge(row)}</td></tr>')
    failures = ''.join(f'<tr><td>{esc(observer)}</td><td>{esc(row["symbol"] or "—")}</td><td>{esc(row["channel_label"])}</td><td>{esc(row["failure_type"])}</td><td class="number">{row["count"]:,}</td><td>{esc(time_text(row["last_seen_beijing"]))}</td></tr>' for observer, groups in [("本地", data["request_failures"]["groups"]), ("云端", data["cloud_failures"]["groups"])] for row in groups)
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>财报采集进展</title><style>
:root{font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif;color:#172536;background:#f4f6f8;font-synthesis:none}*{box-sizing:border-box}body{margin:0;font-size:14px;line-height:1.6}main{max-width:1600px;margin:auto;padding:28px 32px 60px}header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}h1{font-size:25px;margin:0 0 5px;font-weight:650}h2{font-size:18px;margin:0 0 7px}p{margin:5px 0}a{color:#155a9e;text-decoration:none}a:hover{text-decoration:underline}.muted,.sub{color:#586778}.sub{display:block;font-size:12px;margin-top:4px}.stamp{text-align:right;font-size:12px;color:#586778}.verdict{margin:22px 0;padding:18px 20px;background:#fff;border-left:4px solid #a62c25;border-radius:4px}.verdict strong{font-size:21px;color:#92251f}.summary{display:flex;flex-wrap:wrap;gap:8px 28px;margin-top:10px}.summary b{font-variant-numeric:tabular-nums;font-size:17px}section{margin-top:28px}.note{font-size:13px;color:#586778;margin:7px 0 13px}.table-scroll{overflow-x:auto;border:1px solid #d8e0e7;border-radius:5px;background:#fff}table{width:100%;border-collapse:collapse;font-size:13px;min-width:1040px}th{background:#eaf0f5;color:#3b4c5f;text-align:left;font-weight:600;white-space:nowrap}th,td{padding:12px 13px;border-bottom:1px solid #e4e9ee;vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#f8fafc}.symbol{font-weight:700;white-space:nowrap}.document{min-width:260px;max-width:400px;overflow-wrap:anywhere}.links{font-size:12px;margin-top:6px}.artifact-path{display:none}.number{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.number .sub{max-width:150px;white-space:normal;line-height:1.4}.time{font-variant-numeric:tabular-nums;min-width:188px;font-size:12px}.badge{display:inline-block;padding:3px 7px;border-radius:3px;font-size:12px;white-space:nowrap;background:#edf1f4;color:#42566c}.badge.fail{background:#fbe9e7;color:#9b2c25}.badge.pass{background:#e4f2eb;color:#17613c}.badge.live{background:#e6effb;color:#265584}.badge.backfill{background:#fff1d9;color:#805c1e}.badge.replay{background:#edeaf7;color:#5f4b87}details{margin-top:8px;font-size:12px;max-width:210px;color:#586778}summary{cursor:pointer}.empty{text-align:center;color:#586778;padding:26px}footer{margin-top:26px;color:#586778;font-size:12px}.failure-details{max-width:none;font-size:14px}.failure-details>summary{font-weight:600;margin:10px 0}.cloud table{min-width:850px}.cloud td:first-child,.cloud td:nth-child(2){white-space:nowrap}@media(max-width:700px){main{padding:20px 14px 40px}header{display:block}.stamp{text-align:left;margin-top:12px}.summary{gap:6px 18px}.verdict{padding:14px}h1{font-size:22px}}@media print{main{padding:0}.table-scroll{overflow:visible}table{min-width:0;font-size:10px}.artifact-path{display:block;font-size:9px}.local-artifact{display:none}details{display:block}}
</style></head><body><main>''' + f'''
<header><div><h1>财报采集进展</h1><p class="muted">只读进度快照 · 全部时间为北京时间（UTC+8）</p></div><div class="stamp">页面生成 {esc(time_text(data['generated_at_beijing']))}<br>本地采集器心跳 {esc(time_text(heartbeat['at_beijing']))}<br>{esc(heartbeat_note)}<br>云端桥接心跳 {esc(time_text(data['cloud_heartbeat_at_beijing']))}</div></header>
<div class="verdict"><strong>实时新增：{live['passed']} / {live['measured']} 份已计时文档在 300ms 内完成</strong><p>尚未证明所有新公告均达到 300ms。首次已存在、事后补采、重试和旧文档重放单独展示。</p><div class="summary"><span>实际采集记录 <b>{summary['captures']['documents']}</b> 条（本地 {summary['local_captures']['documents']} / 云端 {summary['cloud_captures']['documents']}）</span><span>涉及 <b>{summary['companies']}</b> 家公司</span><span>计时缺失 <b>{summary['captures']['timing_missing']}</b> 条</span><span>失败记录 本地 <b>{data['request_failures']['failed_requests']:,}</b> / 云端 <b>{summary['cloud_failed_records']:,}</b></span></div><p class="note">{esc(summary['counts_semantics'])}</p></div>
<section><h2>云端采集记录</h2><p class="note">发现→解析不含归档和返回本机；归档、含列表请求和本机往返分别展示。重试保留首次发现时刻，不用本次尝试的快速结果冒充首次达标。私人产物需要站点权限，无权限可查看公开原文；重放记录不计入实际采集统计。</p>{cloud_capture_table(data['cloud_captures'])}</section>
<section><h2>来源巡视状态</h2><p class="note">暂无新稿也保留最近巡视时间；等待窗口与请求失败分开显示。这里的状态不表示该公司所有资料已收齐。</p>{patrol_table(data['source_patrols'])}</section>
<section><h2>本地实际采集的资料</h2><p class="note">{esc(data['metric'])} “—” 表示没有计时记录，不能用下载时间替代。0 达标按 0 展示。</p>{document_table(data['captures'])}</section>
<section><details id="support-attachments" class="failure-details"><summary>{len(data['attachments'])} 份支持附件</summary><p class="note">支持附件单独展示，不计入财务文档数量或 300ms 成绩。原始接收与事后恢复归档时间分别保留；没有跨运行的完整计时，耗时保持为空。本机原件链接仅在本机打开本页时有效。</p>{attachment_table(data['attachments'])}</details></section>
<section><h2>本地旧公开文档性能重放</h2><p class="note">{summary['replays']['passed']} / {summary['replays']['measured']} 个已计时样本在 300ms 内完成；另有 {summary['replay_failed_requests']} 次重放请求失败。这里的成功不计入实时新增验收。</p>{document_table(data['local_replays'])}</section>
<section class="cloud"><h2>云端旧公开文档性能重放</h2><p class="note">{summary['cloud_replays']['passed']} / {summary['cloud_replays']['measured']} 个已计时样本解析通过。逐项展示所有地区与失败样本；解析耗时为记录的上界，归档耗时另列，解析达标不代表归档达标。均不含结果传回国内，不代表新发布公告 SLA。</p><div class="table-scroll"><table><thead><tr><th>公司</th><th>执行地区</th><th>样本</th><th>开始 · 北京时间</th><th>资料核验</th><th class="number">发现→解析 / ms</th><th class="number">发现→归档 / ms</th><th>解析 300ms 检查</th></tr></thead><tbody>{''.join(cloud_rows) or '<tr><td colspan="8" class="empty">暂无已保存的云端重放结果</td></tr>'}</tbody></table></div></section>
<section><h2>失败记录</h2><p class="note">本地累计 {data['request_failures']['requests']:,} 次请求，{data['request_failures']['failed_requests']:,} 次为网络异常或 HTTP 400 及以上；另有 {summary['cloud_failed_records']:,} 条云端请求或处理失败。HTTP 304 不算失败；失败不会被计为低延迟成功。</p><details class="failure-details"><summary>按采集端、公司、渠道和错误类型查看全部累计数</summary><div class="table-scroll"><table><thead><tr><th>采集端</th><th>公司</th><th>渠道</th><th>失败类型</th><th class="number">次数</th><th>最近发生 · 北京时间</th></tr></thead><tbody>{failures or '<tr><td colspan="6" class="empty">没有失败记录</td></tr>'}</tbody></table></div></details></section>
<footer>本页不含请求头、Cookie、Token、代理地址或本机路径。公开原文可联网查看；私人云端产物保持站点原有权限，本地产物链接只在本机有效。静态快照不会自行更新，以上方生成时间和两端心跳为准。</footer>
</main><script>if(location.protocol!=="file:"){{document.querySelectorAll(".local-artifact").forEach(a=>{{a.removeAttribute("href");a.title="仅在本机可用";a.textContent+="（仅本地）";}});}}</script></body></html>'''


def generate_progress(runtime=BASE / "runtime", replay_runtimes=None):
    runtime = Path(runtime)
    data = build_progress(runtime, replay_runtimes)
    for name, content in (("progress.json", json.dumps(data, ensure_ascii=False, indent=2)), ("progress.html", render_html(data))):
        target = runtime / name
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=runtime,
                                             prefix=f".{name}.", suffix=".tmp", delete=False) as output:
                temporary = Path(output.name)
                output.write(content)
            for attempt in range(3):
                try:
                    temporary.replace(target)
                    break
                except PermissionError:
                    # Concurrent Windows replacements can briefly deny access.
                    if attempt == 2:
                        raise
                    time.sleep(0.02)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=BASE / "runtime")
    parser.add_argument("--replay-runtime", type=Path, action="append", help="Repeat for replay databases; omitted: read sibling runtime_latency* databases")
    args = parser.parse_args()
    data = generate_progress(args.runtime, args.replay_runtime)
    print(json.dumps({"captures": data["summary"]["captures"], "live": data["summary"]["live"],
                      "local_replays": data["summary"]["replays"], "cloud_replays": data["summary"]["cloud_replays"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
