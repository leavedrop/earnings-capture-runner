"""Publish a strict public-document allowlist to the owner's private progress repo."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import progress


BASE = Path(__file__).resolve().parent
REPOSITORY = "leavedrop/earnings-watch-progress"
REPOSITORY_URL = "https://github.com/" + REPOSITORY
UNTIL = "2026-11-17T13:10:00+08:00"
ROW_FIELDS = (
    "symbol", "channel", "channel_label", "site", "title", "document_kind", "url", "url_parameters_removed",
    "context", "context_label", "context_explanation", "already_present_on_first_poll", "mode", "retry",
    "discovered_at_beijing", "parsed_at_beijing", "discovery_to_parsed_ms", "request_total_ms",
    "queue_ms", "parse_ms", "validation_queue_ms",
    "body_to_validation_ms", "timing_start", "latency_budget_passed", "accepted", "tables_complete",
    "table_count", "pdf_pages_processed",
    "timing_basis", "timing_note", "quality_note",
    "evidence_id", "run_id", "observer", "node_region", "us_execution_qualified", "bridge_received_at_beijing", "archive_readback_verified",
) + progress.OBSERVATION_FIELDS
CLOUD_FIELDS = (
    "symbol", "case", "sample", "node_region", "url", "metric_scope", "started_at_beijing",
    "context_label", "discovery_to_parsed_ms", "timing_bound", "accepted", "completeness_verified",
    "latency_budget_passed", "bytes", "table_count", "scope", "channel", "parsed_at_beijing",
    "request_to_parsed_upper_ms", "discovery_to_archived_ms", "archive_readback_verified",
    "run_id", "target_id", "context", "mode", "us_node_verified", "status", "error_type", "ended_at_beijing",
    "attempt_elapsed_ms", "invocation_to_end_ms", "invocation_to_archived_ms", "archived", "archive_state",
    "timing_basis", "tables_complete", "sha256", "tables_sha256", "raw_sha256_verified",
    "tables_sha256_verified", "text_length_verified",
    "route_note", "pipeline", "canonical_url", "canonical_previous_status", "http_response_complete", "request_eof_verified",
    "discovery_route", "discovery_clock_preserved",
    "seed_status", "seed_url", "seed_request_total_ms", "seed_listing_contains_candidate", "seed_request_to_parsed_ms",
    "connection_reused", "cli_start_to_archived_upper_ms", "archive_timing_note",
    "document_variant", "actual_source_url", "canonical_channel", "pdf_pages_total", "report_url", "replay_artifacts",
    "new_tcp_connections", "response_cache_headers",
    "transport", "transport_version", "curl_cumulative_ms",
    "cache_profile", "prior_target_fetch",
)
CLOUD_CAPTURE_FIELDS = ROW_FIELDS + (
    "capture_id", "node_region", "bridge_received_at_beijing", "request_to_parsed_upper_ms",
    "discovery_to_archived_ms", "bridge_roundtrip_ms", "attempt_to_parsed_upper_ms",
    "retry_wall_elapsed_ms", "archive_state", "us_execution_qualified",
)
PATROL_FIELDS = (
    "observer", "symbol", "channel", "channel_label", "url", "site", "state", "status",
    "last_patrol_at_beijing", "new_count", "bridge_roundtrip_ms",
    "request_start_utc", "request_end_utc", "request_start_mono_ns", "request_end_mono_ns",
    "request_start_at_beijing", "request_end_at_beijing",
    "last_negative_listing_ns", "last_negative_listing_mono_ns",
    "last_negative_listing_utc", "last_negative_listing_at_beijing", "listing_observation_gap_ms",
)
FAILURE_FIELDS = ("symbol", "channel_label", "failure_type", "count", "last_seen_beijing")
ATTACHMENT_FIELDS = ("symbol", "form", "url", "received_at_beijing", "archived_at_beijing",
                     "bytes", "sha256", "path", "discovery_to_parsed_ms", "latency_budget_passed",
                     "supporting_title", "supporting_document", "pdf_pages_total", "pdf_pages_processed", "artifacts",
                     "evidence_id", "log_id", "observer", "mode", "retry", "discovered_utc", "validated_utc",
                     "discovered_mono_ns", "validated_mono_ns", "already_present_on_first_poll",
                     "last_negative_listing_ns", "last_negative_listing_mono_ns")
COUNT_FIELDS = ("documents", "measured", "passed", "not_passed", "timing_missing")
CONTEXTS = {"live", "initially_present", "backfill", "recovery", "replay", "retry", "unknown"}
REPORT_NAME = re.compile(r"[A-Za-z0-9._-]+_(?:official|sec|newswire)_[a-fA-F0-9]{12}\.(?:txt|html|pdf)")
PUBLISHED_REPORT = re.compile(r"reports/(?:live|initially_present|backfill|recovery|replay|retry|unknown)_[A-Za-z0-9._-]+\.(?:html|txt|json)")
PUBLISHED_ATTACHMENT = re.compile(r"attachments/(?P<symbol>[A-Za-z0-9][A-Za-z0-9._-]*)/[0-9]{18}/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:htm|html|xml|xsd|txt|pdf)", re.I)
SENSITIVE_TEXT = re.compile(r"(?i)(?:[a-z]:[\\/]users[\\/]|[a-z]:[\\/]Hermes_project[\\/]|"
                            r"gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})")


def pick(value, names):
    return {name: value[name] for name in names if name in value}


def safe_projection(data):
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported progress schema; publication stopped")
    result = pick(data, ("schema_version", "generated_at_beijing", "timezone", "budget_ms", "metric"))
    result["heartbeat"] = pick(data["heartbeat"], ("at_beijing", "age_seconds", "state"))
    summary = data["summary"]
    result["summary"] = pick(summary, ("companies", "replay_failed_requests", "cloud_failed_records",
                                       "counts_semantics", "all_new_releases_under_budget_proven"))
    result["summary"]["contexts"] = {key: value for key, value in summary.get("contexts", {}).items() if key in CONTEXTS}
    for key in ("captures", "live", "replays", "cloud_replays"):
        result["summary"][key] = pick(summary[key], COUNT_FIELDS)
    for key in ("local_captures", "cloud_captures", "local_live", "cloud_live"):
        if key in summary:
            result["summary"][key] = pick(summary[key], COUNT_FIELDS)
    result["summary"]["support_attachments"] = summary.get("support_attachments", 0)
    result["attachments"] = [pick(row, ATTACHMENT_FIELDS) for row in data.get("attachments", [])]
    for row in result["attachments"]:
        row["url"] = progress.public_url(row.get("url"))
        if progress.recognized_achr_attachment(row):
            row["supporting_document"] = pick(row["supporting_document"], progress.SUPPORT_FIELDS)
            row["artifacts"] = [pick(item, ("path", "label", "local_only")) for item in row.get("artifacts", [])]
            row["discovery_to_parsed_ms"] = progress.milliseconds(row.get("discovery_to_parsed_ms"))
        else:
            row["discovery_to_parsed_ms"] = None
            row.pop("artifacts", None)
        row["latency_budget_passed"] = None
    for group in ("captures", "local_replays"):
        result[group] = []
        for source in data[group]:
            row = pick(source, ROW_FIELDS)
            row["url"] = progress.public_url(row.get("url"))
            row["artifacts"] = []
            if row.get("context") not in CONTEXTS:
                row.update(context="unknown", context_label="采集时机未记录")
            result[group].append(row)
    result["cloud_replays"] = [pick(row, CLOUD_FIELDS) for row in data["cloud_replays"]]
    for row in result["cloud_replays"]:
        row["url"] = progress.public_url(row.get("url"))
    result["cloud_captures"] = []
    for source in data.get("cloud_captures", []):
        row = pick(source, CLOUD_CAPTURE_FIELDS)
        row["url"] = progress.public_url(row.get("url"))
        row["artifacts"] = progress.cloud_artifacts([item.get("url") for item in source.get("artifacts", [])]) if row.get("archive_state") != "failed" else []
        result["cloud_captures"].append(row)
    result["cloud_heartbeat_at_beijing"] = data.get("cloud_heartbeat_at_beijing")
    result["us_live"] = pick(data.get("us_live", {}), ("run_id", "state", "node_region", "us_execution_qualified",
        "heartbeat_at_beijing", "updated_at_beijing", "until_at_beijing", "requests", "failed_requests",
        "selected_run_id", "selection_status", "bridge_state", "selection_checked_at_beijing"))
    result["source_patrols"] = [pick(row, PATROL_FIELDS) for row in data.get("source_patrols", [])]
    for row in result["source_patrols"]:
        row["url"] = progress.public_url(row.get("url"))
    cloud_failures = data.get("cloud_failures", {"failed_records": 0, "groups": []})
    result["cloud_failures"] = pick(cloud_failures, ("failed_records",))
    result["cloud_failures"]["groups"] = [pick(row, FAILURE_FIELDS) for row in cloud_failures["groups"]]
    failures = data["request_failures"]
    result["request_failures"] = pick(failures, ("requests", "failed_requests"))
    result["request_failures"]["groups"] = [pick(row, FAILURE_FIELDS)
                                                   for row in failures["groups"]]
    result["privacy"] = "私有进展快照；仅白名单进展字段、公开财报提取文本/表格及SEC支持附件原件，不含采集请求元数据。"
    return result


def render_tables(tables, table_spans=None):
    """Render the stored cells without discarding their original row/column spans."""
    if table_spans is not None:
        from sources import check_table_spans
        check_table_spans(tables, table_spans)
    parts = []
    for ti, table in enumerate(tables):
        parts.append("<table>")
        for ri, cells in enumerate(table):
            parts.append("<tr>")
            for ci, value in enumerate(cells):
                spans = table_spans[ti][ri][ci] if table_spans is not None else (1, 1)
                attributes = "".join(f' {name}="{span}"' for name, span in zip(("rowspan", "colspan"), spans) if span != 1)
                parts.append("<td" + attributes + ">" + html.escape(str("" if value is None else value)) + "</td>")
            parts.append("</tr>")
        parts.append("</table>")
    return "".join(parts)


def derived_documents(source_row, row, runtime):
    """Read only a listed report text, and export JSON without its metadata."""
    verified_alternative = (source_row.get("symbol") == "BAM" and source_row.get("channel") == "newswire"
                            and source_row.get("document_variant") == "official_pdf_alternative" or
                            source_row.get("symbol") == "MSGK" and source_row.get("channel") == "official"
                            and source_row.get("document_variant") == "issuer_copy")
    if verified_alternative:
        if source_row.get("completeness_verified") is not True:
            return {}
        relative = source_row.get("parsed_artifact") or ""
        source = (runtime / relative).resolve()
        if (not re.fullmatch(r"us_runner_[0-9]+/parsed/[A-Za-z0-9._-]+\.json", relative)
                or not source.is_relative_to(runtime) or not source.is_file()):
            raise ValueError("Runner artifact is outside the approved parsed directories")
        report = json.loads(source.read_text(encoding="utf-8"))
        text = report["text"]
        stem = source_row["replay_artifacts"][0]["path"].removesuffix(".html")
        if not PUBLISHED_REPORT.fullmatch(stem + ".html"):
            raise ValueError("Runner export is outside the report allowlist")
    else:
        text_artifact = next((item for item in source_row.get("artifacts", []) if str(item.get("path", "")).endswith(".txt")), None)
        if text_artifact is None:
            return {}
        source = (runtime / text_artifact["path"]).resolve()
        root = source.parent.parent
        if (source.parent.name != "reports" or root.parent != runtime.parent or
                not (root == runtime or root.name.startswith(("runtime_latency", "runtime_recovery"))) or
                not REPORT_NAME.fullmatch(source.name) or not source.is_file()):
            raise ValueError("Artifact is outside the approved report directories")
        text = source.read_text(encoding="utf-8")
        report = json.loads(source.with_suffix(".json").read_text(encoding="utf-8"))
        stem = "reports/" + row["context"] + "_" + source.stem
    tables = report.get("tables", [])
    if not isinstance(tables, list) or any(not isinstance(table, list) or
            any(not isinstance(cells, list) or any(not isinstance(cell, (str, int, float, bool, type(None))) for cell in cells)
                for cells in table) for table in tables):
        raise ValueError("Unexpected table structure; metadata will not be published")
    table_html = render_tables(tables, report.get("table_spans"))
    quality_warning = ('<p class="quality-warning" role="alert" style="padding:12px 16px;border:2px solid #a32b23;background:#fff1ef;color:#8b1e17;font-weight:700">解析质量未通过 / 表格待核验</p>'
                       if row.get("accepted") is False or row.get("tables_complete") is False else "")
    document = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>财报提取文本与表格</title>'
                '<style>body{max-width:1200px;margin:32px auto;font-family:system-ui;line-height:1.6}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;margin:24px 0}td{border:1px solid #ccc;padding:6px}</style>'
                + quality_warning + '<h1>财报提取文本与表格</h1><p>来自公开财报；此文件为解析产物，原文请使用进展表中的公开链接。</p><pre>'
                + html.escape(text) + "</pre>" + table_html + "</html>")
    row["artifacts"] = [{"label": label, "path": stem + suffix, "local_only": False}
                        for suffix, label in ((".html", "解析HTML"), (".txt", "全文文本"), (".json", "文本与表格JSON"))]
    return {stem + ".txt": text, stem + ".html": document,
            stem + ".json": json.dumps({"text": text, "tables": tables, "accepted": row.get("accepted"),
                                        "tables_complete": row.get("tables_complete"),
                                        **{key: report[key] for key in ("table_spans", "spreadsheet") if key in report}}, ensure_ascii=False, indent=2)}


def cell(value):
    return html.escape(str(value if value is not None else "—")).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def budget(row):
    value = row.get("latency_budget_passed")
    return "达标 ≤300ms" if value is True else "未达标" if value is False else "未计时，不判达标"


def report_table(rows):
    lines = ["| 公司 | 来源站点 | 报告与产物 | 采集性质 | 解析完成（北京时间） | 完整性 | 发现→解析 / ms | 300ms |",
             "|---|---|---|---|---|---|---:|---|"]
    for row in rows:
        site = f'[{cell(row.get("site") or row["channel_label"])}]({row["url"]})' if row.get("url") else cell(row["channel_label"])
        links = " · ".join(f'[{cell(item["label"])}]({item["path"]})' for item in row["artifacts"])
        integrity = ("正文已验证" if row.get("accepted") else "正文未通过") + "；" + ("全部检测表格已提取" if row.get("tables_complete") is True else "全表完整性未确认")
        integrity += f'；{row["table_count"]} 表' if row.get("table_count") is not None else ""
        value = row.get("discovery_to_parsed_ms")
        duration = f"{value:.3f}" if value is not None else "—"
        lines.append(f'| {cell(row["symbol"])} | {site} | {cell(row["title"])}<br>{links} | {cell(row["context_label"])} | {cell(progress.time_text(row.get("parsed_at_beijing")))} | {cell(integrity)} | {duration} | {budget(row)} |')
    if not rows:
        lines.append("| — | — | 暂无记录 | — | — | — | — | — |")
    return "\n".join(lines)


def cloud_capture_table(rows):
    lines = ["| 公司 | 渠道/站点/地区 | 报告与产物 | 采集性质 | 解析完成（北京时间） | 正文/表格 | 归档 | 发现→解析 / ms | 发现→归档 / ms | 国内桥接往返 / ms | 解析300ms |",
             "|---|---|---|---|---|---|---|---:|---:|---:|---|"]
    for row in rows:
        site = f'[{cell(row.get("site") or row["channel_label"])}]({row["url"]})' if row.get("url") else cell(row["channel_label"])
        links = " · ".join(f'[{cell(item["label"])}]({item["url"]})' for item in row["artifacts"])
        complete = ("正文通过" if row["accepted"] else "正文未通过") + "；" + ("全部检测表格已提取" if row["tables_complete"] else "全表未确认")
        complete += f'；{row["table_count"]} 表' if row.get("table_count") is not None else ""
        archive = {"saved": "已保存", "failed": "归档失败", "unknown": "未记录"}[row["archive_state"]]
        category = row["context_label"]
        if row.get("already_present_on_first_poll") is True and row["context"] != "initially_present":
            category += "；首次轮询已存在"
        if row.get("retry") and row["context"] != "retry":
            category += "；重试"
        lines.append(f'| {cell(row["symbol"])} | {cell(row["channel_label"])}<br>{site}<br>{cell(row["node_region"])} | {cell(row["title"])}<br>{links or "私人产物链接未提供"} | {cell(category)} | {cell(progress.time_text(row.get("parsed_at_beijing")))} | {cell(complete)} | {archive} | {progress.duration_text(row.get("discovery_to_parsed_ms"))} | {progress.duration_text(row.get("discovery_to_archived_ms"))} | {progress.duration_text(row.get("bridge_roundtrip_ms"))} | {budget(row)} |')
    if not rows:
        lines.append("| — | — | 暂无记录 | — | — | — | — | — | — | — | — |")
    return "\n".join(lines)


def patrol_table(rows):
    lines = ["| 公司 | 执行端 | 渠道/站点 | 最后巡视（北京时间） | 结果 | HTTP | 本次记录 | 国内桥接往返 / ms |",
             "|---|---|---|---|---|---:|---:|---:|"]
    for row in rows:
        site = f'[{cell(row.get("site") or row["channel_label"])}]({row["url"]})' if row.get("url") else cell(row["channel_label"])
        lines.append(f'| {cell(row["symbol"])} | {cell(row["observer"])} | {cell(row["channel_label"])}<br>{site} | {cell(progress.time_text(row.get("last_patrol_at_beijing")))} | {cell(row["state"])} | {cell(row.get("status"))} | {cell(row.get("new_count"))} | {progress.duration_text(row.get("bridge_roundtrip_ms"))} |')
    if not rows:
        lines.append("| — | — | — | — | 暂无巡视记录 | — | — | — |")
    return "\n".join(lines)


def attachment_table(rows):
    lines = ["| 公司 | 类型 | 原文/私有原件 | 原始接收（北京时间） | 补存归档（北京时间） | 字节 | SHA-256 |",
             "|---|---|---|---|---|---:|---|"]
    for row in rows:
        public = f'[公开原文]({row["url"]})' if row.get("url") else "公开链接未提供"
        if progress.recognized_achr_attachment(row):
            public += "；16页原生文字已保留，图片/轮廓文字见原PDF，不参与300ms成绩"
        lines.append(f'| {cell(row["symbol"])} | {cell(row["form"])} | {public} · [私有原件]({row["path"]}) | {cell(progress.time_text(row.get("received_at_beijing")))} | {cell(progress.time_text(row.get("archived_at_beijing")))} | {row["bytes"]:,} | {cell(row["sha256"])} |')
    if not rows:
        lines.append("| — | — | 暂无支持附件 | — | — | — | — |")
    return "\n".join(lines)


def readme(data):
    summary = data["summary"]
    live = summary["live"]
    output = ["# 财报采集进展", "", f'更新时间：**{progress.time_text(data["generated_at_beijing"])}（北京时间）**。每 10 分钟自动同步，截止北京时间 {datetime.fromisoformat(UNTIL).astimezone(progress.BEIJING).strftime("%Y-%m-%d %H:%M")}。',
              "", f'实时新增已计时：**{live["passed"]} / {live["measured"]}** 份达到 300ms；另有 {live["timing_missing"]} 份缺少完整计时。**尚未证明所有新公告均达到 300ms。**',
              "", f'已记录 {summary["captures"]["documents"]} 份采集记录，涉及 {summary["companies"]} 家公司。本地采集器最近心跳：{progress.time_text(data["heartbeat"]["at_beijing"])}；云端桥接最近更新：{progress.time_text(data.get("cloud_heartbeat_at_beijing"))}。',
              "", "[结构化进展](progress.json) · [进展 HTML（下载后打开）](progress.html)", "", data["metric"],
              "", "完整性列描述单份正文与检测表格；不把一份简版公告等同于同季全部文件收齐。列表收齐后计时的记录，不代表已测到最早可识别候选字节。", ""]
    if data.get("next_window_start_beijing"):
        output += [f'下一批尚未进入的监控窗口：**{progress.time_text(data["next_window_start_beijing"])}（北京时间）**起。窗口开始不等于公告已经发布；此前的夜间复测明确列为旧公告重放。', ""]
    if summary.get("counts_semantics"):
        output += [summary["counts_semantics"], ""]
    for title, rows in (("本地实时观察到新增", [r for r in data["captures"] if r["context"] == "live"]),
                        ("本地首次已存在、事后补采及未确定时机", [r for r in data["captures"] if r["context"] not in ("live", "recovery")]),
                        ("本地历史原文恢复", [r for r in data["captures"] if r["context"] == "recovery"]),
                        ("本地旧公告重放（不计入实时新增）", data["local_replays"])):
        output += ["## " + title, "", report_table(rows), ""]
    output += [f'<details><summary>支持附件：{summary["support_attachments"]} 份（独立原件归档）</summary>', "",
               "这些支持附件与财务正文分开展示，不计入财务采集份数或 300ms 成绩。原件逐份核对 SHA-256；原始接收与补存归档时间分别保留。", "",
               attachment_table(data["attachments"]), "", "</details>", ""]
    cloud_captures = data["cloud_captures"]
    output += ["## 云端采集器记录", "", "发现→解析为云端计时；归档及国内桥接往返单列，不能将其中一项替代国内端到端耗时。首次已存在、重试和重放不计入实时新增；重试保留原始发现时间。私人产物链接需要对应站点访问权限。", ""]
    for title, rows in (("云端实时观察到新增", [row for row in cloud_captures if row["context"] == "live"]),
                        ("云端首次已存在、重试及未确定时机", [row for row in cloud_captures if row["context"] not in ("live", "replay")]),
                        ("云端采集链路重放（不计入实时新增）", [row for row in cloud_captures if row["context"] == "replay"])):
        output += ["### " + title, "", cloud_capture_table(rows), ""]
    output += ["## 云端旧公告重放（不含结果返回国内）", "", "| 公司 | 地区 | 类型/样本 | 开始（北京时间） | 正文/表格一致性 | 解析上界 / ms | 归档 / ms | 归档读回 | 解析300ms |", "|---|---|---|---|---|---:|---:|---|---|"]
    for row in data["cloud_replays"]:
        duration = f'{row["discovery_to_parsed_ms"]:.3f}' if row.get("discovery_to_parsed_ms") is not None else "—"
        complete = "通过" if row.get("accepted") and row.get("completeness_verified") else "未通过"
        if row.get("error_type"):
            complete = "错误：" + cell(row["error_type"])
        archived = f'{row["discovery_to_archived_ms"]:.3f}' if row.get("discovery_to_archived_ms") is not None else "—"
        readback = "已读回" if row.get("archive_readback_verified") else "未验证"
        scope = {"old_document_download_replay": "旧公告下载重放", "listing_discovery_replay": "旧列表发现重放"}.get(row.get("scope"), "旧公告重放")
        output.append(f'| {cell(row["symbol"])} | {cell(row["node_region"])} | {scope} / {row["sample"]} | {cell(progress.time_text(row.get("started_at_beijing")))} | {complete} | {duration} | {archived} | {readback} | {budget(row)} |')
    output += ["", "解析达标不等于归档也在300ms内；未记录归档耗时按缺失展示。云端重放成功不能作为实时新公告或返回国内全链路达标证明。", "",
               "## 来源最后巡视状态", "", patrol_table(data["source_patrols"]), "", "本次未新增记录表示本轮没有新增入库记录，不能据此认定没有新公告；请求进行中、巡视失败与等待发布窗口分别展示。", "", "## 请求情况", "",
               f'主采集累计 {data["request_failures"]["requests"]:,} 次请求，其中 {data["request_failures"]["failed_requests"]:,} 次为网络异常或 HTTP 400 以上。失败不计作低延迟成功，HTTP 304 不算失败。',
               f'云端另有 {data["cloud_failures"]["failed_records"]:,} 条采集失败记录。',
               "", "本仓库为私有，未邀请其他用户；未配置 GitHub Actions 或 Pages。产物仅含公开财务正文与表格、SEC支持附件原件，不含请求头、Cookie、SQLite、源清单或本机路径。", ""]
    return "\n".join(output)


def build_export(data, runtime, next_window=None):
    runtime = Path(runtime).resolve()
    published = safe_projection(data)
    published["next_window_start_beijing"] = next_window
    files = {}
    for group in ("captures", "local_replays"):
        for source_row, row in zip(data[group], published[group]):
            files.update(derived_documents(source_row, row, runtime))
    for source_row, row in zip(data["cloud_replays"], published["cloud_replays"]):
        if source_row.get("document_variant") in ("official_pdf_alternative", "issuer_copy"):
            files.update(derived_documents(source_row, row, runtime))
    for row in published["attachments"]:
        if progress.recognized_achr_attachment(row):
            artifacts = row.get("artifacts", [])
            if {Path(item["path"]).suffix for item in artifacts} != {".pdf", ".txt", ".json"}:
                raise ValueError("Supporting letter files incomplete")
            for item in artifacts:
                relative = item["path"].replace("\\", "/")
                source = (runtime / relative).resolve()
                if not progress.ACHR_SUPPORT_FILE.fullmatch(relative) or source.parent != runtime / "reports":
                    raise ValueError("Supporting letter outside approved reports directory")
                body = source.read_bytes()
                if source.suffix == ".pdf" and (len(body) != row["bytes"] or hashlib.sha256(body).hexdigest() != row["sha256"]):
                    raise ValueError("Supporting letter original mismatch")
                if source.suffix == ".json":
                    parsed = json.loads(body)
                    if parsed["text"] != source.with_suffix(".txt").read_text(encoding="utf-8") or parsed["supporting_document"] != row["supporting_document"]:
                        raise ValueError("Supporting letter native text mismatch")
                    body = json.dumps({key: parsed[key] for key in ("text", "tables", "table_spans", "page_diagnostics",
                        "pdf_pages_total", "pdf_pages_processed", "pdf_pages_text_extracted", "pdf_metadata", "supporting_document")}, ensure_ascii=False).encode()
                files[relative] = body
            continue
        if not row.get("path"):
            continue  # Keep its recorded metadata and public source; no local file was archived.
        relative = row["path"].replace("\\", "/")
        match = PUBLISHED_ATTACHMENT.fullmatch(relative)
        source = (runtime / relative).resolve()
        if (not match or match["symbol"] != row["symbol"] or
                not source.is_relative_to(runtime / "attachments" / row["symbol"]) or not source.is_file()):
            raise ValueError("Attachment is outside the approved company directory")
        body = source.read_bytes()
        if hashlib.sha256(body).hexdigest() != row["sha256"].lower():
            raise ValueError("Attachment SHA-256 mismatch; publication stopped")
        row.update(path=relative, bytes=len(body))
        files[relative] = body
    from lxml import html as lxml_html
    tree = lxml_html.fromstring(progress.render_html(published))
    for script in tree.xpath("//script"):
        script.drop_tree()
    for footer in tree.xpath("//footer"):
        footer.text = "私有仓库每10分钟更新。解析产物随仓库提供；下载仓库后可打开HTML及相对链接。以上方生成时间和采集器心跳为准。"
    files.update({"README.md": readme(published), "progress.json": json.dumps(published, ensure_ascii=False, indent=2),
                  "progress.html": "<!doctype html>" + lxml_html.tostring(tree, encoding="unicode")})
    for path, content in files.items():
        if path not in ("README.md", "progress.json", "progress.html") and not PUBLISHED_REPORT.fullmatch(path) and not PUBLISHED_ATTACHMENT.fullmatch(path) and not progress.ACHR_SUPPORT_FILE.fullmatch(path):
            raise ValueError("Export path is outside the publish allowlist")
        if SENSITIVE_TEXT.search(content if isinstance(content, str) else content.decode("utf-8", errors="replace")):
            raise ValueError("A local path or credential-shaped value was found; publication stopped")
    return files


def command(arguments, directory, env, allowed=(0,)):
    for attempt in range(3):
        result = subprocess.run(arguments, cwd=directory, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        transient = re.search(r"EOF|TLS handshake timeout|connection reset|HTTP 50[234]|remote end hung up|unexpected disconnect", result.stderr, re.I)
        if result.returncode == 0 or not transient or attempt == 2:
            break
        time.sleep(2 ** attempt)
    if result.returncode not in allowed:
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): {result.stderr.strip()[:600]}")
    return result


def publish(runtime, checkout, proxy):
    runtime, checkout = Path(runtime).resolve(), Path(checkout).resolve()
    if checkout != runtime / "share_checkout":
        raise ValueError("Publish checkout must be runtime/share_checkout")
    # Generate from read-only databases; source log and report metadata stay local.
    data = progress.generate_progress(runtime)
    now = datetime.now(timezone.utc)
    starts = [datetime.fromisoformat(event["window_start"]) for event in json.loads((BASE / "watchlist.json").read_text(encoding="utf-8"))]
    upcoming = min((start for start in starts if start > now), default=None)
    files = build_export(data, runtime, progress.beijing(upcoming))
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY")}
    env.update(HTTPS_PROXY=proxy, HTTP_PROXY=proxy, ALL_PROXY=proxy, NO_PROXY="localhost,127.0.0.1",
               GIT_TERMINAL_PROMPT="0", GH_PROMPT_DISABLED="1", GODEBUG="http2client=0")
    owner = json.loads(command(["gh", "api", "user"], BASE, env).stdout)
    if owner.get("login") != "leavedrop":
        raise RuntimeError("Active GitHub owner differs from the authorized owner")
    result = command(["gh", "api", "repos/" + REPOSITORY], BASE, env, (0, 1))
    if result.returncode != 0:
        if "(HTTP 404)" not in result.stderr:
            raise RuntimeError(f"Cannot verify the private repository: gh failed ({result.returncode}): " + result.stderr.strip()[:300])
        command(["gh", "repo", "create", REPOSITORY, "--private", "--description", "Private earnings collection progress and public-report derivatives"], BASE, env)
        result = command(["gh", "api", "repos/" + REPOSITORY], BASE, env)
    repo = json.loads(result.stdout)
    if repo.get("private") is not True or repo.get("owner", {}).get("login") != "leavedrop":
        raise RuntimeError("Publication requires the owner's private repository")
    git = ["git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential", "-c", "http.proxy=" + proxy]
    if not (checkout / ".git").is_dir():
        if checkout.exists() and any(checkout.iterdir()):
            raise RuntimeError("Checkout is not an empty directory or Git repository")
        command(git + ["clone", REPOSITORY_URL + ".git", str(checkout)], BASE, env)
    origin = command(git + ["remote", "get-url", "origin"], checkout, env).stdout.strip().removesuffix(".git")
    if origin != REPOSITORY_URL:
        raise RuntimeError("Unexpected checkout remote")
    tracked = command(git + ["ls-files"], checkout, env).stdout.splitlines()
    if any(path not in ("README.md", "progress.json", "progress.html") and not PUBLISHED_REPORT.fullmatch(path) and not PUBLISHED_ATTACHMENT.fullmatch(path) and not progress.ACHR_SUPPORT_FILE.fullmatch(path) for path in tracked):
        raise RuntimeError("Existing repository contains files outside the approved allowlist")
    (checkout / ".git" / "info" / "exclude").write_text("__pycache__/\n*.tmp\n*.log\n", encoding="utf-8")
    attributes = checkout / ".git" / "info" / "attributes"
    existing = attributes.read_text(encoding="utf-8") if attributes.exists() else ""
    if "attachments/** -text" not in existing.splitlines():
        attributes.write_text(existing + ("\n" if existing and not existing.endswith("\n") else "") + "attachments/** -text\n", encoding="utf-8")
    command(git + ["config", "user.name", "Earnings Watch Progress"], checkout, env)
    command(git + ["config", "user.email", f'{owner["id"]}+leavedrop@users.noreply.github.com'], checkout, env)
    head = command(git + ["rev-parse", "--verify", "HEAD"], checkout, env, (0, 128))
    if head.returncode == 0:
        branch = repo.get("default_branch") or "main"
        if command(git + ["ls-remote", "--heads", "origin", branch], checkout, env).stdout.strip():
            command(git + ["pull", "--ff-only", "origin", branch], checkout, env)
    else:
        command(git + ["symbolic-ref", "HEAD", "refs/heads/main"], checkout, env)
    for path in tracked:
        if path not in files:
            target = checkout / path
            if not target.resolve().is_relative_to(checkout):
                raise ValueError("Refusing to delete outside checkout")
            target.unlink(missing_ok=True)
    for path, content in files.items():
        target = checkout / path
        if not target.resolve().is_relative_to(checkout):
            raise ValueError("Refusing to write outside checkout")
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    owned = sorted(set(files) | set(tracked))
    command(git + ["add", "--", *owned], checkout, env)
    staged = command(git + ["diff", "--cached", "--name-only"], checkout, env).stdout.splitlines()
    if any(path not in owned for path in staged):
        raise RuntimeError("Unrelated staged changes present; publication stopped")
    if staged:
        stamp = datetime.now(progress.BEIJING).strftime("%Y-%m-%d %H:%M Beijing")
        command(git + ["commit", "-m", "Update earnings progress " + stamp], checkout, env)
    command(git + ["push", "origin", "HEAD:" + (repo.get("default_branch") or "main")], checkout, env)
    commit = command(git + ["rev-parse", "HEAD"], checkout, env).stdout.strip()
    return {"repository": REPOSITORY_URL, "private": True, "commit": commit, "published_files": len(files)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=BASE / "runtime")
    parser.add_argument("--proxy", default="http://127.0.0.1:10808")
    parser.add_argument("--until", default=UNTIL)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if datetime.now(timezone.utc) >= datetime.fromisoformat(args.until):
        return
    import msvcrt
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "share_publish.lock").open("a+b") as lock:
        try:
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        try:
            result = publish(runtime, runtime / "share_checkout", args.proxy)
            message = json.dumps(result, ensure_ascii=False)
        except Exception as exc:
            message = json.dumps({"error": str(exc)}, ensure_ascii=False)
            raise
        finally:
            if "message" in locals():
                with (runtime / "share_publish.log").open("a", encoding="utf-8") as log:
                    log.write(datetime.now(timezone.utc).isoformat() + " " + message + "\n")
                if sys.stdout is not None:
                    print(message)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == "__main__":
    main()
