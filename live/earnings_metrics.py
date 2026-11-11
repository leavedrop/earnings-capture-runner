"""Evidence-bearing earnings fields from already received report bytes.

This module neither downloads documents nor chooses forecasts or trading signals.
Only formats exercised against actual archived reports are enabled. Historical
replay is development evidence, never a new-publication latency measurement.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from collections import deque
import hashlib
import re
import time
from typing import Mapping

from lxml import html, etree


OUTPUT_FIELDS = (
    "company_id", "symbol", "report_period", "period_start", "period_end", "metric",
    "metric_definition", "business_scope", "share_basis", "currency", "scale",
    "raw_label", "raw_value", "normalized_value", "source_url", "source_position",
    "document_hash", "received_at_utc", "document_version", "status",
)
SUPPORTED_SYMBOLS = frozenset({"ONON", "TDG", "MRDN", "SE", "QBTS", "NCMI", "RGTI", "GIB", "FNV", "BN",
                               "NBIS", "CBRS", "CSCO", "XPEV", "BIDU", "BEKE", "HTHT", "ARMK", "TSN", "ACM", "INFQ", "STEM"})
_NUMBER = re.compile(r"[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|[+-]?\.\d+")
_YEAR = re.compile(r"\b20\s?\d\s?\d\b")
_PER_SHARE = re.compile(r"\bEPS\b|per\s+(?:(?:basic|diluted|common|ordinary|American depositary|Class\s+[AB]|and)\s+)*(?:share|ADS)", re.I)
_DURATION = re.compile(r"three[ -]months?|thirteen[ -]weeks?|quarter|nine[ -]months?|six[ -]months?|years?\s+ended|fiscal years?|twelve[ -]months?", re.I)
_MONTHS = "January February March April May June July August September October November December".split()
_END_DATE = re.compile(r"\b(" + "|".join(_MONTHS) + r")\s+(\d{1,2})\b", re.I)
_ANNOUNCED_PERIOD = re.compile(
    r"\b(?:announced|reported)\b[^.;]{0,120}\bresults\b[^.;]{0,140}?"
    r"\b(?:quarter|three(?:\s+and\s+(?:six|nine|twelve))?\s+months?)\s+ended\s+"
    r"(" + "|".join(_MONTHS) + r")\s+(\d{1,2})\s*,?\s*(20\d{2})", re.I)
_CURRENCY_HEADER = re.compile(r"(RMB|CNY|USD|US\$|CHF|CAD)(?:\s*\(\d+\))?", re.I)


def normalize_number(raw: str, *, loss_label: bool = False) -> Decimal | None:
    """Normalize one evidenced amount; blanks/dashes/NM never become zero."""
    value = raw.strip().replace("\u2212", "-").replace("\u00a0", " ")
    if not value or value.upper() in {"-", "\u2014", "\u2013", "NM", "N/M", "N.A.", "N/A"}:
        return None
    value = re.sub(r"\b(?:USD|US|CHF|CAD|RMB|CNY)\b|[$\u00a5]", "", value).strip()
    negative = value.startswith("(") and value.endswith(")")
    if negative:
        value = value[1:-1].strip()
    if not _NUMBER.fullmatch(value):
        raise ValueError("not_one_unambiguous_number")
    try:
        result = Decimal(value.replace(",", ""))
    except InvalidOperation as error:
        raise ValueError("invalid_decimal") from error
    return -abs(result) if negative or loss_label else result


def _text(node) -> str:
    return " ".join(" ".join(node.itertext()).split())


def _visible(value: str) -> str:
    return value.replace("\u200b", "").replace("\ufeff", "").strip()


def _currency_header(value):
    value = _visible(value)
    match = _CURRENCY_HEADER.fullmatch(value) or re.search(r"\((RMB|CNY|USD|US\$|CHF|CAD)\)$", value, re.I)
    return match[1].upper() if match else None


def _html_tables(body: bytes, parsed: Mapping | None) -> tuple[str, list[dict]]:
    tree = html.fromstring(body)
    root = next(tree.iter("article"), None)
    if root is None:
        root = next(tree.iter("main"), tree)
    for tag in list(root.iter("script", "style", "nav", "header", "footer")):
        tag.drop_tree()
    # Read surrounding titles/units once in document order. Re-running a
    # preceding-axis XPath for every financial table rescans the whole report.
    table_nodes = list(root.iter("table"))
    enclosing_tables = {ancestor for table in table_nodes for ancestor in table.iterancestors()}
    contexts, recent = {}, deque(maxlen=4)
    walker = etree.iterwalk(root, events=("start", "end"), tag=("table", "p", "div"))
    for action, node in walker:
        if node.tag == "table" and action == "start":
            context = " | ".join(recent)[-1800:]
            for nested in node.iter("table"):
                contexts[nested] = context
            walker.skip_subtree()  # Text inside tables never changes preceding context.
        elif action == "end" and node.tag in {"p", "div"} and node not in enclosing_tables:
            context_text = _text(node)
            if context_text:
                recent.append(context_text)
    if parsed is not None:
        # The owning full-document validator supplied these exact cells/spans.
        # Keep DOM only for their surrounding headings, without re-extracting
        # every cell and then comparing the duplicate to the same parsed data.
        visible_tables = [table for table in table_nodes if any(_text(cell)
            for row in table.iter("tr") for cell in row.iterchildren("td", "th"))]
        tables = [{"rows": rows, "spans": spans, "context": contexts[table]}
                  for table, rows, spans in zip(visible_tables, parsed["tables"], parsed["table_spans"], strict=True)]
        return " ".join(parsed["text"].split()), tables
    tables = []
    for table in table_nodes:
        rows, spans = [], []
        for row in table.iter("tr"):
            cells = list(row.iterchildren("td", "th"))
            values = [_text(cell) for cell in cells]
            if not any(values):
                continue
            rows.append(values)
            spans.append([[int(cell.get("rowspan", "1")), int(cell.get("colspan", "1"))] for cell in cells])
        if rows:
            tables.append({"rows": rows, "spans": spans, "context": contexts[table]})
    return _text(root), tables


def _grid(rows, spans):
    occupied, anchors = {}, []
    for ri, (row, row_spans) in enumerate(zip(rows, spans)):
        col, cells = 0, []
        for ci, (value, (height, width)) in enumerate(zip(row, row_spans)):
            while (ri, col) in occupied:
                col += 1
            height = height or len(rows) - ri  # HTML rowspan=0 covers its remaining row group.
            cell = {"value": value, "row": ri, "cell": ci, "column": col, "end": col + width}
            for y in range(ri, ri + height):
                for x in range(col, col + width):
                    if (y, x) in occupied:
                        raise ValueError("overlapping_cell_spans")
                    occupied[y, x] = cell
            cells.append(cell)
            col += width
        anchors.append(cells)
    return anchors, occupied


def _label(rows, index):
    value = next((_visible(str(cell)) for cell in rows[index] if _visible(str(cell))), "")
    if re.fullmatch(r"[-\u2013\u2014]?\s*(?:basic|diluted|basic and diluted)", value, re.I):
        for previous in reversed(rows[:index]):
            parent = next((_visible(str(cell)) for cell in previous if _visible(str(cell))), "")
            if re.search(r"weighted.average|shares outstanding|shares used|adjustments to|EPS Impact", parent, re.I):
                return value, None
            if _PER_SHARE.search(parent) and not re.search(r"except|statements|amounts|par value|dividends", parent, re.I):
                return parent + " / " + value, "eps"
            if re.search(r"net\s+(?:income|loss)|earnings|profit", parent, re.I) and not _PER_SHARE.search(parent):
                return value, None
        return value, None
    if (_PER_SHARE.search(value) and re.search(r"earnings|income|loss|profit|EPS|(?:basic|diluted).*operations", value, re.I)
            and not re.search(r"weighted.average|shares outstanding|shares for|shares used|used in|EPS Impact|adjustments to|EBITDA|except|statements|amounts|par value", value, re.I)):
        return value, "eps"
    if re.search(r"Per Brookfield share", value, re.I) and index:
        parent = next((_visible(str(cell)) for cell in rows[index-1] if _visible(str(cell))), "")
        if parent.lower().startswith("distributable earnings"):
            return parent + " / " + value, "eps"
    if re.fullmatch(r"(?:core\s+)?(?:total\s+)?(?:net\s+)?(?:sales|revenues?)", value, re.I):
        return value, "revenue"
    return value, None


def _period_groups(anchors, occupied, row, event, context=""):
    for header_index in range(row - 1, -1, -1):
        years = [(cell, _YEAR.findall(cell["value"]) or re.findall(r"Q[1-4]-F(20\d{2})", cell["value"])) for cell in anchors[header_index]]
        years = [(cell, found[0].replace(" ", "")) for cell, found in years if len(found) == 1]
        if len(years) < 2:
            continue
        result = []
        for cell, year in years:
            column = cell["column"]
            headers, duration = [cell["value"]], None
            for below in range(header_index+1, row):
                child = occupied.get((below, column))
                if child and (re.fullmatch(r"Class\s+[AB]", _visible(child["value"]), re.I) or _CURRENCY_HEADER.fullmatch(_visible(child["value"]))):
                    headers.append(child["value"])
            compact = re.fullmatch(r"Q([1-4])(?:-F|\s+(?:FY\s*)?)(20\d{2})", cell["value"], re.I)
            if compact and (int(compact[1]), int(compact[2])) == (event["quarter"], event["fiscal_year"]):
                result.append((cell, headers))
                continue
            if year != event["period_end"][:4]:
                continue
            for prior in range(header_index - 1, -1, -1):
                parent = occupied.get((prior, column))
                if parent and parent["value"]:
                    headers.append(parent["value"])
                    if duration is None and _DURATION.search(parent["value"]):
                        duration = parent["value"]
            if duration is None:
                continue
            quarterly = bool(re.search(r"three[ -]months?|thirteen[ -]weeks?|quarter", duration, re.I))
            cumulative = bool(re.search(r"nine[ -]months?|six[ -]months?|fiscal years?|twelve[ -]months?", duration, re.I))
            if not quarterly or cumulative:
                continue
            dates = _END_DATE.findall(" ".join(headers))
            if not dates:
                # BN prints the one shared end-date in the label-column header.
                shared = " ".join(item["value"] for prior in anchors[:header_index] for item in prior)
                dates = _END_DATE.findall(shared)
            named_quarter = re.search(r"\b(first|second|third|fourth) quarter\b", duration, re.I)
            quarter_matches = named_quarter and ["first", "second", "third", "fourth"].index(named_quarter[1].lower())+1 == event["quarter"]
            if not (not dates and quarter_matches) and not any(f"{_MONTHS.index(month.capitalize())+1:02}-{int(day):02}" == event["period_end"][5:]
                                                              for month, day in dates):
                continue
            # A single dated header can span both original-currency and issuer
            # USD-conversion columns (HTHT). Keep those amounts independent.
            currency_columns = []
            for below in range(header_index+1, row):
                currency_columns = [child for child in anchors[below]
                                    if cell["column"] <= child["column"] < cell["end"]
                                    and _CURRENCY_HEADER.fullmatch(_visible(child["value"]))]
                if currency_columns:
                    break
            if len(currency_columns) > 1:
                for child in currency_columns:
                    result.append((child, list(reversed([header for header in headers if not _CURRENCY_HEADER.fullmatch(_visible(header))])) + [child["value"]]))
            else:
                total_column = next((child for below in range(header_index+1, row) for child in anchors[below]
                                     if child["column"] <= cell["column"] < child["end"] and child["value"] == "Total"), None) if event["symbol"] == "CBRS" else None
                result.append((total_column or cell, list(reversed(headers)) + (["Total"] if total_column else [])))
        return result
    return []


def _share_basis(label: str, table_text: str):
    low = label.lower()
    if "per brookfield share" in low:
        return "distributable_earnings:Brookfield_share"
    if "basic" in low and "diluted" in low:
        dilution = "basic_and_diluted"
    elif "diluted" in low:
        dilution = "diluted"
    elif "basic" in low:
        dilution = "basic"
    else:
        return None
    classes = list(dict.fromkeys(re.findall(r"Class\s+([AB])", label, re.I)))
    instrument = "ADS" if re.search(r"\bADS\b|depositary", label, re.I) else (
        "ordinary" if "ordinary" in low or classes else "common")
    parts = [dilution, instrument]
    if classes:
        parts.append("Class " + "+".join(item.upper() for item in classes))
    if instrument == "ADS":
        ratio = re.search(r"1\s+ADS\s+(?:representing|represents)\s+(\d+)", label, re.I)
        if ratio:
            parts.append("ratio=" + ratio[1])
    if "two-class method" in low:
        parts.append("two_class_method")
    return ":".join(parts)


def _unit_context(symbol, metric, table_text, full_text, event, headers=()):
    # A bare $ is not an ISO currency. Callers may supply a separately verified
    # reporting currency; a stock's listing market is never used as a fallback.
    column_currency = next(({"RMB": "CNY", "CNY": "CNY", "USD": "USD", "US$": "USD", "CHF": "CHF", "CAD": "CAD"}[code]
                            for header in reversed(headers) if (code := _currency_header(header))), None)
    if column_currency:
        currency = column_currency
    elif re.search(r"\bCAD\b|Canadian dollars", table_text, re.I):
        currency = "CAD"
    elif re.search(r"\bCHF\b|Swiss Franc", table_text, re.I):
        currency = "CHF"
    elif re.search(r"\bRMB\b|\bCNY\b", table_text, re.I):
        currency = "CNY" if not re.search(r"US\$|USD", table_text, re.I) else None
    elif re.search(r"\bUSD\b|US\$|U\.?S\.?\s+dollars|iso4217:USD", table_text + " " + full_text, re.I):
        currency = "USD"
    else:
        currency = event.get("reporting_currency")
    if metric == "eps":
        scale = 1
    elif re.search(r"in millions|\bmillions\b", table_text, re.I):
        scale = 1_000_000
    elif re.search(r"in thousands|\bthousands\b", table_text, re.I):
        scale = 1_000
    elif symbol == "MRDN" and "Consolidated Statements of Operations" in table_text:
        scale = 1  # The actual operating statement has unscaled dollar cells.
    else:
        scale = None
    return currency, scale


def _record(event, common, metric, label="", **fields):
    result = dict.fromkeys(OUTPUT_FIELDS)
    result.update(company_id=event.get("company_id") or "cik:" + str(int(event["cik"])),
                  symbol=event["symbol"], report_period=f"FY{event['fiscal_year']} Q{event['quarter']}",
                  period_start=event["period_start"], period_end=event["period_end"], metric=metric,
                  business_scope="consolidated", raw_label=label, status="missing", **common)
    result.update(fields)
    return result


def _acm_summary_groups(anchors, row, event, full_text):
    quarter = ["first", "second", "third", "fourth"][event["quarter"]-1]
    if not re.search(quarter + r"\s+quarter\s+(?:fiscal\s+)?" + str(event["fiscal_year"]), full_text[:5000], re.I):
        return []
    header = next((line for line in anchors[:min(row, 3)] if any("continuing operations" in cell["value"].lower() for cell in line)), None)
    if header is None:
        return []
    return [(cell, [f"{quarter} quarter fiscal {event['fiscal_year']}", "Continuing Operations", cell["value"]])
            for cell in header if re.search(r"As Reported|Adjusted.*Non-GAAP|^Adjusted|Metrics Excl\. Const\. Mgmt\. Project Charge", cell["value"], re.I)]


def _html_fields(body, event, parsed, common, diagnostics):
    full_text, tables = _html_tables(body, parsed)
    currency_conflict = None
    if event.get("reporting_currency_source") == "provided_company_rule":
        currency_conflict = re.search(r"\b(?:CAD|CHF|CNY|RMB|EUR|GBP|JPY|HKD)\b|Canadian dollars|Swiss francs|Chinese yuan|euros|pounds sterling|Japanese yen|Hong Kong dollars", full_text, re.I)
        if currency_conflict:
            diagnostics.append({"reason": "provided_currency_conflicts_with_document", "configured_currency": event["reporting_currency"],
                                "text": currency_conflict[0], "text_offset": currency_conflict.start()})
    announcement = _ANNOUNCED_PERIOD.search(full_text[:5000])
    if announcement:
        announced_end = f"{announcement[3]}-{_MONTHS.index(announcement[1].capitalize())+1:02}-{int(announcement[2]):02}"
        if announced_end != event["period_end"]:
            diagnostics.append({"reason":"announced_report_period_mismatch", "announced_period_end":announced_end,
                                "requested_period_end":event["period_end"], "text":announcement[0],
                                "text_offset":announcement.start()})
            return []
    output = []
    standard = "IFRS" if event["symbol"] in {"ONON", "GIB", "FNV", "BN"} else "US_GAAP"
    for ti, table in enumerate(tables):
        rows = table["rows"]
        table_text = table["context"] + " " + " ".join(" ".join(row) for row in rows)
        anchors = occupied = None
        for ri, row in enumerate(rows):
            label, metric = _label(rows, ri)
            if event["symbol"] == "ACM" and re.match(r"Net Service Revenue \(NSR\)", label, re.I):
                metric = "revenue"
            if (event["symbol"] == "ARMK" and metric is None and ri >= 3
                    and "Diluted Weighted Average Shares Outstanding" in " ".join(rows[ri-1])
                    and "Earnings Per Share" in " ".join(rows[ri-3])):
                label, metric = " ".join(rows[ri-3]).strip() + " / diluted", "eps"
            if metric is None:
                continue
            # Segment and reconciliation profit amounts are not consolidated revenue.
            summary = event["symbol"] == "SE" and label.lower() == "total revenue"
            summary = summary or (event["symbol"] == "GIB" and "Financial highlights" in table_text)
            summary = summary or (event["symbol"] == "NCMI" and "Operating Data" in table_text and label.lower() == "total revenue")
            summary = summary or (event["symbol"] == "CBRS" and label.lower().startswith("core ") and "RECONCILIATION OF GAAP" in table_text)
            summary = summary or (event["symbol"] == "STEM" and label.lower() == "revenue" and "Key Financial Results and Operating Metrics" in table_text)
            acm_summary = event["symbol"] == "ACM" and (metric == "eps" or "Net Service Revenue" in label)
            summary = summary or acm_summary
            if metric == "revenue" and event["symbol"] != "ONON" and not summary and "CONSOLIDATED" not in table_text.upper():
                continue
            if (metric == "revenue" and event["symbol"] == "ACM" and label.lower() == "revenue"
                    and not re.search(r"Consolidated Statements? of (?:Income|Operations)", table["context"], re.I)):
                continue
            if anchors is None:
                anchors, occupied = _grid(rows, table["spans"])
            groups = _period_groups(anchors, occupied, ri, event, table["context"])
            if not groups and acm_summary:
                groups = _acm_summary_groups(anchors, ri, event, full_text)
            for year_cell, headers in groups:
                parts = [cell for cell in anchors[ri] if year_cell["column"] <= cell["column"] < year_cell["end"]]
                raw = " ".join(_visible(cell["value"]) for cell in parts if _visible(cell["value"]))
                if raw.count("(") == raw.count(")") + 1:
                    closing = next((cell for cell in anchors[ri] if cell["column"] == year_cell["end"]
                                    and cell["value"].strip() == ")"), None)
                    if closing is not None:
                        parts.append(closing)
                        raw += " " + closing["value"]
                try:
                    value = normalize_number(raw, loss_label=bool(re.search(r"loss", label, re.I)
                        and not re.search(r"income|earnings|profit", label, re.I)))
                except ValueError:
                    diagnostics.append({"metric": metric, "table": ti, "row": ri, "reason": "ambiguous_numeric_cells", "raw": raw})
                    continue
                if value is None:
                    continue
                currency, scale = _unit_context(event["symbol"], metric, table_text, full_text, event, headers)
                if currency_conflict:
                    currency = None
                share_label = label + " " + " ".join(header for header in headers if re.fullmatch(r"Class\s+[AB]", header, re.I))
                if event["symbol"] == "FNV" and label.lower() == "adjusted net income per share" and ri and "Basic weighted average" in " ".join(rows[ri-1]):
                    share_label += " basic"
                share = _share_basis(share_label, table_text) if metric == "eps" else None
                adjusted = bool(re.search(r"adjusted|non.?GAAP|non.?IFRS|excluding adjusting items", label, re.I))
                if event["symbol"] == "CBRS" and label.lower().startswith("core "):
                    adjusted = True
                if acm_summary and any(re.search(r"Adjusted|Metrics Excl", header, re.I) for header in headers):
                    adjusted = True
                if event["symbol"] == "CSCO" and "Non-GAAP Results" in table["context"].split("|")[-1]:
                    adjusted = True
                definition = ("non_IFRS_adjusted" if standard == "IFRS" else "non_GAAP_adjusted") if adjusted else standard
                if label.lower().startswith("distributable earnings"):
                    definition = "non_IFRS_distributable_earnings_before_realizations" if "before realizations" in label.lower() else "non_IFRS_distributable_earnings"
                if "constant currency" in label.lower():
                    definition += ":constant_currency"
                if "without the calendar shift" in label.lower():
                    definition += ":without_calendar_shift"
                if any("Metrics Excl. Const. Mgmt. Project Charge" in header for header in headers):
                    definition += ":excluding_construction_management_project_charge"
                if metric == "revenue":
                    definition += ":" + re.sub(r"\s+", "_", label.lower())
                scope = "discontinued_operations" if "discontinued operations" in label.lower() else (
                    "continuing_operations" if "continuing operations" in label.lower() or "Continuing Operations" in headers else "consolidated")
                position = {"table_index": ti, "row_index": ri, "column_headers": headers,
                            "column_range": [year_cell["column"], max(cell["end"] for cell in parts)],
                            "cells": [{"row": cell["row"], "cell": cell["cell"], "text": cell["value"]} for cell in parts],
                            "table_title": " | ".join(" ".join(row) for row in rows[:3]), "preceding_context": table["context"]}
                currency_pattern = {"USD":r"\bUSD\b|US\$|U\.?S\.?\s+dollars|iso4217:USD", "CAD":r"\bCAD\b|Canadian dollars",
                                    "CHF":r"\bCHF\b|Swiss Franc", "CNY":r"\bRMB\b|\bCNY\b"}.get(currency)
                if currency_pattern:
                    unit_match = re.search(currency_pattern, full_text, re.I)
                    position["currency_evidence"] = ({"text":unit_match[0], "text_offset":unit_match.start(), "scope":"document"}
                                                     if unit_match else {"scope":"caller_reporting_currency_contract"})
                    if unit_match is None and event.get("reporting_currency_source") == "provided_company_rule":
                        position["currency_evidence"] = {"scope": "provided_company_rule", "currency": currency}
                matched = currency is not None and scale is not None and (metric != "eps" or share is not None)
                output.append(_record(event, common, metric, label, metric_definition=definition,
                    share_basis=share, currency=currency, scale=scale, raw_value=raw, business_scope=scope,
                    normalized_value=format(value * scale, "f") if scale is not None else None,
                    source_position=position, status="matched" if matched else "unsupported_basis"))
    return output


def _se_pdf_fields(body, event, common, diagnostics):
    """Read actual PDF word coordinates; never consume the fragmented generic tables."""
    import fitz
    from sources import _PDF_LOCK

    output = []
    if event["period_end"] != "2026-09-30" or event["quarter"] != 3:
        diagnostics.append({"reason": "pdf_period_format_not_yet_verified"})
        return output
    # The existing document parser owns this process-wide MuPDF lock. Lock
    # waiting remains inside extract_metrics' elapsed time.
    with _PDF_LOCK, fitz.open(stream=body, filetype="pdf") as document:
        for pi in range(min(4, len(document))):
            page = document[pi]
            text = page.get_text()
            if not ("For the Three Months" in text and "ended September 30" in text
                    and "2026" in text and "thousands of US dollars" in text):
                continue
            words = page.get_text("words")
            year_words = [word for word in words if word[4] == str(event["fiscal_year"])]
            for year in year_words:
                # Column header is above the financial rows. A year in prose is
                # not a column, so require the adjacent prior-year header.
                prior_year = next((word for word in words if word[4] == str(event["fiscal_year"]-1)
                                   and abs(word[3]-year[3]) < 2), None)
                if prior_year is None:
                    continue
                column_right = year[2]
                center = (year[0] + year[2]) / 2
                prior_center = (prior_year[0] + prior_year[2]) / 2
                column_left, column_end = (center + prior_center) / 2, center + (center - prior_center) / 2
                lines = []
                for word in sorted((word for word in words if word[1] > year[3]), key=lambda w: ((w[1]+w[3])/2, w[0])):
                    center = (word[1]+word[3])/2
                    if not lines or abs(center-lines[-1][0]) > 2:
                        lines.append((center, [word]))
                    else:
                        lines[-1][1].append(word)
                eps_parent = False
                for _, line_words in lines:
                    line_words.sort(key=lambda word: word[0])
                    label_words = [word for word in line_words if word[2] < column_right - 110]
                    label = " ".join(word[4] for word in label_words)
                    if "Earnings per share" in label:
                        eps_parent = True
                    metric = "revenue" if label == "Total revenue" else (
                        "eps" if eps_parent and label in ("Basic", "Diluted") else None)
                    if metric is None:
                        continue
                    candidates = [word for word in line_words if column_left < (word[0]+word[2])/2 < column_end
                                  and _NUMBER.fullmatch(word[4])]
                    if len(candidates) != 1:
                        diagnostics.append({"metric": metric, "page": pi+1, "reason": "ambiguous_pdf_column"})
                        continue
                    word = candidates[0]
                    raw = word[4]
                    value = normalize_number(raw)
                    scale = 1_000 if metric == "revenue" else 1
                    output.append(_record(event, common, metric,
                        "Earnings per share attributable to Sea Limited's ordinary shareholders / " + label if metric == "eps" else label,
                        metric_definition="US_GAAP" if metric == "eps" else "US_GAAP:total_revenue",
                        share_basis=label.lower()+":ordinary" if metric == "eps" else None,
                        currency="USD", scale=scale, raw_value=raw, normalized_value=format(value*scale, "f"),
                        source_position={"page": pi+1, "bbox": list(word[:4]), "label_bbox": [min(w[0] for w in label_words), min(w[1] for w in label_words), max(w[2] for w in label_words), max(w[3] for w in label_words)],
                                         "column_headers": ["Three Months ended September 30", str(event["fiscal_year"])],
                                         "unit_label": "thousands of US dollars except for per share data"}, status="matched"))
    return output


def _nbis_gib_pdf_fields(body, event, common, diagnostics):
    """Read verified native PDF statement columns, without OCR or quotient EPS."""
    import fitz
    from sources import _PDF_LOCK

    output = []
    with _PDF_LOCK, fitz.open(stream=body, filetype="pdf") as document:
        texts = [page.get_text() for page in document]
        month = _MONTHS[int(event["period_end"][5:7])-1]
        date_pattern = (month + r"\s+" + str(int(event["period_end"][8:])) + r",?\s+" + event["period_end"][:4])
        if not re.search(date_pattern, " ".join(" ".join(texts).split()), re.I):
            diagnostics.append({"reason":"pdf_report_end_date_not_evidenced"})
            return output
        for pi, page in enumerate(document):
            text = texts[pi]
            compact = " ".join(text.split())
            if event["symbol"] == "GIB":
                eligible = ("Financial highlights" in compact and f"Q{event['quarter']}-F{event['fiscal_year']}" in compact
                            and "In millions of Canadian dollars" in compact)
                currency, scale, standard = "CAD", 1_000_000, "IFRS"
            else:
                month = _MONTHS[int(event["period_end"][5:7])-1]
                eligible = ("consolidated statements of operations" in compact.lower()
                            and re.search(r"Three months ended\s+(?:" + month + "|" + month[:3] + r")\s+" + str(int(event["period_end"][8:])), compact, re.I)
                            and re.search(r"millions of U\.S\. dollars|In USD \$ millions", compact, re.I))
                currency, scale, standard = "USD", 1_000_000, "US_GAAP"
            if not eligible:
                continue
            words = page.get_text("words")
            years = [word for word in words if (word[4] == str(event["fiscal_year"]) or
                     word[4] == f"Q{event['quarter']}-F{event['fiscal_year']}")]
            current = None
            for year in sorted(years, key=lambda w: (w[1], w[0])):
                nearby = sorted([word for word in words if abs(word[3]-year[3]) < 2 and
                                (re.fullmatch(r"20\d{2}(?:1)?", word[4]) or re.fullmatch(r"Q[1-4]-F20\d{2}", word[4]))], key=lambda w: w[0])
                if len(nearby) >= 2:
                    current = year
                    break
            if current is None:
                continue
            centers = [(word[0]+word[2])/2 for word in nearby]
            ci = nearby.index(current)
            center = centers[ci]
            gap = abs(centers[1]-centers[0])
            left = (centers[ci-1]+center)/2 if ci else center-gap/2
            right = (center+centers[ci+1])/2 if ci+1<len(centers) else center+gap/2
            lines = []
            for word in sorted((word for word in words if word[1]>current[3]), key=lambda w: ((w[1]+w[3])/2, w[0])):
                cy = (word[1]+word[3])/2
                if not lines or abs(cy-lines[-1][0]) > 2:
                    lines.append((cy, [word]))
                else:
                    lines[-1][1].append(word)
            parent = ""
            for _, line in lines:
                line.sort(key=lambda w:w[0])
                labels = [word for word in line if word[2] < min(centers)-gap/2]
                label = " ".join(word[4] for word in labels).strip()
                entire_line = " ".join(word[4] for word in line)
                if "per Class A and Class B share" in entire_line:
                    parent = entire_line
                    continue
                if "Weighted average" in label:
                    parent = ""
                metric = "revenue" if label in {"Revenue", "Revenues"} else None
                if event["symbol"] == "GIB" and re.fullmatch(r"(?:Adjusted )?Diluted EPS\d?", label, re.I):
                    metric = "eps"
                if parent and label in {"Basic", "Diluted"}:
                    label, metric = parent + " / " + label, "eps"
                if metric is None:
                    continue
                numbers = [word for word in line if left<(word[0]+word[2])/2<right and
                           (_NUMBER.fullmatch(word[4].strip("()")) or word[4] in {"—", "-"})]
                if len(numbers) != 1:
                    diagnostics.append({"metric": metric, "page": pi+1, "reason": "ambiguous_pdf_column"})
                    continue
                word = numbers[0]
                value = normalize_number(word[4])
                if value is None:
                    continue
                factor = scale if metric == "revenue" else 1
                definition = "non_IFRS_adjusted" if "adjusted" in label.lower() else standard
                if metric == "revenue":
                    definition += ":" + label.lower()
                scope = "discontinued_operations" if "discontinued operations" in label.lower() else (
                    "continuing_operations" if "continuing operations" in label.lower() else "consolidated")
                output.append(_record(event, common, metric, label, metric_definition=definition,
                    business_scope=scope, share_basis=_share_basis(label, compact) if metric=="eps" else None,
                    currency=currency, scale=factor, raw_value=word[4], normalized_value=format(value*factor,"f"),
                    source_position={"page":pi+1,"bbox":list(word[:4]),"column_header":current[4],
                                     "label_words":[{"text":w[4],"bbox":list(w[:4])} for w in labels],
                                     "unit_label":"millions of Canadian dollars" if currency=="CAD" else "millions of U.S. dollars"},
                    status="matched"))
    return output


def extract_metrics(body: bytes, source_url: str, event: Mapping, *, received_at_utc: str,
                    document_version: str, parsed: Mapping | None = None, rules: Mapping | None = None) -> dict:
    """Extract target-period fields with caller-owned receipt/version provenance.

    ``event`` supplies a verified company identity and accounting-period contract.
    A separately verified ``reporting_currency`` is optional for reports stating
    only '$'. Missing currency remains unsupported; no FX conversion is applied.
    ``parsed``, when supplied, is the owning validator's complete result for
    these same body bytes, including text, tables and table_spans.
    All normalized values are decimal strings in their original currency unit.
    """
    started = time.perf_counter_ns()
    common = {"source_url": source_url, "document_hash": hashlib.sha256(body).hexdigest(),
              "received_at_utc": received_at_utc, "document_version": document_version}
    diagnostics = []
    company_rule = None
    if rules is not None:
        company_rule = next((row for row in rules["companies"] if row["symbol"] == event["symbol"]), None) if "companies" in rules else rules
        if "companies" not in rules and company_rule.get("symbol") != event["symbol"]:
            raise ValueError("rules_do_not_describe_this_company")
    if (event["symbol"] in {"TDG", "MRDN"} and company_rule is not None
            and company_rule.get("currency") == "USD" and company_rule.get("currency_source") == "provided_company_rule"):
        event = {**event, "reporting_currency": "USD", "reporting_currency_source": "provided_company_rule"}
        diagnostics.append({"reason": "currency_from_provided_company_rule", "symbol": event["symbol"], "currency": "USD"})
    if rules is not None and company_rule is None:
        records = [_record(event, common, metric, status="unsupported_basis") for metric in ("eps", "revenue")]
        diagnostics.append({"reason":"company_not_configured"})
    elif event["symbol"] not in SUPPORTED_SYMBOLS:
        records = [_record(event, common, metric, status="unsupported_basis") for metric in ("eps", "revenue")]
        diagnostics.append({"reason": "company_format_not_yet_verified"})
    elif body.startswith(b"%PDF") and event["symbol"] == "SE":
        records = _se_pdf_fields(body, event, common, diagnostics)
    elif body.startswith(b"%PDF") and event["symbol"] in {"NBIS", "GIB"}:
        records = _nbis_gib_pdf_fields(body, event, common, diagnostics)
    elif body.startswith(b"%PDF"):
        records = []
        diagnostics.append({"reason": "pdf_format_not_yet_verified"})
    else:
        records = _html_fields(body, event, parsed, common, diagnostics)
    located = time.perf_counter_ns()
    # Equal repetitions share one contract; conflicting amounts stay ambiguous.
    groups = {}
    for record in records:
        key = tuple(record[field] for field in ("metric", "metric_definition", "share_basis", "business_scope", "currency"))
        groups.setdefault(key, []).append(record)
    output = []
    for group in groups.values():
        values = {record["normalized_value"] for record in group}
        if len(values) > 1:
            for record in group:
                record["status"] = "ambiguous"
            diagnostics.append({"metric": group[0]["metric"], "reason": "conflicting_values_for_same_contract"})
            output.extend(group)
        else:
            output.append(group[0])
    for metric in ("eps", "revenue"):
        if not any(record["metric"] == metric for record in output):
            output.append(_record(event, common, metric))
            diagnostics.append({"metric": metric, "reason": "no_verified_target_period_field"})
    if event.get("period_start") is None:
        for record in output:
            if record["status"] == "matched":
                record["status"] = "unsupported_basis"
        diagnostics.append({"reason":"period_start_not_verified"})
    if company_rule is not None:
        # Rules request a basis; they never supply a measured value. In
        # particular, no latest_example or observed reference number is read.
        wants_adjusted = any(re.search(r"adjusted|non.?GAAP|non.?IFRS", label, re.I)
                             for label in company_rule.get("eps_labels", []))
        if wants_adjusted and not any(row["metric"] == "eps" and str(row["metric_definition"]).startswith("non_") for row in output):
            standard = "non_IFRS_adjusted" if event["symbol"] in {"ONON", "GIB", "FNV", "BN"} else "non_GAAP_adjusted"
            output.append(_record(event, common, "eps", metric_definition=standard))
            diagnostics.append({"metric":"eps", "metric_definition":standard, "reason":"requested_basis_not_explicitly_published_in_target_period"})
    for record in output:
        if record["status"] == "unsupported_basis":
            missing = [field for field in ("currency", "scale", "period_start") if record[field] is None]
            if record["metric"] == "eps" and record["share_basis"] is None:
                missing.append("share_basis")
            diagnostics.append({"metric":record["metric"], "metric_definition":record["metric_definition"],
                                "raw_label":record["raw_label"], "reason":"basis_not_verified", "unverified_fields":missing})
    finished = time.perf_counter_ns()
    return {"metrics": output, "diagnostics": diagnostics,
            "timings_ms": {"location": (located-started)/1e6, "basis_validation": (finished-located)/1e6,
                           "total": (finished-started)/1e6},
            "scope": "document_metric_extraction_not_network_or_trade_latency"}
