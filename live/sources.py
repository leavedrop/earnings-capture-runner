"""Financial-release discovery and conservative document validation.

The validator is a collection gate, not an assertion about accounting accuracy.
Publisher timestamps retain their own precision; they are never request clocks.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunparse
from xml.etree import ElementTree
from zoneinfo import ZoneInfo

from bs4 import BeautifulSoup
from lxml import etree
from selectolax.lexbor import LexborHTMLParser

_ANNOUNCEMENT = re.compile(
    r"\b(?:to\s+(?:report|release|announce|host)|will\s+(?:report|release|announce|host)|"
    r"sets?\s+(?:date|earnings)|schedules?\s+(?:earnings|conference)|"
    r"announces?\s+(?:the\s+)?date\b|"
    r"(?:earnings|results)\s+(?:conference\s+)?call|webcast\s+to\s+discuss)\b", re.I)
_FINANCIAL = re.compile(r"\b(?:results|earnings|financial\s+(?:statements|report)|"
                        r"quarterly\s+report|shareholder\s+letter|form\s+10-[qk])\b", re.I)
_METRICS = re.compile(r"\b(?:revenues?|net\s+(?:income|loss)|earnings\s+per\s+share|"
                      r"assets|liabilities|cash\s+flows?|operating\s+(?:income|loss)|"
                      r"diluted|balance\s+sheets?)\b", re.I)
_ORDINAL = {1: "first", 2: "second", 3: "third", 4: "fourth"}
_PDF_LOCK = threading.Lock()  # PyMuPDF table extraction mutates module-global CHARS/EDGES.
_DIGIT = re.compile(r"\d")


class _TextNodes(threading.local):
    def __init__(self):
        # A shared XPath evaluator serializes its prepared context across threads.
        self.evaluate = etree.XPath(".//text()", smart_strings=False)


_TEXT_NODES = _TextNodes()


def _clean(value):
    return " ".join((value or "").split())


def _pdf_title(text):
    # GlobeNewswire puts a release timestamp ahead of the title. Keep it in
    # the full text, but never treat its year as the title's reporting year.
    lines = text.splitlines()[:8]
    return _clean(" ".join(line for line in lines if not re.fullmatch(
        r"[A-Za-z]+\s+\d{1,2},\s+20\d{2}\s+\d{2}:\d{2}\s+ET", line.strip())))[:800]


def _normal(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _target(text, event):
    """Require quarter and fiscal year in the same short phrase."""
    q, year = int(event["quarter"]), int(event["fiscal_year"])
    quarter = rf"(?:Q\s*{q}|{q}\s*Q|{_ORDINAL[q]}[\s-]+quarter|quarter\s+{q})"
    yr = rf"(?:FY\s*)?(?:{year}|['’]{str(year)[2:]})"
    return bool(re.search(rf"\b{quarter}[\s\w,()'-]{{0,24}}\b{yr}\b|"
                          rf"\b{yr}[\s\w,()'-]{{0,24}}\b{quarter}\b|"
                          rf"\b{q}Q{str(year)[2:]}\b|\bQ{q}[ '’-]*{str(year)[2:]}\b",
                          text, re.I))


def _period_end_in_lead(text, event):
    try:
        day = datetime.fromisoformat(event["period_end"])
    except (KeyError, ValueError):
        return False
    date = rf"(?:{day:%B}\s+{day.day},?\s+{day.year}|{day:%b}\.?\s+{day.day},?\s+{day.year}|{day:%Y-%m-%d})"
    return bool(re.search(rf"(?:quarter|three\s+months|period)\s+ended\s+{date}", text, re.I))


def _quarter_without_year(title, event):
    if re.search(r"\b(?:20\d{2}|FY\s*['’]?\d{2})\b", title, re.I):
        return False
    match = re.search(r"\b(?:(first|second|third|fourth)[\s-]+quarter|Q\s*([1-4]))\b", title, re.I)
    if not match:
        return False
    quarter = int(match[2]) if match[2] else next(q for q, word in _ORDINAL.items() if word == match[1].lower())
    return quarter == int(event["quarter"])


def _date_in_release_window(day, event):
    if not event.get("window_start") or not event.get("window_end"):
        return False
    eastern = ZoneInfo("America/New_York")
    start = datetime.fromisoformat(event["window_start"]).astimezone(eastern).date()
    end = datetime.fromisoformat(event["window_end"]).astimezone(eastern).date()
    return start <= day <= end


def _trusted_issuer_url(url, event):
    parsed = urlparse(url or "")
    hostname = (parsed.hostname or "").lower()
    if hostname.endswith("sec.gov") and event.get("cik"):
        match = re.search(r"/Archives/edgar/data/(\d+)/", parsed.path)
        if match and int(match[1]) == int(event["cik"]):
            return True
    return any(source.get("channel") == "official" and
               (urlparse(source.get("url", "")).hostname or "").lower() == hostname
               for source in event.get("sources", []))


def _identity(text, event, url=None):
    normal = _normal(text)
    aliases = [event.get("company", ""), *event.get("aliases", [])]
    for alias in aliases:
        cleaned = _normal(alias)
        if len(cleaned) >= 4 and cleaned in normal:
            return True
        if not 2 <= len(cleaned) <= 3:
            continue
        word = rf"(?<![A-Za-z0-9]){re.escape(alias)}(?![A-Za-z0-9])"
        if alias.isupper() and re.search(word, text):
            return True
        # Common short words (Sea/On) need a company role or a verified issuer URL.
        if re.search(word, text) and (_trusted_issuer_url(url, event) or re.search(
                word + r"\s+(?:Limited|Ltd\.?|Inc\.?|Reports|Announces|Releases)\b", text)):
            return True
    return False


def _url(base, href):
    result = urljoin(base, href.strip())
    parsed = urlparse(result)
    if parsed.scheme not in ("https", "http"):
        return None
    if parsed.hostname and parsed.hostname.endswith("sec.gov"):
        doc = parse_qs(parsed.query).get("doc")
        if doc:
            result = urljoin("https://www.sec.gov", doc[0])
            parsed = urlparse(result)
    return urlunparse(parsed._replace(fragment=""))


def _stamp(value, kind="publisher_page"):
    if not value:
        return {"value": None, "precision": "unknown", "kind": kind}
    value = str(value).strip()
    if re.fullmatch(r"\d{4}-\d\d-\d\d", value):
        return {"value": value, "precision": "day", "kind": kind}
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return {"value": value, "precision": "unknown", "kind": kind,
                    "note": "Publisher timezone unspecified"}
        precision = "second" if re.search(r"[T ]\d\d:\d\d:\d\d", value) else "minute"
        return {"value": parsed.isoformat(), "precision": precision, "kind": kind}
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo:
                return {"value": parsed.isoformat(), "precision": "second", "kind": kind}
        except (ValueError, TypeError):
            pass
        return {"value": value, "precision": "unknown", "kind": kind}


def _published_in_json(obj):
    if isinstance(obj, dict):
        if obj.get("datePublished"):
            return obj["datePublished"]
        for child in obj.values():
            value = _published_in_json(child)
            if value:
                return value
    elif isinstance(obj, list):
        for child in obj:
            value = _published_in_json(child)
            if value:
                return value
    return None


def _timestamp(soup):
    for selector in ('meta[property="article:published_time"]',
                     'meta[itemprop="datePublished"]', 'meta[name="datePublished"]'):
        tag = soup.select_one(selector)
        if tag and tag.get("content"):
            return _stamp(tag["content"])
    for tag in soup.select('script[type="application/ld+json"]'):
        try:
            value = _published_in_json(json.loads(tag.get_text()))
            if value:
                return _stamp(value)
        except (ValueError, TypeError):
            pass
    tag = soup.select_one('time[datetime]')
    return _stamp(tag.get("datetime") if tag else None)


def _document(body):
    return etree.fromstring(body if body.strip() else b"<html></html>", etree.HTMLParser())


def check_table_spans(tables, spans):
    """Verify the public cell-span array contains only aligned integer pairs."""
    if not isinstance(spans, list) or len(spans) != len(tables):
        raise ValueError("table_spans_shape_mismatch")
    for table, table_spans in zip(tables, spans):
        if not isinstance(table_spans, list) or len(table_spans) != len(table):
            raise ValueError("table_spans_shape_mismatch")
        for row, row_spans in zip(table, table_spans):
            if not isinstance(row_spans, list) or len(row_spans) != len(row):
                raise ValueError("table_spans_shape_mismatch")
            for pair in row_spans:
                if (not isinstance(pair, list) or len(pair) != 2 or
                        any(type(value) is not int for value in pair) or pair[0] < 0 or pair[1] < 1):
                    raise ValueError("table_spans_not_integer_pairs")


def _text(node, separator=" ", strip=True):
    values = _TEXT_NODES.evaluate(node) if len(node) else ((node.text,) if node.text else ())
    if strip:
        return separator.join(filter(None, map(str.strip, values)))
    return separator.join(values)


def _cell_text(node):
    # Cell output collapses whitespace once, including text-node boundaries.
    if not len(node):
        text = node.text
        return " ".join(text.split()) if text else ""
    return " ".join(" ".join(node.itertext()).split())


def _cell_spans(cell):
    rowspan, colspan = cell.get("rowspan", "1"), cell.get("colspan", "1")
    if rowspan == "1" and colspan == "1":
        return [1, 1]
    rowspan, colspan = rowspan.strip(), colspan.strip()
    return [int(rowspan) if rowspan.isdecimal() else 1,
            int(colspan) if colspan.isdecimal() and int(colspan) > 0 else 1]


def _drop_content(root, *tags):
    for node in list(root.iter(*tags)):
        # Preserve the separation between text nodes that BeautifulSoup kept on
        # either side of a removed node; lxml otherwise joins their tails.
        parent = node.getparent()
        if node.tail:
            previous = node.getprevious()
            if previous is not None:
                previous.tail = (previous.tail or "") + " " + node.tail
            else:
                parent.text = (parent.text or "") + " " + node.tail
        parent.remove(node)


def _native_timestamp(root):
    for attribute, value in (("property", "article:published_time"),
                             ("itemprop", "datePublished"), ("name", "datePublished")):
        tag = next((tag for tag in root.iter("meta") if tag.get(attribute) == value), None)
        if tag is not None and tag.get("content"):
            return _stamp(tag.get("content"))
    for tag in root.iter("script"):
        if tag.get("type") != "application/ld+json":
            continue
        try:
            value = _published_in_json(json.loads(tag.text or ""))
            if value:
                return _stamp(value)
        except (ValueError, TypeError):
            pass
    tag = next((tag for tag in root.iter("time") if tag.get("datetime") is not None), None)
    return _stamp(tag.get("datetime") if tag is not None else None)


def uses_native_html_parser(url, event):
    """Only the SEC exhibit whose complete text, cells and spans were compared."""
    parsed = urlparse(url)
    return (event.get("symbol") == "B" and parsed.scheme == "https"
            and parsed.hostname == "www.sec.gov"
            and parsed.path == "/Archives/edgar/data/756894/000119312526453391/d141003dex992.htm")


def _lexbor_text_fragments(node):
    # skip_empty only handles ASCII whitespace. Filter after Unicode strip so
    # NBSP-only fragments do not introduce extra separators into the full text.
    return " ".join(filter(None, node.text(separator="\x00", strip=True).split("\x00")))


def _extract_barrick_native_html(body, *, document=None):
    # The audited native routes only accept ASCII bytes. Decode numeric entities
    # as HTML5 visible characters, matching the frozen complete US reference.
    if document is None:
        document = LexborHTMLParser(body, encoding=False)
        selected = None
    else:
        # KKR already has its DEI-checked tree. Collect page elements in one
        # native traversal instead of repeatedly scanning this 16 MB filing.
        selected = document.css('article,main,script,style,h1,meta,title,nav,header,footer,time[datetime]')
        by_tag = {}
        for node in selected:
            by_tag.setdefault(node.tag, []).append(node)
    metadata = (document.css('meta,script[type="application/ld+json"],time[datetime]') if selected is None else
                [node for node in selected if node.tag == "meta"
                 or node.tag == "script" and node.attrs.sget("type") == "application/ld+json"
                 or node.tag == "time" and node.attrs.sget("datetime") is not None])
    timestamp = (_native_timestamp(_document("".join(node.html for node in metadata).encode("utf-8")))
                 if metadata else _stamp(None))
    if selected is None:
        root = document.css_first("article") or document.css_first("main") or document.root
        for node in root.css("script,style"):
            node.decompose()
        h1 = root.css_first("h1")
        og = document.css_first('meta[property="og:title"]')
        title_node = document.css_first("title")
    else:
        root = next(iter(by_tag.get("article", [])), None) or next(iter(by_tag.get("main", [])), None) or document.root
        scoped = []
        for node in selected:
            ancestor = node
            while ancestor is not None:
                if ancestor.mem_id == root.mem_id:
                    scoped.append(node)
                    break
                ancestor = ancestor.parent
        cleanup = [node for node in scoped if node.tag in ("script", "style")]
        h1 = next((node for node in scoped if node.tag == "h1"), None)
        og = next((node for node in by_tag.get("meta", []) if node.attrs.sget("property") == "og:title"), None)
        title_node = next(iter(by_tag.get("title", [])), None)
        chrome = [node for node in scoped if node.tag in ("nav", "header", "footer")]
        for node in cleanup:
            node.decompose()
    title = _clean(_lexbor_text_fragments(h1) if h1 is not None else
                   og.attrs.sget("content") if og is not None else
                   _lexbor_text_fragments(title_node) if title_node is not None else "")
    for node in root.css("nav,header,footer") if selected is None else chrome:
        node.decompose()
    text = _lexbor_text_fragments(root)
    tables, table_spans = [], []
    for table in root.css("table"):
        rows, spans = [], []
        for row in table.css("tr"):
            cells = [cell for cell in row.iter() if cell.tag in ("td", "th")]
            values = [" ".join(cell.text(separator=" ").split()) for cell in cells]
            if not any(values):
                continue
            rows.append(values)
            row_spans = []
            for cell in cells:
                attrs = cell.attrs
                rowspan, colspan = attrs.sget("rowspan", "1"), attrs.sget("colspan", "1")
                if rowspan == "1" and colspan == "1":
                    row_spans.append([1, 1])
                    continue
                rowspan, colspan = rowspan.strip(), colspan.strip()
                row_spans.append([int(rowspan) if rowspan.isdecimal() else 1,
                                  int(colspan) if colspan.isdecimal() and int(colspan) > 0 else 1])
            spans.append(row_spans)
        if rows:
            tables.append(rows)
            table_spans.append(spans)
    return title, text, tables, table_spans, timestamp


def _sec_report_facts(tree, url, event):
    """Read the filing's own DEI cover facts, never comparative XBRL contexts."""
    if (urlparse(url).hostname or "").lower() not in ("sec.gov", "www.sec.gov"):
        return None
    required = {"DocumentType", "DocumentPeriodEndDate", "DocumentFiscalYearFocus",
                "DocumentFiscalPeriodFocus", "EntityRegistrantName", "EntityCentralIndexKey"}
    contexts = {}
    native = isinstance(tree, LexborHTMLParser)
    nodes = tree.css('[name^="dei:"]') if native else tree.iter("ix:nonnumeric")
    for node in nodes:
        if native and node.tag != "ix:nonnumeric":
            continue
        get = node.attrs.sget if native else node.get
        name = get("name", "")
        if name.startswith("dei:") and name[4:] in required:
            value = _lexbor_text_fragments(node) if native else _text(node)
            contexts.setdefault(get("contextref"), {}).setdefault(name[4:], set()).add(_clean(value))
    covers = [values for values in contexts.values()
              if values.get("DocumentType", set()) & {"10-Q", "10-K"}]
    if not covers:
        return None
    if len(covers) != 1 or set(covers[0]) != required or any(len(v) != 1 for v in covers[0].values()):
        return {"identity": False, "reporting_period": False, "facts": {},
                "reason": "missing_or_conflicting_cover_facts"}
    facts = {key: next(iter(values)) for key, values in covers[0].items()}
    period_end = None
    for pattern in ("%B %d, %Y", "%Y-%m-%d"):
        try:
            period_end = datetime.strptime(facts["DocumentPeriodEndDate"], pattern).date().isoformat()
            break
        except ValueError:
            pass
    identity = (bool(event.get("cik")) and _trusted_issuer_url(url, event) and
                facts["EntityCentralIndexKey"].lstrip("0") == str(event["cik"]).lstrip("0") and
                _identity(facts["EntityRegistrantName"], event, url))
    fiscal_period = "FY" if facts["DocumentType"] == "10-K" and int(event["quarter"]) == 4 else f"Q{event['quarter']}"
    reporting_period = (facts["DocumentFiscalYearFocus"] == str(event["fiscal_year"]) and
                        facts["DocumentFiscalPeriodFocus"] == fiscal_period and
                        period_end == event.get("period_end"))
    return {"identity": bool(identity), "reporting_period": reporting_period, "facts": facts}


def _candidate(url, title, timestamp=None, **extra):
    timestamp = timestamp or _stamp(None)
    return {"url": url, "title": _clean(title), "role": "candidate",
            "published_at": timestamp["value"],
            "published_precision": timestamp["precision"], **extra}


def sec_supporting_title(form, description, *, body=None, event=None, validation=None):
    """Recognize a prepared-remarks exhibit without exempting an exhibit number."""
    if not re.fullmatch(r"EX-99(?:\.\d+)?", form or "", re.I):
        return None
    if validation is not None:
        checks = validation.get("checks", {})
        if (validation.get("accepted") or validation.get("tables")
                or not all(checks.get(key) is True for key in ("identity", "reporting_period", "not_announcement"))):
            return None
    remarks = r"\bprepared\s+(?:management\s+)?remarks\s*$"
    if re.search(remarks, _clean(description), re.I):
        return _clean(description)
    if body is None or event is None or validation is None:
        return None
    lead = _clean(validation.get("text", ""))[:500]
    for node in _document(body).iter():
        heading = _clean(node.text)
        if (len(heading) <= 200 and re.search(remarks, heading, re.I) and heading in lead
                and _identity(heading, event) and _target(heading, event)):
            return heading
    return None


def listing_structure(body: bytes, url: str, content_type: str, event: dict) -> str | None:
    """A readable source is required before absence can be a negative observation.

    Historical announcement links establish an HTML list, while an application
    shell or verification page does not. These are the same evidence categories
    used by the US runner's handoff readiness check.
    """
    parsed = urlparse(url)
    try:
        if "json" in content_type or body.lstrip().startswith((b"{", b"[")):
            payload = json.loads(body)
            if (event.get("symbol") == "KKR" and parsed.hostname == "tools.cms-eqs.com"
                    and parsed.path == "/fcf5b4/content/events/eventbox" and isinstance(payload, dict)
                    and payload.get("@type") == "hydra:Collection"
                    and isinstance(payload.get("hydra:member"), list)
                    and all(isinstance(row, dict) and isinstance(row.get("boxItems"), list)
                            for row in payload["hydra:member"])):
                return "Official KKR event document entries with published file paths"
            if parsed.hostname == "www.barrick.com" and parsed.path == "/Services/PressReleaseService.svc/GetPressReleaseList" and event.get("symbol") == "B":
                entries = payload.get("GetPressReleaseListResult") if isinstance(payload, dict) else None
                if isinstance(entries, list) and all(isinstance(row, dict) and row.get("Headline") and row.get("LinkToDetailPage") for row in entries):
                    return "Official Q4 press release entries with titles and document links"
            if (event.get("symbol") == "OXY" and parsed.hostname == "www.oxy.com"
                    and parsed.path == "/quarterly-earnings-api/filter"):
                entries = payload.get("results") if isinstance(payload, dict) else None
                if isinstance(entries, list) and entries and all(
                        isinstance(row, dict) and isinstance(row.get("date"), dict) and row.get("period")
                        and isinstance(row.get("description"), dict) and row["description"].get("title")
                        and isinstance(row.get("actions"), list)
                        and all(isinstance(action, dict) and action.get("label") and action.get("link")
                                for action in row["actions"]) for row in entries):
                    return "Official Occidental quarterly earnings entries with dated document actions"
            if parsed.hostname == "data.sec.gov" and parsed.path.startswith("/submissions/") and isinstance(payload, dict):
                filings = payload.get("filings")
                recent = filings.get("recent") if isinstance(filings, dict) else None
                if (str(payload.get("cik", "")).lstrip("0") == str(event.get("cik", "")).lstrip("0")
                        and event.get("cik") and isinstance(recent, dict) and isinstance(recent.get("form"), list)):
                    return "SEC submissions CIK and recent filings structure"
            if parsed.hostname in ("sea.com", "www.sea.com") and parsed.path.rstrip("/") == "/api/financial/resource" and event.get("symbol") == "SE":
                if isinstance(payload, list) and any(isinstance(row, dict) and row.get("year") and isinstance(row.get("data"), list) for row in payload):
                    return "Official financial resource years and report entries"
            return None
        if any(kind in content_type for kind in ("xml", "rss", "atom")) or body.lstrip().startswith((b"<?xml", b"<rss", b"<feed")):
            document = ElementTree.fromstring(body)
            for item in document.iter():
                if item.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
                    continue
                fields = {child.tag.rsplit("}", 1)[-1]: child for child in item}
                title, link = fields.get("title"), fields.get("link")
                if title is not None and title.text and link is not None and (link.text or link.get("href")):
                    return "Parsed public feed with titled entry links"
            return None
        document = _document(body)
        if (event.get("symbol") == "SKYD" and parsed.hostname == "ir.skydance.com"
                and parsed.path.rstrip("/") == "/financials/quarterly-results"):
            for link in document.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' qr-doc-list ')]//a[@href]"):
                target = urlparse(urljoin(url, link.get("href")))
                if (target.hostname == parsed.hostname and target.path.startswith("/static-files/")
                        and re.search(r"\bQ[1-4]\s+20\d{2}\b", _text(link))):
                    return "Official Skydance quarterly document directory with labeled report files"
        if (event.get("symbol") == "LCID" and parsed.hostname == "ir.lucidmotors.com"
                and parsed.path.startswith("/events/event-details/")):
            title_node = next(document.iter("title"), None)
            title = _text(title_node) if title_node is not None else ""
            if (parsed.path == f"/events/event-details/lucid-q{event['quarter']}-{event['fiscal_year']}-earnings-call"
                    and _target(title, event) and _identity(title, event)
                    and any("node--nir-event--full" in node.get("class", "").split()
                            for node in document.iter("article"))):
                return "Verified issuer quarter event document directory; report links may be absent"
            return None
        if (event.get("symbol") == "BN" and parsed.hostname == "bn.brookfield.com"
                and parsed.path.rstrip("/") == "/events-news/press-releases"):
            for row in document.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-wrapper ')]"):
                if (row.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-title ')]")
                        and row.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-date ')]")
                        and any(link.get("href", "").startswith("/press-releases/") for link in row.iter("a"))):
                    return "Official Brookfield dated press-release rows and document links"
        if (event.get("symbol") == "NBIS" and parsed.hostname == "nebius.com"
                and parsed.path.rstrip("/") == "/newsroom"):
            for card in document.xpath(".//a[contains(concat(' ', normalize-space(@class), ' '), ' pc-basic-card ')]"):
                if (card.get("href", "").startswith("/newsroom/")
                        and any(_clean(_text(node)) for node in card.iter("h2"))):
                    return "Official Nebius server-rendered titled newsroom cards"
        if (event.get("symbol") == "GIB" and parsed.hostname == "www.cgi.com"
                and parsed.path.rstrip("/") == "/en/newsroom"):
            for card in document.xpath(".//article[contains(concat(' ', normalize-space(@class), ' '), ' teaser-related ')]"):
                if ("Press release" in _text(card)
                        and any(_clean(_text(node)) for node in card.iter("h3"))
                        and any(link.get("href", "").startswith("/en/cgi-") for link in card.iter("a"))):
                    return "Official CGI server-rendered press-release cards"
        if (event.get("symbol") == "FNV" and parsed.hostname in ("www.newswire.ca", "www.prnewswire.com")
                and parsed.path.rstrip("/") == "/news/franco__nevada-corporation"):
            for link in document.iter("a"):
                if (re.fullmatch(r"/news-releases/[^/]+-\d+\.html", urlparse(link.get("href", "")).path)
                        and _identity(_text(link), event)):
                    return "Cision issuer page with titled Franco-Nevada release links"
        if (parsed.hostname == "www.prnewswire.com"
                and (event.get("symbol") in ("TDG", "GIB") and parsed.path.rstrip("/") == "/search/news"
                     or event.get("symbol") == "CSCO" and unquote(parsed.path).rstrip("/") == "/news/cisco-systems,-inc.")):
            for link in document.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' newsCards ')]//a[@href]"):
                target = urlparse(urljoin(url, link.get("href")))
                if (target.hostname == parsed.hostname
                        and re.fullmatch(r"/news-releases/[^/]+-\d+\.html", target.path)
                        and _identity(_text(link), event)):
                    return "PR Newswire server-rendered news cards with issuer-matched release links"
        if (event.get("symbol") == "MRDN" and parsed.hostname == "www.newmediawire.com"
                and parsed.path.rstrip("/") == ""):
            for link in document.xpath(".//ul[contains(concat(' ', normalize-space(@class), ' '), ' news-list ')]//a[@href]"):
                target = urlparse(urljoin(url, link.get("href")))
                if (target.hostname == parsed.hostname and re.fullmatch(r"/news/[^/]+-\d+", target.path)
                        and _clean(_text(link))):
                    return "NewMediaWire publisher-wide recent release list; not an issuer-specific listing"
        for link in document.iter("a"):
            if _clean(_text(link)) and re.search(
                    r"/(?:news-release-details|news-details|press-release-details)/|/news/home/\d+/|"
                    r"/(?:20\d{2})/.*(?:results|earnings|reports)", link.get("href", ""), re.I):
                return "Public announcement links present; current-quarter candidate may be absent"
    except (ValueError, UnicodeError, ElementTree.ParseError):
        pass
    return None


def discover(body: bytes, url: str, content_type: str, event: dict) -> list[dict]:
    """Return target-period links, SEC filing indexes, or EX-99 attachments."""
    found = []
    hostname = (urlparse(url).hostname or "").lower()
    newswire = any(hostname == domain or hostname.endswith("." + domain) for domain in
                   ("businesswire.com", "globenewswire.com", "prnewswire.com", "newmediawire.com", "newswire.ca"))
    if "json" in content_type or body.lstrip().startswith(b"{"):
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return []
        if hostname in ("sea.com", "www.sea.com") and urlparse(url).path.rstrip("/") == "/api/financial/resource":
            if not isinstance(payload, list) or event.get("symbol") != "SE":
                return []
            for year in payload:
                if year.get("year") != int(event["fiscal_year"]):
                    continue
                for report in year.get("data", []):
                    if report.get("quarter") == f"Q{int(event['quarter'])}" and report.get("press_release"):
                        target = _url(url, report["press_release"])
                        if target:
                            found.append(_candidate(target, f"Sea Limited Q{event['quarter']} {event['fiscal_year']} Financial Results",
                                                    identity_verified=True))
            return found
        if not isinstance(payload, dict):
            return []
        if (event.get("symbol") == "OXY" and hostname == "www.oxy.com"
                and urlparse(url).path == "/quarterly-earnings-api/filter"):
            for row in payload.get("results", []):
                title = row.get("description", {}).get("title", "")
                period_title = re.sub(r"\b([1-4])(?:st|nd|rd|th)\s+Quarter\b", r"Q\1", title, flags=re.I)
                if (row.get("period") != f"Q{event['quarter']}" or not _target(period_title, event)
                        or not _FINANCIAL.search(title) or _ANNOUNCEMENT.search(title)):
                    continue
                for action in row.get("actions", []):
                    if action.get("type") != "file":
                        continue
                    target = _url(url, action.get("link", ""))
                    if (not target or urlparse(target).hostname != hostname
                            or not urlparse(target).path.startswith("/siteassets/documents/investors/quarterly-earnings/")):
                        continue
                    label = _clean(action.get("label", ""))
                    found.append(_candidate(target, f"Occidental {title} - {label}", identity_verified=True,
                                            document_role=re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_"),
                                            source_document_label=label,
                                            discovery_route="official_quarterly_documents"))
            return found
        if (event.get("symbol") == "KKR" and hostname == "tools.cms-eqs.com"
                and urlparse(url).path == "/fcf5b4/content/events/eventbox"):
            if payload.get("@type") != "hydra:Collection":
                return []
            seen = set()
            for row in payload.get("hydra:member", []):
                for document in row.get("boxItems", []):
                    title = document.get("title", "")
                    path = document.get("filePath") or ""
                    if (document.get("fileType") != "application/pdf" or not path.startswith("/media/document/")
                            or not _target(title, event) or not _FINANCIAL.search(title)
                            or _ANNOUNCEMENT.search(title)):
                        continue
                    target = "https://ir.kkr.com" + path
                    if target not in seen:
                        seen.add(target)
                        found.append(_candidate(target, "KKR " + title, identity_verified=True,
                                                discovery_route="official_eqs_event_document",
                                                source_document_date=document.get("date")))
            return found
        if hostname == "www.barrick.com" and urlparse(url).path == "/Services/PressReleaseService.svc/GetPressReleaseList" and event.get("symbol") == "B":
            for row in payload.get("GetPressReleaseListResult", []):
                title = row.get("Headline", "")
                if not (_target(title, event) and _FINANCIAL.search(title) and _identity(title, event)) or _ANNOUNCEMENT.search(title):
                    continue
                target = _url(url, row.get("LinkToDetailPage", ""))
                if not target or urlparse(target).hostname != hostname:
                    continue
                try:
                    published = datetime.strptime(row.get("PressReleaseDate", ""), "%m/%d/%Y %H:%M:%S").replace(tzinfo=ZoneInfo("America/New_York")).isoformat()
                except ValueError:
                    published = None
                found.append(_candidate(target, title, _stamp(published, "official_q4_list") if published else None,
                                        identity_verified=True))
            return found
        recent = payload.get("filings", {}).get("recent", {})
        if not recent:
            return []
        expected = str(event.get("cik", "")).lstrip("0")
        if not expected or str(payload.get("cik", "")).lstrip("0") != expected:
            return []
        filing_start = event.get("period_end", "")
        if event.get("window_start"):
            filing_start = datetime.fromisoformat(event["window_start"]).astimezone(
                ZoneInfo("America/New_York")).date().isoformat()
        for i, form in enumerate(recent.get("form", [])[:100]):
            if form not in ("8-K", "6-K", "10-Q", "10-K", "8-K/A", "6-K/A"):
                continue
            def at(key, default=""):
                seq = recent.get(key, [])
                return seq[i] if i < len(seq) else default
            # Realtime monitoring must not spend the release window on old filings.
            if at("filingDate") < filing_start:
                continue
            accession = at("accessionNumber")
            if not re.fullmatch(r"\d{10}-\d{2}-\d{6}", accession):
                continue
            directory = f"https://www.sec.gov/Archives/edgar/data/{expected}/{accession.replace('-', '')}/"
            accepted = at("acceptanceDateTime") or None
            found.append(_candidate(directory + accession + "-index.html", form,
                                    role="filing_index", sec_accepted_at=accepted,
                                    identity_verified=True))
            if form in ("10-Q", "10-K") and at("primaryDocument"):
                found.append(_candidate(urljoin(directory, at("primaryDocument")), form,
                                        sec_accepted_at=accepted, identity_verified=True,
                                        form=form, inspection_only=False))
        return found
    if body.startswith(b"%PDF") or "pdf" in content_type:
        return []
    if "xml" in content_type or body.lstrip().startswith((b"<?xml", b"<rss", b"<feed")):
        try:
            root = ElementTree.fromstring(body)
        except ElementTree.ParseError:
            return []
        for item in root.iter():
            if item.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
                continue
            fields = {child.tag.rsplit("}", 1)[-1]: child for child in item}
            title = fields["title"].text or "" if "title" in fields else ""
            if not _target(title, event) or not _FINANCIAL.search(title) or _ANNOUNCEMENT.search(title):
                continue
            if not _trusted_issuer_url(url, event) and not _identity(title, event):
                continue
            link = fields.get("link")
            href = (link.get("href") or link.text) if link is not None else None
            date = next((fields[k].text for k in ("published", "pubDate", "updated") if k in fields), None)
            if href and (target := _url(url, href)):
                found.append(_candidate(target, title, _stamp(date, "feed")))
        return found
    tree = _document(body)
    _drop_content(tree, "script", "style")
    if (hostname == "ir.skydance.com" and event.get("symbol") == "SKYD"
            and urlparse(url).path.rstrip("/") == "/financials/quarterly-results"):
        for anchor in tree.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' qr-doc-list ')]//a[@href]"):
            title = _clean(_text(anchor))
            if not _target(title, event) or _ANNOUNCEMENT.search(title):
                continue
            target = _url(url, anchor.get("href"))
            parsed_target = urlparse(target) if target else None
            if (parsed_target and parsed_target.hostname == hostname
                    and parsed_target.path.startswith("/static-files/")):
                found.append(_candidate(target, title))
        return list({item["url"]: item for item in found}.values())
    if hostname == "www.berkshirehathaway.com" and event.get("symbol") == "BRK.B":
        # The official reports grid uses image-only links, then a quarterly
        # index. Match the published link itself; do not guess a PDF URL.
        ordinal = {1: "1st", 2: "2nd", 3: "3rd", 4: "4th"}[int(event["quarter"])]
        stem = f"{ordinal}qtr{str(event['fiscal_year'])[-2:]}"
        path = urlparse(url).path
        expected = "/qtrly/links" + stem + ".html" if path == "/reports.html" else "/qtrly/" + stem + ".pdf"
        if path in ("/reports.html", "/qtrly/links" + stem + ".html"):
            for anchor in tree.iter("a"):
                if anchor.get("href") and (target := _url(url, anchor.get("href"))):
                    if urlparse(target).hostname == hostname and urlparse(target).path == expected:
                        found.append(_candidate(target, f"Berkshire Hathaway Q{event['quarter']} {event['fiscal_year']} Quarterly Report"))
            return found
    if (hostname, event.get("symbol")) in (("bam.brookfield.com", "BAM"), ("bn.brookfield.com", "BN")):
        rows = tree.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-wrapper ')]")
        if rows:
            for row in rows:
                titles = row.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-title ')]")
                dates = row.xpath(".//div[contains(concat(' ', normalize-space(@class), ' '), ' press-data-date ')]")
                if not titles or not dates:
                    continue
                title = _clean(_text(titles[0]))
                if not (_identity(title, event) and _FINANCIAL.search(title)) or _ANNOUNCEMENT.search(title):
                    continue
                # BN's actual earnings headlines omit the quarter; the row's
                # release date bounds discovery and full-body validation checks
                # the report period. Its call notices must never become PDFs.
                if event["symbol"] == "BAM" and not (_target(title, event) or _quarter_without_year(title, event)):
                    continue
                try:
                    published_day = datetime.strptime(_clean(_text(dates[0])), "%b %d, %Y").date()
                except ValueError:
                    continue
                if not _date_in_release_window(published_day, event):
                    continue
                for anchor in row.iter("a"):
                    if anchor.get("href") and (target := _url(url, anchor.get("href"))):
                        found.append(_candidate(target, title, discovery_date=published_day.isoformat()))
            return list({item["url"]: item for item in found}.values())
    sec_index = "sec.gov/Archives/edgar/data/" in url and "-index" in url
    if sec_index:
        for row in tree.xpath(".//table[contains(concat(' ', normalize-space(@class), ' '), ' tableFile ')]//tr"):
            cells = list(row.iter("td"))
            if len(cells) < 4:
                continue
            form = _clean(_text(cells[3], "", False)).upper()
            financial_form = bool(re.fullmatch(r"EX-99(?:\.\d+)?", form)) or form in ("10-Q", "10-K")
            description = _text(cells[1]) or form
            supporting_title = sec_supporting_title(form, description)
            financial_required = financial_form and supporting_title is None
            exhibit = form.startswith("EX-") if event.get("symbol") in ("MSGK", "MSGR") else financial_form
            if not (exhibit or form in ("10-Q", "10-K")):
                continue
            anchor = next((tag for tag in cells[2].iter("a") if tag.get("href") is not None), None)
            if anchor is not None:
                target = _url(url, anchor.get("href"))
                if target:
                    candidate = _candidate(target, description, identity_verified=True, form=form,
                                           inspection_only=not financial_required)
                    if supporting_title:
                        candidate.update(supporting_title=supporting_title, classification_basis="sec_index_description")
                    found.append(candidate)
        return found
    # RSS/Atom timestamps belong to each item, never to the whole feed.
    for item in tree.iter("item", "entry"):
        title_tag = next(item.iter("title"), None)
        title = _text(title_tag) if title_tag is not None else ""
        if not _target(title, event) or not _FINANCIAL.search(title) or _ANNOUNCEMENT.search(title):
            continue
        if not _trusted_issuer_url(url, event) and not _identity(title, event):
            continue
        link = next(item.iter("link"), None)
        href = link.get("href") or _text(link, "") if link is not None else None
        if href and (target := _url(url, href)):
            dt = next(item.iter("published", "pubdate", "updated"), None)
            ts = _stamp(_text(dt, "") if dt is not None else None, "feed")
            found.append(_candidate(target, title, ts))
    previous_heading = None
    context_text = {}
    for anchor in tree.iter("a", "h2", "h3", "h4"):
        if anchor.tag != "a":
            previous_heading = anchor
            continue
        if anchor.get("href") is None:
            continue
        target = _url(url, anchor.get("href"))
        if not target or target == _url(url, ""):
            continue
        title = _clean(_text(anchor) or anchor.get("title", ""))
        if re.fullmatch(r"read\s+more", title, re.I):
            # NIR cards can omit href on the real headline and shorten away
            # "to" in the Read More slug. Classify the card's actual headline.
            for level, parent in enumerate(anchor.iterancestors()):
                if level == 3 or parent.tag in ("body", "html"):
                    break
                headline = next((node for node in parent.iter()
                                 if "nir-widget--news--headline" in node.get("class", "").split()), None)
                if headline is not None:
                    title = _clean(_text(next(headline.iter("a"), headline)))
                    break
        if newswire and not _identity(title, event):
            # Distributor search pages contain many other companies' same-quarter releases.
            continue
        href_hint = unquote(urlparse(target).path).replace("-", " ").replace("_", " ")
        direct = title + " " + href_hint
        if _ANNOUNCEMENT.search(direct):
            continue
        if hostname == "enbridge.mediaroom.com" and event.get("symbol") == "ENB":
            # This actual headline puts its year in a distant guidance clause.
            # Its own dated URL bounds discovery; deep validation still checks
            # the report period, so guidance cannot certify the financial body.
            dated_path = re.match(r"/(\d{4}-\d{2}-\d{2})-", urlparse(target).path)
            quarter_title = re.sub(r"\b20\d{2}\b", "", title)
            years = set(re.findall(r"\b20\d{2}\b", title))
            if (dated_path and _identity(title, event) and _FINANCIAL.search(title) and
                    _quarter_without_year(quarter_title, event) and
                    years <= {str(event["fiscal_year"])} and
                    _date_in_release_window(datetime.strptime(dated_path[1], "%Y-%m-%d").date(), event)):
                found.append(_candidate(target, title, discovery_date=dated_path[1]))
                continue
        if hostname.endswith("globenewswire.com") and _FINANCIAL.search(title) and _quarter_without_year(title, event):
            date_path = re.search(r"/news-release/(\d{4})/(\d{2})/(\d{2})/", urlparse(target).path)
            if date_path:
                published_day = datetime(*map(int, date_path.groups())).date()
                if _date_in_release_window(published_day, event):
                    found.append(_candidate(target, title, discovery_date=published_day.isoformat()))
                    continue
        if _target(direct, event) and _FINANCIAL.search(direct):
            found.append(_candidate(target, title or href_hint))
            continue
        if _FINANCIAL.search(title) and re.search(
                r"\b(?:Q[1-4]|(?:first|second|third|fourth)[ -]+quarter)\b", title, re.I):
            # A neighboring article must not supply the target quarter to this link.
            continue
        # Quarterly-report grids commonly use Q3 + an enclosing 2026 heading.
        if not (_FINANCIAL.search(title) or re.search(r"\bQ[1-4]\b", title, re.I)
                or urlparse(target).path.lower().endswith(".pdf")):
            continue
        context = ""
        for level, parent in enumerate(anchor.iterancestors()):
            if level == 3 or parent.tag in ("body", "html"):
                break
            if parent not in context_text:
                context_text[parent] = _clean(_text(parent))
            value = context_text[parent]
            if len(value) <= 800:
                context = value
        if not _target(context + " " + href_hint, event):
            if previous_heading is not None:
                context = _text(previous_heading) + " " + direct
        if _target(context, event) and not _ANNOUNCEMENT.search(title) and (
                _FINANCIAL.search(context) or re.search(r"\bQ[1-4]\b", title, re.I)):
            found.append(_candidate(target, title))
    return list({item["url"]: item for item in found}.values())


def _financial_table(rows):
    if len(rows) < 3:
        return False
    numeric = 0
    for row in rows:
        for cell in row:
            if _DIGIT.search(str(cell or "")):
                numeric += 1
                if numeric == 8:
                    break
        if numeric == 8:
            break
    if numeric < 8:
        return False
    text = " ".join(" ".join(str(cell or "") for cell in row) for row in rows)
    matches = _METRICS.finditer(text)
    return next(matches, None) is not None and next(matches, None) is not None


def is_tgtx_announcement_index(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.hostname == "ir.tgtherapeutics.com" and parsed.path.rstrip("/") == "/press-releases"


SKYD_XLSX_URL = "https://ir.skydance.com/static-files/ce71d9f0-8c13-4a67-9259-576b602305da"
SKYD_PDF_URL = "https://ir.skydance.com/static-files/af510edc-00d2-44ca-8e8c-b73466e99694"
XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _validate_skyd_xlsx(body, url, content_type, event):
    result = {"accepted": False, "reason": "unsupported_spreadsheet_source", "title": "",
              "text": "", "tables": [], "table_spans": [], "publisher_timestamp": _stamp(None),
              "checks": {"source": False}, "tables_complete": False,
              "tables_extraction_scope": "not_parsed", "document_format": "xlsx"}
    if (event.get("symbol") != "SKYD" or url != SKYD_XLSX_URL
            or content_type.split(";", 1)[0].strip().lower() != XLSX_CONTENT_TYPE
            or not body.startswith(b"PK\x03\x04")):
        return result
    try:
        from spreadsheet_tables import extract_xlsx_tables
        workbook = extract_xlsx_tables(body)
    except Exception as exc:
        result.update(reason="xlsx_parse_error: " + type(exc).__name__, checks={"parse": False})
        return result
    # The cover identifies this release; comparison years in the schedules do not.
    sheets = {sheet["name"]: sheet for sheet in workbook["worksheets"]}
    cover = " ".join(str(cell["value"] or "") for cell in sheets.get("Cover", {}).get("cells", []))
    intro = " ".join(str(cell["value"] or "") for cell in sheets.get("Intro", {}).get("cells", []))
    heading = re.search(r"\b(March|June|September|December)\s+Quarter\s+(20\d{2})\s+Trending Schedules\b", cover, re.I)
    period = None
    if heading:
        quarter_ends = {"march": "03-31", "june": "06-30", "september": "09-30", "december": "12-31"}
        period = heading[2] + "-" + quarter_ends[heading[1].lower()]
    tables = workbook["tables"]
    checks = {"identity": bool(re.search(r"\bSkydance Corporation\b", intro, re.I)),
              "reporting_period": period is not None and period == event["period_end"],
              "not_announcement": True,
              "financial_body": len(workbook["text"]) >= 1200 and len(_METRICS.findall(workbook["text"])) >= 5,
              "financial_tables": any(_financial_table(table) for table in tables),
              "tables_complete": (workbook["tables_complete"] is True and
                  len(tables) == len(workbook["worksheets"]) == workbook["xlsx_sheets_total"] == workbook["xlsx_sheets_processed"]),
              "display_complete": workbook["display_complete"] is True and workbook["unsupported_display_cell_count"] == 0}
    accepted = all(checks.values())
    result.update(accepted=accepted, reason="validated_release" if accepted else
                  "needs_review: " + ",".join(key for key, value in checks.items() if not value),
                  title=_clean(heading[0]) if heading else "Trending Schedules",
                  text=workbook["text"], tables=tables, table_spans=workbook["table_spans"], checks=checks,
                  spreadsheet={key: value for key, value in workbook.items() if key not in ("text", "tables", "table_spans")},
                  tables_complete=checks["tables_complete"] and checks["display_complete"],
                  tables_extraction_scope=workbook["tables_extraction_scope"], quality_reason=workbook["quality_reason"],
                  document_facts={"cover_period_end": period},
                  **{key: workbook[key] for key in ("xlsx_sheets_total", "xlsx_sheets_processed", "explicit_cell_count",
                                                    "formula_count", "merge_count", "display_complete")})
    return result


def check_xlsx_archive(body, report):
    """Check an exported workbook against its complete original, outside capture timing."""
    import hashlib
    from spreadsheet_tables import extract_xlsx_tables
    saved = report.get("spreadsheet", {})
    if saved.get("display_complete") is not True or saved.get("tables_complete") is not True:
        raise ValueError("xlsx_structure_or_display_unverified")
    if len(body) != saved.get("source_bytes") or hashlib.sha256(body).hexdigest() != saved.get("source_sha256"):
        raise ValueError("xlsx_original_digest_or_length_mismatch")
    actual = extract_xlsx_tables(body)
    for key, value in actual.items():
        if key == "parse_ms":  # Reverification never substitutes the original capture clock.
            continue
        archived = report.get(key) if key in ("text", "tables", "table_spans") else saved.get(key)
        if archived != value:
            raise ValueError("xlsx_archive_mismatch:" + key)


def _skyd_pdf_facts(native, event):
    title = native["pdf_metadata"]["title"]
    metadata_period = re.fullmatch(r"Ex 99_Q([1-4])['\u2019](\d{2})", title)
    operations = next((table for table in native["table_details"] if table["page"] == 17), None)
    column_period = None
    if operations:
        try:
            column_period = datetime.strptime(operations["rows"][1][1] + " " + operations["rows"][2][1],
                                               "Three Months Ended %B %d, %Y").date().isoformat()
        except (ValueError, IndexError):
            pass
    quarter, year = (int(metadata_period[1]), 2000 + int(metadata_period[2])) if metadata_period else (None, None)
    return {"identity": "SKYDANCE CORPORATION AND SUBSIDIARIES" in native["pages"][16]
                       and "Paramount Skydance" in native["pages"][1],
            "reporting_period": bool(quarter == event["quarter"] and year == event["fiscal_year"]
                and column_period == event["period_end"]
                and re.search(r"\bParamount Skydance Q" + str(quarter) + r"\b", native["pages"][1])),
            "facts": {"metadata_title": title, "metadata_quarter": quarter, "metadata_year": year,
                      "primary_operations_column_period_end": column_period, "identity_pages": [2, 17]}}


def check_skyd_pdf_archive(body, report):
    """Recheck all native word/column/span evidence outside the capture clock."""
    import hashlib
    from pdf_tables import extract_skyd_pdf_tables
    if hashlib.sha256(body).hexdigest() != "f4d772a634018d7042f887b012a1d534ebe1f685ffdf586a48e646e421008694":
        raise ValueError("skyd_pdf_original_digest_mismatch")
    actual = extract_skyd_pdf_tables(body)
    if actual["tables_complete"] is not True:
        raise ValueError("skyd_pdf_structure_unverified")
    for key in ("text", "tables", "table_spans", "table_details", "page_diagnostics"):
        if json.dumps(report.get(key), sort_keys=True) != json.dumps(actual[key], sort_keys=True):
            raise ValueError("skyd_pdf_archive_mismatch:" + key)


def validate(body: bytes, url: str, content_type: str, event: dict, *, prepared_tree=None) -> dict:
    """Validate identity, current reporting period and financial content together.

    Rejected documents remain useful raw evidence and can be reviewed manually.
    prepared_tree is a fresh HTMLParser.feed/close tree of this complete body;
    validation consumes that tree. It is never used for PDFs.
    """
    if is_tgtx_announcement_index(url):
        return {"accepted": False, "reason": "announcement_index_not_full_report", "title": "Press Releases",
                "text": "", "tables": [], "publisher_timestamp": _stamp(None),
                "checks": {"full_report": False}, "tables_complete": False, "tables_extraction_scope": "not_a_report"}
    if body.startswith(b"PK\x03\x04") or XLSX_CONTENT_TYPE in content_type.lower():
        return _validate_skyd_xlsx(body, url, content_type, event)
    tables = []
    table_spans = []
    timestamp = _stamp(None)
    pdf = body.startswith(b"%PDF") or "pdf" in content_type
    cover = None
    pdf_pages_total = pdf_pages_processed = 0
    native_pdf = None
    if pdf:
        pages = []
        title = text = ""
        try:
            parsed_url = urlparse(url)
            if event.get("symbol") == "BRK.B" and parsed_url.hostname in ("berkshirehathaway.com", "www.berkshirehathaway.com") and parsed_url.path.startswith("/qtrly/"):
                from pdf_tables import extract_pdf_tables
                with _PDF_LOCK:
                    native_pdf = extract_pdf_tables(body)
            elif event.get("symbol") == "BAM" and (
                parsed_url.hostname in ("globenewswire.com", "www.globenewswire.com") and parsed_url.path.startswith("/news-release/")
                or parsed_url.hostname == "pnr-files.pro1.gus.wdc.dianum.io" and parsed_url.path.startswith("/globenewswire/articles/")):
                from pdf_tables import extract_bam_pdf_tables
                with _PDF_LOCK:
                    native_pdf = extract_bam_pdf_tables(body, event)
            elif event.get("symbol") == "KKR" and parsed_url.hostname == "ir.kkr.com" and parsed_url.path.startswith("/media/document/"):
                from pdf_tables import extract_kkr_pdf_tables
                with _PDF_LOCK:
                    native_pdf = extract_kkr_pdf_tables(body)
            elif event.get("symbol") == "LCID" and parsed_url.hostname == "ir.lucidmotors.com" and parsed_url.path.startswith("/static-files/"):
                from pdf_tables import extract_lcid_pdf_tables
                native_pdf = extract_lcid_pdf_tables(body, event)
            elif event.get("symbol") == "SKYD" and url == SKYD_PDF_URL:
                from pdf_tables import extract_skyd_pdf_tables
                native_pdf = extract_skyd_pdf_tables(body)
                cover = _skyd_pdf_facts(native_pdf, event)
            else:
                from pdf_tables import extract_generic_pdf_tables
                generic = extract_generic_pdf_tables(body)
                pages = generic["pages"]
                text = generic["text"]
                tables = generic["tables"]
                pdf_pages_total = generic["pdf_pages_total"]
                pdf_pages_processed = generic["pdf_pages_processed"]
                title = _pdf_title(text)
            if native_pdf is not None:
                text = native_pdf["text"]
                tables = native_pdf["tables"]
                pdf_pages_total = native_pdf["pdf_pages_total"]
                pdf_pages_processed = native_pdf["pdf_pages_processed"]
                title = native_pdf["pdf_metadata"]["title"] if event.get("symbol") == "SKYD" and url == SKYD_PDF_URL else _pdf_title(text)
        except Exception as exc:
            return {"accepted": False, "reason": "pdf_parse_error: " + type(exc).__name__,
                    "title": title, "text": "\n".join(pages), "tables": tables, "publisher_timestamp": timestamp,
                    "checks": {"parse": False, "tables_complete": False}, "tables_extraction_scope": "partial",
                    "tables_complete": False, "pdf_pages_total": pdf_pages_total,
                    "pdf_pages_processed": pdf_pages_processed, "pdf_pages_text_extracted": len(pages)}
    elif (prepared_tree is None and event.get("symbol") == "KKR" and body.isascii()
          and url == "https://www.sec.gov/Archives/edgar/data/1404912/000140491226000034/kkr-20260930.htm"):
        document = LexborHTMLParser(body, encoding=False)
        cover = _sec_report_facts(document, url, event) or {
            "identity": False, "reporting_period": False, "facts": {},
            "reason": "missing_or_conflicting_cover_facts"}
        title, text, tables, table_spans, timestamp = _extract_barrick_native_html(body, document=document)
    elif (prepared_tree is None and uses_native_html_parser(url, event)
          and body.isascii() and b"<ix:" not in body.lower()):
        title, text, tables, table_spans, timestamp = _extract_barrick_native_html(body)
    else:
        tree = prepared_tree if prepared_tree is not None else _document(body)
        cover = _sec_report_facts(tree, url, event)
        timestamp = _native_timestamp(tree)
        root = None
        if event.get("symbol") == "MSGK" and urlparse(url).hostname == "investor.msgknicks.com":
            root = next((node for node in tree.iter("div") if
                         {"evergreen-news-details", "module-news-details"}.intersection(node.get("class", "").split())), None)
        if root is None:
            root = next(tree.iter("article"), None)
        if root is None:
            root = next(tree.iter("main"), tree)
        _drop_content(root, "script", "style")
        h1 = next(root.iter("h1"), None)
        og = next((tag for tag in tree.iter("meta") if tag.get("property") == "og:title"), None)
        title_tag = next(tree.iter("title"), None)
        title = _clean(_text(h1) if h1 is not None else
                       og.get("content", "") if og is not None else
                       _text(title_tag) if title_tag is not None else "")
        _drop_content(root, "nav", "header", "footer")
        text = _text(root)
        for table in root.iter("table"):
            rows, spans = [], []
            for row in table.iter("tr"):
                cells = list(row.iterchildren("td", "th"))
                values = [_cell_text(cell) for cell in cells]
                if not any(values):
                    continue
                rows.append(values)
                spans.append([_cell_spans(cell) for cell in cells])
            if rows:
                tables.append(rows)
                table_spans.append(spans)
    lead = _clean(text)[:2000]
    title_report = bool(_FINANCIAL.search(title))
    current_period = _target(title, event) or (
        not title_report and _target(lead[:900], event) and bool(_FINANCIAL.search(lead[:900])))
    # Releases and SEC 10-Qs may name an exact quarter-end instead of Q1/Q2/Q3/Q4.
    # Do not let a comparison period override an explicitly different title.
    period_date = _period_end_in_lead(lead, event)
    explicit_quarter = bool(re.search(r"\b(?:Q[1-4]|(?:first|second|third|fourth)[ -]+quarter)\b", title, re.I))
    title_years = re.findall(r"\b20\d{2}\b", title)
    if period_date and (not explicit_quarter or _target(title, event) or _quarter_without_year(title, event)) and (
            not title_years or str(event["fiscal_year"]) in title_years):
        current_period = True
    announcement = bool(_ANNOUNCEMENT.search(title or lead[:400]))
    body_metrics = _METRICS.finditer(text)
    checks = {
        "identity": cover["identity"] if cover is not None else _identity(title + " " + lead, event, url),
        "reporting_period": cover["reporting_period"] if cover is not None else bool(current_period),
        "not_announcement": not announcement,
        "financial_body": len(text) >= 1200 and all(next(body_metrics, None) is not None for _ in range(5)),
        # Financial classification is an acceptance gate, never a content filter.
        "financial_tables": any(_financial_table(rows) for rows in tables),
    }
    if native_pdf is not None:
        checks["tables_complete"] = native_pdf["tables_complete"]
    publisher_pdf_needs_review = (pdf and native_pdf is None and (
        event.get("symbol") == "BAM" and parsed_url.hostname in ("globenewswire.com", "www.globenewswire.com", "pnr-files.pro1.gus.wdc.dianum.io")
        or event.get("symbol") == "KKR" and parsed_url.hostname == "ir.kkr.com" and parsed_url.path.startswith("/media/document/")))
    if publisher_pdf_needs_review:
        # This publisher's untagged PDF has no native cell rectangles. The
        # text-alignment fallback clips prose and splits financial amounts.
        # Preserve its full text and candidate tables without certifying them.
        checks["tables_complete"] = False
    accepted = all(checks.values())
    result = {"accepted": accepted,
            "reason": "validated_release" if accepted else "needs_review: " + ",".join(k for k, v in checks.items() if not v),
            "title": title, "text": text, "tables": tables,
            "publisher_timestamp": timestamp, "checks": checks,
            "tables_extraction_scope": "full_detected", "tables_complete": True}
    if not pdf:
        result["table_spans"] = table_spans
    if native_pdf is not None:
        result.update({key:native_pdf[key] for key in ("table_details", "page_diagnostics", "pdf_structure_checks", "tables_extraction_scope", "tables_complete", "quality_reason")})
        if "table_spans" in native_pdf:
            result["table_spans"] = native_pdf["table_spans"]
        result["pdf_parse_ms"] = native_pdf["parse_ms"]
        result["pdf_parse_phases_ms"] = native_pdf.get("phases_ms")
        if "pdf_metadata" in native_pdf:
            result["pdf_metadata"] = native_pdf["pdf_metadata"]
    elif publisher_pdf_needs_review:
        result.update(tables_complete=False, tables_extraction_scope="unverified_text_alignment",
                      quality_reason="publisher_pdf_table_cells_not_verified")
    if cover is not None:
        result["document_facts"] = cover["facts"]
    if pdf:
        result.update(pdf_pages_total=pdf_pages_total, pdf_pages_processed=pdf_pages_processed,
                      pdf_pages_text_extracted=native_pdf["pdf_pages_text_extracted"] if native_pdf is not None else len(pages))
    return result
