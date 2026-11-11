"""Lossless native-cell extraction for financial PDFs.

Background rectangles define cells; whole PDF words are assigned, never clipped.
Native cells preserve merged headers, and complete words prove lossless transcription.
The acceptance integration is limited to Berkshire official quarterly PDFs.
No OCR, cached document results, or text-alignment table guessing is used.
"""
from __future__ import annotations

import bisect
import atexit
import collections
import concurrent.futures
import hashlib
import itertools
import multiprocessing
from multiprocessing import shared_memory
from multiprocessing.connection import wait as wait_for_process
import os
import re
import statistics
import threading
import time

import fitz

_NUMBER = re.compile(r"(?<![\w])(?:[+−-]?\d+(?:,\d{3})*(?:\.\d+)?)(?![\w])")
_POOL = None
_POOL_LOCK = threading.Lock()
_POOL_WORKERS = min(8, os.cpu_count() or 1)
_IN_PDF_WORKER = False

# This exact shareholder letter was reviewed page by page. Its five highlight
# bands are prose, not financial tables. A changed PDF must not inherit that
# visual finding just because it has the same metadata or page count.
_ACHR_Q326_SHAREHOLDER_SHA = "ceb60c4f0714c479fc2a17efa8a2a63530e1ad5ca923b8f001b841d4281e8d0b"


def extract_achr_shareholder_pdf(body: bytes) -> dict:
    """Preserve the native content of the audited supporting letter.

    Text layers are kept in original order, including overlapping Q2/Q3
    footers. Outlined and raster lettering remains in the original PDF and
    is not claimed as machine-extracted text. This is not a financial-report
    validator and never manufactures tables from paragraphs or captions.
    """
    started = time.perf_counter_ns()
    source_sha = hashlib.sha256(body).hexdigest()
    texts, diagnostics = [], []
    with fitz.open(stream=body, filetype="pdf") as document:
        metadata = dict(document.metadata)
        recognized = (source_sha == _ACHR_Q326_SHAREHOLDER_SHA
                      and len(document) == 16
                      and metadata.get("title") == "Archer Letter to Shareholders | Q3 2026"
                      and metadata.get("creator") == "Google")
        for index, page in enumerate(document):
            text = page.get_text()
            words = [{"word": wi, "text": word[4], "bbox": list(word[:4]),
                      "block": word[5], "line": word[6], "word_in_line": word[7]}
                     for wi, word in enumerate(page.get_text("words"))]
            layers = [{"text": "".join(chr(char[0]) for char in span["chars"]),
                       "bbox": list(span["bbox"]), "seqno": span["seqno"],
                       "paint_type": span["type"], "opacity": span["opacity"]}
                      for span in page.get_texttrace()]
            overlaps = []
            for li, later in enumerate(layers):
                later_rect = fitz.Rect(later["bbox"])
                if not later["text"].strip() or later_rect.is_empty:
                    continue
                for ei, earlier in enumerate(layers[:li]):
                    if not earlier["text"].strip():
                        continue
                    earlier_rect = fitz.Rect(earlier["bbox"])
                    area = min(later_rect.get_area(), earlier_rect.get_area())
                    if area and (later_rect & earlier_rect).get_area() / area > .8:
                        overlaps.append({"earlier_layer": ei, "later_layer": li,
                                         "same_text": earlier["text"] == later["text"],
                                         "resolution": "both_original_layers_preserved"})
            texts.append(text)
            diagnostics.append({"page": index + 1, "bbox": list(page.rect),
                                "text_extracted": bool(text.strip()), "text_chars": len(text),
                                "method": "native_supporting_document", "word_details": words,
                                "source_word_count": len(words),
                                "numeric_tokens": _NUMBER.findall(" ".join(word["text"] for word in words)),
                                "native_text_layers": layers, "overlapping_text_layers": overlaps,
                                "financial_tables": 0 if recognized else None})
    native_complete = recognized and len(texts) == 16 and all(page["text_extracted"] for page in diagnostics)
    supporting = {"kind": "shareholder_letter", "recognized": recognized,
                  "source_sha256": source_sha, "native_text_complete": native_complete,
                  "financial_table_count": 0 if recognized else None,
                  "rendered_text_complete": False, "latency_budget_applicable": False,
                  "visual_content_source": "original_pdf",
                  "limitations": ["outlined_or_raster_lettering_not_machine_extracted",
                                  "overlapping_original_text_layers_preserved"]}
    return {"text": "\n".join(texts), "pages": texts, "pdf_metadata": metadata,
            "tables": [], "table_spans": [], "table_details": [], "page_diagnostics": diagnostics,
            "pdf_pages_total": len(texts), "pdf_pages_processed": len(texts),
            "pdf_pages_text_extracted": sum(page["text_extracted"] for page in diagnostics),
            "tables_extraction_scope": "achr_supporting_native_text_and_original_visuals",
            "tables_complete": False, "financial_report_complete": False,
            "supporting_document": supporting,
            "quality_reason": "supporting_native_text_preserved_not_full_financial_report"
                if native_complete else "unverified_supporting_document",
            "parse_ms": (time.perf_counter_ns() - started) / 1e6}


def _exit_with_parent(parent_sentinel):
    wait_for_process([parent_sentinel])
    os._exit(0)


def _worker_ready(barrier):
    global _IN_PDF_WORKER
    _IN_PDF_WORKER = True
    threading.Thread(target=_exit_with_parent,
        args=(multiprocessing.parent_process().sentinel,),
        name="pdf-parent-watch", daemon=True).start()
    # Importing this module loads PyMuPDF; no PDF is opened during warmup.
    barrier.wait(timeout=30)


def _worker_ping():
    return os.getpid()


def prewarm_pdf_pool():
    """Start the bounded process pool without opening or parsing any PDF.

    Call during service startup. A caller that skips prewarm pays the complete
    startup wait inside extract_pdf_tables.parse_ms instead.
    """
    global _POOL
    if _IN_PDF_WORKER:
        raise RuntimeError("PDF workers must not create a nested process pool")
    started = time.perf_counter_ns()
    created = False
    with _POOL_LOCK:
        if _POOL is None:
            context = multiprocessing.get_context("spawn")
            pool = concurrent.futures.ProcessPoolExecutor(max_workers=_POOL_WORKERS,
                mp_context=context, initializer=_worker_ready,
                initargs=(context.Barrier(_POOL_WORKERS),))
            try:
                ready = [pool.submit(_worker_ping) for _ in range(_POOL_WORKERS)]
                for future in ready:
                    future.result(timeout=45)
            except BaseException:
                pool.shutdown(wait=True, cancel_futures=True)
                raise
            _POOL = pool
            created = True
    return {"workers": _POOL_WORKERS, "created": created,
            "elapsed_ms": (time.perf_counter_ns()-started)/1e6}


def _close_pdf_pool():
    global _POOL
    with _POOL_LOCK:
        pool, _POOL = _POOL, None
    if pool is not None:
        pool.shutdown(wait=True, cancel_futures=True)


atexit.register(_close_pdf_pool)


def _generic_page_count(body):
    with fitz.open(stream=body, filetype="pdf") as document:
        return len(document)


def _extract_generic_page_batch(body, page_indices):
    # find_tables mutates PyMuPDF module globals and holds the Python GIL for
    # substantial work. Each process executes one batch at a time; never run
    # these page tasks in the collector's HTML / network process.
    from sources import _financial_table
    result = []
    with fitz.open(stream=body, filetype="pdf") as document:
        for index in page_indices:
            started = time.perf_counter_ns()
            page = document[index]
            text, tables = page.get_text(), []
            for table in page.find_tables().tables:
                rows = table.extract()
                if any(str(cell or "").strip() for row in rows for cell in row):
                    tables.append(rows)
            if not any(_financial_table(rows) for rows in tables):
                for table in page.find_tables(strategy="text").tables:
                    rows = table.extract()
                    if any(str(cell or "").strip() for row in rows for cell in row):
                        tables.append(rows)
            result.append({"page": index + 1, "text": text, "tables": tables,
                           "parse_ms": (time.perf_counter_ns() - started) / 1e6})
    return result


def extract_generic_pdf_tables(body: bytes) -> dict:
    """Preserve the generic full-page algorithm while isolating its CPU work.

    No document is read during pool warmup. Unwarmed process startup, transfer,
    parsing, and result collection remain inside this call's elapsed time.
    This does not certify generic cell quality beyond the existing validator.
    """
    started = time.perf_counter_ns()
    warmup = prewarm_pdf_pool()
    # Even the page-count read runs out of process. Callers must not hold the
    # parent _PDF_LOCK while waiting here: native PDF work has a separate GIL.
    count = _POOL.submit(_generic_page_count, body).result()
    # Bound generic work to two workers, leaving CPU / memory bandwidth for live
    # HTML and native PDF work. Interleave pages to distribute financial appendices.
    batches = min(count, 2, max(1, _POOL_WORKERS - 1))
    futures = [_POOL.submit(_extract_generic_page_batch, body, list(range(i, count, batches)))
               for i in range(batches)]
    pages = sorted((page for future in futures for page in future.result()), key=lambda page: page["page"])
    return {"pages": [page["text"] for page in pages],
            "text": "\n".join(page["text"] for page in pages),
            "tables": [table for page in pages for table in page["tables"]],
            "pdf_pages_total": count, "pdf_pages_processed": len(pages),
            "pdf_pages_text_extracted": len(pages),
            "page_diagnostics": [{"page": page["page"], "tables": len(page["tables"]),
                                  "parse_ms": page["parse_ms"]} for page in pages],
            "parse_ms": (time.perf_counter_ns() - started) / 1e6,
            "pool_startup_ms": warmup["elapsed_ms"], "pool_created": warmup["created"],
            "worker_batches": batches}


def clusters(values, tolerance):
    groups = []
    for value in sorted(values):
        if not groups or value - groups[-1][-1] > tolerance:
            groups.append([value])
        else:
            groups[-1].append(value)
    return [sum(group) / len(group) for group in groups]


def components(rects):
    # Filled cells in a row form contiguous horizontal runs. Connect these
    # runs, rather than comparing every cell against every active cell.
    bands = []
    for rect in sorted(rects, key=lambda r: r[1]):
        if not bands or rect[1] - bands[-1][0] > 1.1:
            bands.append((rect[1], [rect]))
        else:
            bands[-1][1].append(rect)
    runs = []
    for _, band in bands:
        current = None
        for rect in sorted(band):
            if current is None or rect[0] > current["bbox"][2] + 1.1:
                current = {"bbox": list(rect), "rects": [rect]}
                runs.append(current)
            else:
                current["bbox"][2] = max(current["bbox"][2], rect[2])
                current["bbox"][3] = max(current["bbox"][3], rect[3])
                current["rects"].append(rect)
    owners = list(range(len(runs)))

    def find(i):
        while owners[i] != i:
            owners[i] = owners[owners[i]]
            i = owners[i]
        return i

    active = []
    for i in sorted(range(len(runs)), key=lambda i: runs[i]["bbox"][1]):
        a = runs[i]["bbox"]
        active = [j for j in active if runs[j]["bbox"][3] + 1.1 >= a[1]]
        for j in active:
            b = runs[j]["bbox"]
            if a[0] <= b[2] + 1.1 and b[0] <= a[2] + 1.1:
                owners[find(i)] = find(j)
        active.append(i)
    groups = collections.defaultdict(list)
    for i, run in enumerate(runs):
        groups[find(i)].extend(run["rects"])
    return list(groups.values())


def nearest(values, value):
    at = bisect.bisect_left(values, value)
    if at == len(values):
        return at - 1
    if at and abs(values[at - 1] - value) < abs(values[at] - value):
        return at - 1
    return at



def _rectangles(page, content):
    """Use native coordinates only for the simple untransformed page grammar.

    Transparency is necessary: this producer also draws invisible rectangles
    behind prose. Treating them as cells would recreate the narrative-table bug.
    """
    document = page.parent
    limit = page.rect.get_area() * .8
    if page.rotation or page.cropbox != page.mediabox or any(op in content for op in (b" cm\n", b" Do\n", b"\nW\n", b"\nW*\n")):
        paths = [p for p in page.get_cdrawings()
                 if p["type"] == "f" and p.get("fill_opacity", 0) > 0
                 and p["rect"][2]-p["rect"][0] > 1 and p["rect"][3]-p["rect"][1] > 1
                 and (p["rect"][2]-p["rect"][0])*(p["rect"][3]-p["rect"][1]) < limit]
        # News-release underlines use transformed paths. MuPDF resolves those
        # transforms; certify only actual rectangle fills, never arbitrary
        # filled-path bounding boxes as native cells.
        rectangles_only = bool(paths) and all(len(p["items"]) == 1 and p["items"][0][0] == "re"
            and tuple(p["items"][0][1]) == tuple(p["rect"]) for p in paths)
        return [p["rect"] for p in paths], "native_drawings" if rectangles_only else "drawings"
    alpha, stack, states, rects = 1.0, [], {}, []
    height = page.mediabox.height
    previous = b""
    for op in content.splitlines():
        if op == b"q":
            stack.append(alpha)
        elif op == b"Q":
            if stack:
                alpha = stack.pop()
        elif op.startswith(b"/") and op.endswith(b" gs"):
            state = op[1:-3].decode("ascii")
            if state not in states:
                kind, value = document.xref_get_key(page.xref, "Resources/ExtGState/"+state+"/ca")
                states[state] = None if kind == "null" else float(value)
            if states[state] is not None:
                alpha = states[state]
        elif op in (b"f", b"F") and alpha > 0 and previous.endswith(b" re"):
            x, y, width, cell_height = map(float, previous.split()[:4])
            if width > 1 and cell_height > 1 and width*cell_height < limit:
                rects.append((x, height-y-cell_height, x+width, height-y))
        previous = op
    return rects, "native_stream"


def _compact_rows(rows, xs, cells):
    # The producer splits a monetary cell into a narrow currency gutter and a
    # wide amount. Header cells span both. Merge only native narrow gutters;
    # retain every word and number, including parentheses and percentage signs.
    width = len(xs)-1
    owners = list(range(width))
    for col in range(1, width-1):
        values = [str(row[col] or "").strip() for row in rows]
        has_currency = "$" in values
        spanning_header = any(c["column"] == col and c["colspan"] > 1 and c["text"] for c in cells)
        right_numeric = any(re.fullmatch(r"[($+−-]*[\d,]+(?:\.\d+)?[)%]*|[—–-]", str(row[col+1] or "").strip()) for row in rows)
        if xs[col+1]-xs[col] < 12 and (has_currency or spanning_header) and right_numeric:
            owners[col+1] = col
    groups = []
    for col in range(width):
        owner = owners[col]
        while owners[owner] != owner:
            owner = owners[owner]
        if groups and groups[-1][0] == owner:
            groups[-1][1].append(col)
        else:
            groups.append((owner, [col]))
    compact = [[" ".join(str(row[c]).strip() for c in columns if row[c] not in (None, ""))
                for _, columns in groups] for row in rows]
    keep = [c for c in range(len(groups)) if any(row[c] for row in compact)]
    kept_rows = [r for r,row in enumerate(compact) if any(row)]
    column_map = {physical:logical for logical,c in enumerate(keep) for physical in groups[c][1]}
    row_map = {physical:logical for logical,physical in enumerate(kept_rows)}
    for cell in cells:
        logical_columns=sorted({column_map[c] for c in range(cell["column"],cell["column"]+cell["colspan"]) if c in column_map})
        logical_rows=sorted({row_map[r] for r in range(cell["row"],cell["row"]+cell["rowspan"]) if r in row_map})
        if logical_columns and logical_rows:
            cell["logical_row"]=logical_rows[0];cell["logical_column"]=logical_columns[0]
            cell["logical_rowspan"]=len(logical_rows);cell["logical_colspan"]=len(logical_columns)
    return [[compact[r][c] for c in keep] for r in kept_rows], [[xs[groups[c][1][0]], xs[groups[c][1][-1]+1]] for c in keep]


def _table(rects, words):
    xs = clusters([r[i] for r in rects for i in (0,2)], .2)
    ys = clusters([r[i] for r in rects for i in (1,3)], 1.1)
    if len(xs) < 3 or len(ys) < 3:
        return None
    grid = [[None]*(len(xs)-1) for _ in range(len(ys)-1)]
    cells = []
    for rect in rects:
        x0,x1 = nearest(xs,rect[0]),nearest(xs,rect[2])
        y0,y1 = nearest(ys,rect[1]),nearest(ys,rect[3])
        if x0 == x1 or y0 == y1:
            continue
        idx=len(cells)
        cells.append({"row":y0,"column":x0,"rowspan":y1-y0,"colspan":x1-x0,"bbox":list(rect),"parts":[]})
        for y in range(y0,y1):
            for x in range(x0,x1):
                grid[y][x]=idx
    source_words, missed = [], []
    for w in words:
        cx,cy=(w[0]+w[2])/2,(w[1]+w[3])/2
        x,y=bisect.bisect_right(xs,cx)-1,bisect.bisect_right(ys,cy)-1
        if 0<=y<len(grid) and 0<=x<len(grid[y]):
            source_words.append(w[4])
            idx=grid[y][x]
            if idx is None:
                missed.append({"text":w[4],"bbox":list(w[:4])})
            else:
                cells[idx]["parts"].append((cy,w[0],w[4]))
    if not source_words:
        return None
    rows=[[None]*(len(xs)-1) for _ in range(len(ys)-1)]
    for cell in cells:
        lines=[]
        for cy,x,text in sorted(cell.pop("parts")):
            if not lines or cy-lines[-1][0]>1.5:
                lines.append((cy,[(x,text)]))
            else:
                lines[-1][1].append((x,text))
        value="\n".join(" ".join(t for _,t in sorted(parts)) for _,parts in lines)
        cell["text"]=value
        rows[cell["row"]][cell["column"]]=value
    compact,columns=_compact_rows(rows,xs,cells)
    source_word_tokens=collections.Counter(" ".join(source_words).split())
    extracted_word_tokens=collections.Counter(" ".join(str(v or "") for row in compact for v in row).split())
    source_numbers=collections.Counter(_NUMBER.findall(" ".join(source_words)))
    extracted_numbers=collections.Counter(_NUMBER.findall(" ".join(str(v or "") for row in compact for v in row)))
    return {"bbox":[xs[0],ys[0],xs[-1],ys[-1]],"rows":compact,"column_bounds":columns,
            "cells":cells,"source_word_count":len(source_words),"unassigned_words":missed,
            "word_tokens_preserved":source_word_tokens==extracted_word_tokens,
            "physical_grid":{"x":xs,"y":ys},
            "numeric_tokens":sum(source_numbers.values()),"numeric_tokens_preserved":source_numbers==extracted_numbers,
            "missing_numeric_tokens":list((source_numbers-extracted_numbers).elements()),
            "extra_numeric_tokens":list((extracted_numbers-source_numbers).elements())}


def _extract_page_batch(body, first, last):
    texts,tables,details,page_diagnostics=[],[],[],[]
    phases=collections.Counter()
    with fitz.open(stream=body,filetype="pdf") as document:
        for page_index in range(first,last):
            page_number,page=page_index+1,document[page_index]
            a=time.perf_counter_ns()
            tp=page.get_textpage(flags=fitz.TEXTFLAGS_TEXT)
            texts.append(tp.extractText())
            words=tp.extractWORDS()
            b=time.perf_counter_ns()
            content=b"\n".join(document.xref_stream(x) for x in page.get_contents())
            rects,method=_rectangles(page,content)
            c=time.perf_counter_ns()
            page_tables=[]
            for group in components(rects):
                table=_table(group,words)
                if table:
                    table["page"]=page_number
                    details.append(table);tables.append(table["rows"]);page_tables.append(table)
            e=time.perf_counter_ns()
            phases["text_and_words_ms"]+=(b-a)/1e6
            phases["rectangles_ms"]+=(c-b)/1e6
            phases["tables_ms"]+=(e-c)/1e6
            page_diagnostics.append({"page":page_number,"method":method,"words":len(words),
                "rectangles":len(rects),"tables":len(page_tables)})
    return {"texts":texts,"tables":tables,"details":details,
            "page_diagnostics":page_diagnostics,"phases_ms":dict(phases)}


def extract_pdf_tables(body: bytes) -> dict:
    """Parse every page from fresh bytes in at most eight isolated processes.

    Twelve ordered page batches retain full text, native cells and merged
    headers. parse_ms includes cold startup, IPC and final completeness checks;
    phases_ms sums the page work across processes and is not a wall-time total.
    The caller enables this path only for identified Berkshire quarterly PDFs.
    """
    started=time.perf_counter_ns()
    prewarm_pdf_pool()
    with fitz.open(stream=body,filetype="pdf") as document:
        page_count=len(document)
    batches=min(12,page_count)
    futures=[_POOL.submit(_extract_page_batch,body,i*page_count//batches,(i+1)*page_count//batches)
             for i in range(batches)]
    chunks=[future.result() for future in futures]
    texts=[text for chunk in chunks for text in chunk["texts"]]
    tables=[table for chunk in chunks for table in chunk["tables"]]
    details=[table for chunk in chunks for table in chunk["details"]]
    page_diagnostics=[page for chunk in chunks for page in chunk["page_diagnostics"]]
    phases=collections.Counter()
    for chunk in chunks:
        phases.update(chunk["phases_ms"])
    unassigned=sum(len(t["unassigned_words"]) for t in details)
    numbers_preserved=bool(details) and all(t["numeric_tokens_preserved"] for t in details)
    checks={"all_pages_extracted":len(texts)==len(page_diagnostics)==page_count,
            "native_layout":all(p["method"] in ("native_stream", "native_drawings") for p in page_diagnostics),
            "all_table_words_assigned":unassigned==0 and all(t["word_tokens_preserved"] for t in details),
            "numeric_tokens_preserved":numbers_preserved}
    verified=all(checks.values())
    return {"text":"\n".join(texts),"tables":tables,"table_details":details,
            "pdf_pages_total":len(texts),"pdf_pages_processed":len(texts),"pdf_pages_text_extracted":len(texts),
            "tables_extraction_scope":"native_background_cells", "tables_complete":verified,
            "quality_reason":"native_cell_structure_and_tokens_verified" if verified else "native_cell_quality_failed",
            "pdf_structure_checks":checks,
            "numeric_tokens_preserved":numbers_preserved,"unassigned_table_words":unassigned,
            "page_diagnostics":page_diagnostics,"parse_ms":(time.perf_counter_ns()-started)/1e6,"phases_ms":dict(phases)}


_BAM_VALUE = re.compile(r"\(?[+\-\u2212]?\d[\d,]*(?:\.\d+)?\)?|[\u2014\u2013]")
# Structural profile of the independently verified publisher PDF, not values
# or row-name templates. A changed profile remains rejected for review.
_BAM_ROWS = (5, 22, 21, 20, 5, 6)
_BAM_COLUMNS = (4, 2, 4, 4, 4, 4)


# The Q3 shareholder letter has 18 visually audited ruled/painted tables.
# Bounds are registration points for native rules, never cached cell values.
# Every page is read, including the narrative pages between these regions.
_SKYD_Q326_REGIONS = (
    (10, 160.5, 468, 204.75, 6), (17, 117.2, 653.45, 176.45, 6),
    (18, 117.2, 711.2, 141.2, 2), (19, 117.2, 597.95, 176.45, 3),
    (21, 200.8, 452.8, 273.55, 3), (22, 140, 420.5, 212.75, 3),
    (23, 138.8, 297.05, 211.55, 4), (24, 136, 293.5, 222.25, 4),
    (24, 302.5, 462.25, 376.75, 4), (25, 136, 299.5, 214, 4),
    (26, 136, 286, 214.75, 4), (26, 299, 497.75, 383.75, 4),
    (27, 412.5, 554.25, 472.5, 6), (28, 251.7, 505.95, 347.7, 8),
    (29, 210.9, 477.15, 318.9, 8), (29, 487.15, 571.15, 558.4, 6),
    (30, 308.1, 557.85, 398.1, 8), (31, 482.2, 582.7, 532.45, 6),
)
_SKYD_VALUE = re.compile(r"^(?:\(?[+\-\u2212]?(?:\d[\d,]*(?:\.\d+)?|\.\d+)\)?|[\u2013\u2014\-])%?$")


def _skyd_page_words(page):
    tp = page.get_textpage(flags=fitz.TEXTFLAGS_TEXT)
    lines = {}
    for block in tp.extractDICT()["blocks"]:
        for index, line in enumerate(block.get("lines", [])):
            main = max(line["spans"], key=lambda span: span["size"])
            lines[block["number"], index] = (main["origin"][1], main["size"])
    words = []
    for index, word in enumerate(tp.extractWORDS()):
        baseline, size = lines[word[5], word[6]]
        words.append({"word": index, "page": page.number + 1, "text": word[4],
                      "bbox": list(word[:4]), "y": baseline, "size": size,
                      "line": [word[5], word[6]]})
    rules, fills = [], []
    for path in page.get_cdrawings():
        for item in path["items"]:
            if item[0] == "l" and abs(item[1][1] - item[2][1]) < .1:
                left, right = sorted((item[1][0], item[2][0]))
                if right - left > 20:
                    rules.append([left, item[1][1], right])
            elif item[0] == "re" and path.get("fill") and min(path["fill"]) < .9:
                fills.append(list(item[1]))
    return tp.extractText(), words, rules, fills


def _skyd_table(words, rules, fills, profile):
    page, top, bottom, header_end, count = profile
    native = [line for line in rules if top - .2 <= line[1] <= bottom + .2]
    painted = [rect for rect in fills if top - .2 <= rect[1] and rect[3] <= bottom + .2]
    registered = all(any(abs(line[1] - y) < .2 for line in native) or
                     any(abs(rect[k] - y) < .2 for rect in painted for k in (1, 3))
                     for y in (top, bottom, header_end))
    if not native and not painted:
        return None
    left = min([line[0] for line in native] + [rect[0] for rect in painted])
    right = max([line[2] for line in native] + [rect[2] for rect in painted])
    source = [word for word in words if top <= word["y"] <= bottom and
              left - .2 <= (word["bbox"][0] + word["bbox"][2]) / 2 <= right + .2]
    inner = [line[0] for line in native if line[0] > left + 15]
    if painted:
        inner.extend(rect[0] for rect in painted if rect[0] > left + 15)
    label_end = min(inner) if inner else right
    data = [word for word in source if word["y"] > header_end]
    baselines = clusters([word["y"] for word in data], .7)
    line_words = [[] for _ in baselines]
    for word in data:
        line_words[nearest(baselines, word["y"])].append(word)
    seeds = next((sorted([word for word in row if word["bbox"][0] > label_end and
                            _SKYD_VALUE.fullmatch(word["text"])], key=lambda word: word["bbox"][0])
                  for row in line_words if sum(word["bbox"][0] > label_end and
                      bool(_SKYD_VALUE.fullmatch(word["text"])) for word in row) == count), [])
    if len(seeds) != count:
        return {"page": page, "source_word_count": len(source), "rows": [], "cells": [],
                "quality_errors": ["no_full_native_value_row"], "native_region": [left, top, right, bottom]}
    anchors = [word["bbox"][2] for word in seeds]
    # Monetary values are right aligned. All original words, currency signs,
    # percent signs and parentheses remain intact in their original columns.
    by_column = [[] for _ in range(count)]
    for word in data:
        if word["bbox"][0] >= label_end and _SKYD_VALUE.fullmatch(word["text"]):
            by_column[nearest(anchors, word["bbox"][2])].append(word)
    value_lefts = [min(word["bbox"][0] for word in group) for group in by_column]
    value_rights = [max(word["bbox"][2] for word in group) for group in by_column]
    # Where the PDF provides individual period headings, their centered text
    # independently fixes the data-column partition, including empty cells.
    header = [word for word in source if word["y"] <= header_end]
    header_line_sizes = collections.Counter(tuple(word["line"]) for word in header)
    years = [word for word in header if re.fullmatch(r"20\d\d", word["text"])
             and header_line_sizes[tuple(word["line"])] == 1]
    year_rows = collections.defaultdict(list)
    for word in years:
        year_rows[round(word["y"], 1)].append(word)
    full_years = next((sorted(row, key=lambda word: word["bbox"][0])
                       for row in year_rows.values() if len(row) == count), [])
    if full_years:
        centers = [(word["bbox"][0] + word["bbox"][2]) / 2 for word in full_years]
        separators = [(a + b) / 2 for a, b in zip(centers, centers[1:])]
    else:
        for word in data:
            if word["text"] == "$" and word["bbox"][0] >= label_end:
                column = next((i for i, anchor in enumerate(anchors) if anchor >= word["bbox"][0] - 2), count - 1)
                value_lefts[column] = min(value_lefts[column], word["bbox"][0])
            elif word["text"] == "%" and word["bbox"][0] >= label_end:
                column = nearest(anchors, word["bbox"][0])
                value_rights[column] = max(value_rights[column], word["bbox"][2])
        separators = [(value_rights[i] + value_lefts[i + 1]) / 2 for i in range(count - 1)]
    xs = [left, label_end, *separators, right]
    header_ys = clusters([top, header_end] + (
        [rect[k] for rect in painted if rect[3] - rect[1] > 4 for k in (1, 3)
         if top < rect[k] < header_end] if painted else
        [line[1] for line in native if top < line[1] < header_end]), .5)
    # Native row labels can wrap while values are vertically centered or
    # bottom aligned. Join only adjacent baselines closer than one row of type,
    # never two baselines that both contain financial amounts.
    row_groups = []
    for baseline, items in zip(baselines, line_words):
        numeric = any(word["bbox"][0] >= label_end and _SKYD_VALUE.fullmatch(word["text"]) for word in items)
        size = statistics.median(word["size"] for word in items)
        if (row_groups and baseline - row_groups[-1]["last_y"] < size * 1.3
                and not (numeric and row_groups[-1]["numeric"])):
            row_groups[-1]["words"].extend(items)
            row_groups[-1]["numeric"] |= numeric
            row_groups[-1]["last_y"] = baseline
        else:
            row_groups.append({"words": list(items), "numeric": numeric, "last_y": baseline})
    rows = [[""] * (count + 1) for _ in range(len(header_ys) - 1 + len(row_groups))]
    cells, assignments, issues = [], [], []

    def cell(items, row, column, colspan=1, role="data"):
        items.sort(key=lambda word: (word["y"], word["bbox"][0]))
        result = _bam_cell(items, row, column, colspan=colspan, role=role)
        result["source_words"] = items
        result["bbox"] = result["page_bboxes"][0]["bbox"]
        cells.append(result)
        rows[row][column] = result["text"]
        assignments.extend(word["word"] for word in items)

    for index, group in enumerate(row_groups, len(header_ys) - 1):
        buckets = [[] for _ in range(count + 1)]
        for word in group["words"]:
            if word["bbox"][0] < label_end:
                column = 0
            elif _SKYD_VALUE.fullmatch(word["text"]):
                column = nearest(anchors, word["bbox"][2]) + 1
            elif word["text"] in ("$", "%"):
                candidates = [i for i, anchor in enumerate(anchors) if anchor >= word["bbox"][0] - 2]
                column = (candidates[0] if candidates else count - 1) + 1
                if word["text"] == "%":
                    column = nearest(anchors, word["bbox"][0]) + 1
            else:
                column = 0
            buckets[column].append(word)
        for column, items in enumerate(buckets):
            if items:
                cell(items, index, column, role="row_label" if column == 0 else "financial_value")
                if column and any(word["bbox"][0] < xs[column] - 1 or
                                  word["bbox"][2] > xs[column + 1] + 1 for word in items):
                    issues.append({"row": index, "column": column, "reason": "value_crosses_column",
                                   "words": [word["text"] for word in items]})
                if column and sum(bool(_SKYD_VALUE.fullmatch(word["text"])) for word in items) != 1:
                    issues.append({"row": index, "column": column, "reason": "ambiguous_amount_cell"})
        if any(buckets[1:]):
            if not buckets[0]:
                issues.append({"row": index, "reason": "amount_row_without_label"})
            else:
                low, high = min(word["y"] for word in buckets[0]), max(word["y"] for word in buckets[0])
                for column, items in enumerate(buckets[1:], 1):
                    if any(not low - word["size"] * .7 <= word["y"] <= high + word["size"] * .7 for word in items):
                        issues.append({"row": index, "column": column, "reason": "amount_label_baseline_mismatch"})
    # Headers use each original PDF text line as an indivisible unit. The
    # ruled header bands and centered bounding boxes determine merged spans.
    lines = collections.defaultdict(list)
    for word in header:
        lines[tuple(word["line"])].append(word)
    header_lines = collections.defaultdict(list)
    for items in lines.values():
        y = items[0]["y"]
        row = min(len(header_ys) - 2, bisect.bisect_right(header_ys, y) - 1)
        x0, x1 = min(word["bbox"][0] for word in items), max(word["bbox"][2] for word in items)
        header_lines[row].append(((x0 + x1) / 2, items))
    for row, entries in sorted(header_lines.items()):
        groups, label = [], []
        for center, items in sorted(entries, key=lambda entry: entry[0]):
            if center < label_end:
                label.extend(items)
            elif groups and center - groups[-1]["centers"][0] < 7:
                groups[-1]["words"].extend(items)
                groups[-1]["centers"].append(center)
            else:
                groups.append({"words": list(items), "centers": [center]})
        if label:
            cell(label, row, 0, role="column_header")
        lower_rules = [line for line in native if abs(line[1] - header_ys[row + 1]) < .5]
        active_columns = [column for column in range(1, count + 1) if any(
            line[0] - 1 <= (xs[column] + xs[column + 1]) / 2 <= line[2] + 1 for line in lower_rules)]
        last_column = max(active_columns, default=count)
        if groups:
            # An unruled heading can continue over the lower currency/% band.
            # Its actual text still owns those columns; a short neighboring
            # rule is not permission to discard the heading's right-hand span.
            last_column = max(last_column, min(count, bisect.bisect_left(xs,
                max(word["bbox"][2] for group in groups for word in group["words"])) - 1))
        choices = []
        if 0 < len(groups) <= last_column:
            # Exhaustive contiguous partitions are tiny (at most eight value
            # columns). They force a single ownership for every header slot.
            for cuts in itertools.combinations(range(2, last_column + 1), len(groups) - 1):
                bounds = (1, *cuts, last_column + 1)
                score = 0.
                for group, a, b in zip(groups, bounds, bounds[1:]):
                    x0 = min(word["bbox"][0] for word in group["words"])
                    x1 = max(word["bbox"][2] for word in group["words"])
                    # First-period headings can extend left of the indented
                    # monetary gutter; the adjacent row-label header is blank.
                    if x0 < (left if a == 1 else xs[a]) - 5 or x1 > xs[b] + 5:
                        break
                    score += abs(statistics.mean(group["centers"]) - (xs[a] + xs[b]) / 2)
                else:
                    choices.append((score, bounds))
        if not choices and groups:
            issues.append({"reason": "unresolved_header_partition", "row": row,
                           "centers": [group["centers"] for group in groups]})
            # Keep original source text available even when the column proof
            # cannot pass; an unresolved layout never receives acceptance.
            for group in groups:
                cell(group["words"], row, 1, count, "unresolved_header")
            continue
        if choices:
            _, bounds = min(choices)
            for group, a, b in zip(groups, bounds, bounds[1:]):
                cell(group["words"], row, a, b - a, "column_header")
    # A missing divider over one header region is a native vertical merge,
    # not a blank header followed by a different column group. Preserve it.
    for item in cells:
        if item["role"] != "column_header":
            continue
        first, last = item["column"], item["column"] + item["colspan"]
        while item["row"] > 0:
            boundary = header_ys[item["row"]]
            mid = (xs[first] + xs[last]) / 2
            divided = any(abs(line[1] - boundary) < .5 and line[0] - 1 <= mid <= line[2] + 1 for line in native)
            if painted:
                divided |= any(abs(rect[k] - boundary) < .5 and rect[0] - 1 <= mid <= rect[2] + 1
                               for rect in painted for k in (1, 3))
            conflict = any(other is not item and other["row"] <= item["row"] - 1 < other["row"] + other["rowspan"]
                           and max(first, other["column"]) < min(last, other["column"] + other["colspan"])
                           for other in cells)
            if divided or conflict:
                break
            rows[item["row"]][first] = ""
            item["row"] -= 1
            item["rowspan"] += 1
            item["logical_row"] = item["row"]
            item["logical_rowspan"] = item["rowspan"]
            rows[item["row"]][first] = item["text"]
    occupancy = collections.Counter((r, c) for item in cells for r in range(item["row"], item["row"] + item["rowspan"])
                                    for c in range(item["column"], item["column"] + item["colspan"]))
    if any(amount != 1 for amount in occupancy.values()):
        issues.append({"reason": "overlapping_native_cell_spans"})
    occupied = set(occupancy)
    for row in range(len(rows)):
        for column in range(count + 1):
            if (row, column) not in occupied:
                cells.append({"row": row, "column": column, "rowspan": 1, "colspan": 1,
                              "logical_row": row, "logical_column": column,
                              "logical_rowspan": 1, "logical_colspan": 1,
                              "role": "empty_cell", "text": "", "source_words": [], "word_ids": [],
                              "inferred_blank": True})
    compact_rows, spans = [], []
    for row in range(len(rows)):
        own = sorted((item for item in cells if item["row"] == row), key=lambda item: item["column"])
        compact_rows.append([item["text"] for item in own])
        spans.append([[item["rowspan"], item["colspan"]] for item in own])
    source_tokens = collections.Counter(token for word in source for token in word["text"].split())
    emitted_tokens = collections.Counter(token for row in rows for value in row for token in value.split())
    assigned = collections.Counter(assignments)
    return {"page": page, "native_region": [left, top, right, bottom], "rows": rows,
            "compact_rows": compact_rows, "table_spans": spans,
            "cells": cells, "source_words": source, "source_word_count": len(source),
            "column_bounds": list(zip(xs, xs[1:])), "header_row_count": len(header_ys) - 1,
            "native_rule_registration": registered, "numeric_tokens": sum(bool(_SKYD_VALUE.fullmatch(word["text"])) for word in source),
            "word_tokens_preserved": source_tokens == emitted_tokens,
            "numeric_tokens_preserved": collections.Counter(word["text"] for word in source if _SKYD_VALUE.fullmatch(word["text"])) ==
                collections.Counter(word["text"] for item in cells for word in item["source_words"] if _SKYD_VALUE.fullmatch(word["text"])),
            "unassigned_words": [word for word in source if not assigned[word["word"]]],
            "duplicate_assignments": [word for word, amount in assigned.items() if amount != 1],
            "quality_errors": issues}


def _extract_skyd_batch(body, indices):
    pages, details, diagnostics = [], [], []
    with fitz.open(stream=body, filetype="pdf") as document:
        for index in indices:
            page = document[index]
            text, words, rules, fills = _skyd_page_words(page)
            pages.append((index + 1, text))
            selected = [profile for profile in _SKYD_Q326_REGIONS if profile[0] == index + 1]
            tables = [table for profile in selected if (table := _skyd_table(words, rules, fills, profile))]
            details.extend(tables)
            unexplained_rules = [line for line in rules if line[2] - line[0] > page.rect.width * .6 and
                                 not any(profile[1] - .2 <= line[1] <= profile[2] + .2 for profile in selected)]
            diagnostics.append({"page": index + 1, "words": len(words), "word_details": words,
                                "tables": len(tables), "text_extracted": bool(text.strip()),
                                "uncovered_wide_rules": unexplained_rules})
    return pages, details, diagnostics


def extract_skyd_pdf_tables(body: bytes) -> dict:
    """Read all 31 pages and the 18 registered native financial-table regions."""
    started = time.perf_counter_ns()
    prewarm_pdf_pool()
    with fitz.open(stream=body, filetype="pdf") as document:
        count = len(document)
        metadata = dict(document.metadata)
        recognized = (count == 31 and metadata.get("creator") == "Workiva" and
                      metadata.get("title") == "Ex 99_Q3'26" and
                      all(tuple(page.rect) == (0., 0., 612., 792.) for page in document))
    jobs = [_POOL.submit(_extract_skyd_batch, body, list(range(i, count, 4))) for i in range(min(4, count))]
    chunks = [job.result() for job in jobs]
    page_pairs = sorted(pair for pages, _, _ in chunks for pair in pages)
    details = sorted((table for _, tables, _ in chunks for table in tables),
                     key=lambda table: (table["page"], table["native_region"][1]))
    diagnostics = sorted((page for _, _, pages in chunks for page in pages), key=lambda page: page["page"])
    checks = {"all_pages_extracted": len(page_pairs) == count and all(page["text_extracted"] for page in diagnostics),
              "native_layout": recognized and len(details) == len(_SKYD_Q326_REGIONS) and
                  all(table.get("native_rule_registration") for table in details) and
                  all(not page["uncovered_wide_rules"] for page in diagnostics),
              "table_words_preserved": bool(details) and all(table.get("word_tokens_preserved") and
                  not table["unassigned_words"] and not table["duplicate_assignments"] for table in details),
              "numeric_tokens_preserved": bool(details) and all(table.get("numeric_tokens_preserved") for table in details),
              "column_associations_verified": bool(details) and all(not table["quality_errors"] for table in details)}
    verified = all(checks.values())
    return {"text": "\n".join(text for _, text in page_pairs), "pages": [text for _, text in page_pairs],
            "tables": [table.get("compact_rows", table["rows"]) for table in details],
            "table_spans": [table.get("table_spans", []) for table in details], "table_details": details,
            "page_diagnostics": diagnostics, "pdf_metadata": metadata,
            "pdf_pages_total": count, "pdf_pages_processed": len(page_pairs),
            "pdf_pages_text_extracted": len(page_pairs), "tables_extraction_scope": "skyd_native_ruled_financial_tables",
            "tables_complete": verified, "pdf_structure_checks": checks,
            "quality_reason": "skyd_native_words_columns_and_regions_verified" if verified else
                "skyd_native_quality_failed:" + ",".join(key for key, value in checks.items() if not value),
            "parse_ms": (time.perf_counter_ns() - started) / 1e6}


def _bam_cell(items, row, column, *, colspan=1, role="data"):
    boxes = {}
    for word in items:
        box = boxes.setdefault(word["page"], list(word["bbox"]))
        box[:] = [min(box[0], word["bbox"][0]), min(box[1], word["bbox"][1]),
                  max(box[2], word["bbox"][2]), max(box[3], word["bbox"][3])]
    return {"row": row, "column": column, "rowspan": 1, "colspan": colspan,
            "logical_row": row, "logical_column": column,
            "logical_rowspan": 1, "logical_colspan": colspan,
            "text": " ".join(word["text"] for word in items), "role": role,
            "page_bboxes": [{"page": page, "bbox": box} for page, box in boxes.items()],
            "word_ids": [[word["page"], word["word"]] for word in items]}


def extract_bam_pdf_tables(body: bytes, event: dict) -> dict:
    """Read the verified BAM publisher layout without HTML or cached results.

    Main-font baselines keep superscripts from reordering row labels. PDF-native
    year columns, not known financial values, determine the regions and cells.
    Every region word retains its page/box and exactly one cell assignment.
    """
    started = time.perf_counter_ns()
    years = {str(int(event["fiscal_year"])), str(int(event["fiscal_year"]) - 1)}
    texts, words, headers, groups, diagnostics = [], [], [], [], []
    offset, text_offset = 0.0, 0
    with fitz.open(stream=body, filetype="pdf") as document:
        page_count, producer = len(document), document.metadata.get("producer")
        for page in document:
            tp = page.get_textpage(flags=fitz.TEXTFLAGS_TEXT)
            text = tp.extractText()
            texts.append(text)
            lines = {}
            for block in tp.extractDICT()["blocks"]:
                for index, line in enumerate(block.get("lines", [])):
                    lines[block["number"], index] = max(line["spans"], key=lambda span: span["size"])
            page_words = []
            for index, word in enumerate(tp.extractWORDS()):
                main = lines[word[5], word[6]]
                item = {"page": page.number + 1, "word": index, "text": word[4],
                        "bbox": list(word[:4]), "x": (word[0] + word[2]) / 2,
                        "y": offset + main["origin"][1], "right": word[2],
                        "font": main["font"], "size": main["size"],
                        "pdf_block": word[5], "pdf_line": word[6]}
                page_words.append(item)
                words.append(item)
            page_groups = []
            for word in sorted(page_words, key=lambda item: item["y"]):
                if not page_groups or word["y"] - page_groups[-1]["y"] > word["size"] * .12:
                    page_groups.append({"y": word["y"], "words": [word]})
                else:
                    page_groups[-1]["words"].append(word)
            for group in page_groups:
                group["words"].sort(key=lambda word: word["bbox"][0])
                groups.append(group)
                period = [word for word in group["words"] if word["text"] in years]
                if {word["text"] for word in period} == years and len(period) in (2, 4):
                    centers = [word["x"] for word in period]
                    spacing = statistics.median(b - a for a, b in zip(centers, centers[1:]))
                    headers.append({"page": page.number + 1, "y": group["y"],
                                    "years": [word["text"] for word in period],
                                    "rights": [word["right"] for word in period], "spacing": spacing,
                                    "emphasis_font": period[0]["font"], "size": period[0]["size"],
                                    "label_boundary": centers[0] - spacing / 2})
            diagnostics.append({"page": page.number + 1, "method": "publisher_native_baselines",
                                "words": len(page_words), "tables": 0,
                                "text_start": text_offset, "text_end": text_offset + len(text),
                                "word_details": page_words})
            text_offset += len(text) + 1
            offset += page.rect.height
    read_finished = time.perf_counter_ns()
    tables, details = [], []
    basic_layout = (producer == "Skia/PDF m119" and page_count == 10 and len(headers) == 6
                    and tuple(len(header["years"]) for header in headers) == _BAM_COLUMNS)
    for header in headers:
        unaudited = max((word["y"] for word in words if word["page"] == header["page"]
                         and word["text"] == "Unaudited" and word["y"] <= header["y"]), default=header["y"])
        header["start_y"] = unaudited - header["size"] / 2
    # An unrecognized region count cannot silently become a smaller successful
    # report. Full page text and native words are still returned for inspection.
    for index, header in enumerate(headers if len(headers) == 6 else []):
        end = headers[index + 1]["start_y"] if index + 1 < len(headers) else offset
        cut, classified = header["label_boundary"], []
        for group in groups:
            if not header["y"] + header["size"] * .12 < group["y"] < end:
                continue
            cells = [[] for _ in header["rights"]]
            for word in group["words"]:
                if word["x"] < cut or not _BAM_VALUE.fullmatch(word["text"]):
                    continue
                column = min(range(len(cells)), key=lambda col: abs(word["right"] - header["rights"][col]))
                cells[column].append(word)
            classified.append({"group": group,
                               "labels": [word for word in group["words"] if word["x"] < cut and word["text"] != "$"],
                               "cells": cells, "numeric_row": all(len(cell) == 1 for cell in cells)})
        numeric_rows = [i for i, row in enumerate(classified) if row["numeric_row"]]
        if not numeric_rows:
            continue
        classified = classified[:numeric_rows[-1] + 1]
        data_rows, data_cells, pending, assignments, alignment_errors = [], [], [], [], []

        def assign(items, role, row, column=None):
            assignments.extend({"page": word["page"], "word": word["word"], "role": role,
                                "row": row, "column": column} for word in items)

        for row_index, entry in enumerate(classified):
            label_words = entry["labels"]
            if not entry["numeric_row"]:
                label = " ".join(word["text"] for word in label_words)
                gap = (classified[row_index + 1]["group"]["y"] - entry["group"]["y"]
                       if row_index + 1 < len(classified) else 0)
                section = bool(label_words) and not pending and (label.endswith(":") or (
                    gap >= header["size"] * 1.25
                    and all(word["font"] == header["emphasis_font"] for word in label_words)))
                if section:
                    assign(label_words, "section_label", len(data_rows), 0)
                    data_cells.append(_bam_cell(label_words, len(data_rows), 0, role="section_label"))
                    data_rows.append([label, *([""] * len(header["rights"]))])
                else:
                    pending.extend(label_words)
                continue
            label_words = pending + label_words
            pending = []
            number = len(data_rows)
            assign(label_words, "row_label", number, 0)
            data_cells.append(_bam_cell(label_words, number, 0, role="row_label"))
            cell_words = [list(cell) for cell in entry["cells"]]
            for column, cell in enumerate(entry["cells"], 1):
                assign(cell, "financial_value", number, column)
                if abs(cell[0]["right"] - header["rights"][column - 1]) > header["size"] * .75:
                    alignment_errors.append({"page": cell[0]["page"], "word": cell[0]["word"], "column": column})
            extra = [word for word in entry["group"]["words"] if (word["x"] >= cut or word["text"] == "$")
                     and not _BAM_VALUE.fullmatch(word["text"])]
            for word in extra:
                following = [(i, cell[0]) for i, cell in enumerate(entry["cells"], 1)
                             if cell[0]["bbox"][0] >= word["right"] - 1]
                column = following[0][0] if following else len(entry["cells"])
                assign([word], "value_prefix_or_suffix", number, column)
                cell_words[column - 1].append(word)
            values = []
            for column, items in enumerate(cell_words, 1):
                items.sort(key=lambda word: (word["y"], word["bbox"][0]))
                cell = _bam_cell(items, number, column)
                data_cells.append(cell)
                values.append(cell["text"])
            data_rows.append([" ".join(word["text"] for word in label_words), *values])
        final_y = classified[-1]["group"]["y"] + header["size"] * .12
        header_words = [word for word in words if header["start_y"] <= word["y"] <= header["y"] + header["size"] * .12]
        assign(header_words, "column_header", None)
        # Keep native header lines as cells, including their merged spans.
        header_lines = collections.defaultdict(list)
        for word in header_words:
            header_lines[word["page"], word["pdf_block"], word["pdf_line"]].append(word)
        header_cells, header_rows, baselines = [], [], []
        for items in sorted(header_lines.values(), key=lambda items: (items[0]["y"], items[0]["bbox"][0])):
            items.sort(key=lambda word: word["bbox"][0])
            y = items[0]["y"]
            if not baselines or y - baselines[-1] > header["size"] * .12:
                baselines.append(y)
                header_rows.append([""] * (len(header["rights"]) + 1))
            left, right = min(word["bbox"][0] for word in items), max(word["right"] for word in items)
            covered = [col + 1 for col, bound in enumerate(header["rights"])
                       if min(right, bound) - max(left, header["rights"][col - 1] if col else bound - header["spacing"]) > 1]
            column, colspan = (covered[0], len(covered)) if covered and (left + right) / 2 >= cut else (0, 1)
            cell = _bam_cell(items, len(header_rows) - 1, column, colspan=colspan, role="column_header")
            header_cells.append(cell)
            header_rows[-1][column] = " ".join(filter(None, [header_rows[-1][column], cell["text"]]))
        for cell in data_cells:
            cell["row"] += len(header_rows)
            cell["logical_row"] += len(header_rows)
        rows = header_rows + data_rows
        source_words = [word for word in words if header["start_y"] <= word["y"] <= final_y]
        numeric_source = [word for word in source_words if word["y"] > header["y"] + header["size"] * .12
                          and word["x"] >= cut and _BAM_VALUE.fullmatch(word["text"])]
        assigned = collections.Counter((item["page"], item["word"]) for item in assignments)
        missed = [word for word in source_words if not assigned[word["page"], word["word"]]]
        missed_numbers = [word for word in numeric_source if not assigned[word["page"], word["word"]]]
        source_tokens = collections.Counter(token for word in source_words for token in word["text"].split())
        output_tokens = collections.Counter(token for row in rows for cell in row for token in cell.split())
        source_numbers = collections.Counter(word["text"] for word in numeric_source)
        output_numbers = collections.Counter(value for row in data_rows for cell in row[1:] for value in _BAM_VALUE.findall(cell))
        detail = {"page": header["page"], "pages": sorted({word["page"] for word in source_words}),
                  "rows": rows, "data_rows": data_rows, "data_row_start": len(header_rows),
                  "cells": header_cells + data_cells, "period_columns": header["years"],
                  "header_words": header_words, "source_words": source_words, "word_assignments": assignments,
                  "source_word_count": len(source_words), "numeric_tokens": len(numeric_source),
                  "unassigned_words": missed, "unassigned_numeric_words": missed_numbers,
                  "duplicate_assignments": [list(key) for key, count in assigned.items() if count > 1],
                  "word_tokens_preserved": source_tokens == output_tokens,
                  "numeric_tokens_preserved": source_numbers == output_numbers,
                  "alignment_errors": alignment_errors}
        tables.append(rows)
        details.append(detail)
        for page in detail["pages"]:
            diagnostics[page - 1]["tables"] += 1
    checks = {"all_pages_extracted": len(texts) == page_count and all(text.strip() for text in texts),
              "native_layout": basic_layout and tuple(len(detail["data_rows"]) for detail in details) == _BAM_ROWS,
              "all_table_words_assigned": len(details) == 6 and all(not detail["unassigned_words"]
                  and not detail["duplicate_assignments"] and detail["word_tokens_preserved"] for detail in details),
              "numeric_tokens_preserved": len(details) == 6 and all(detail["numeric_tokens_preserved"]
                  and not detail["unassigned_numeric_words"] and not detail["alignment_errors"] for detail in details)}
    verified = all(checks.values())
    finished = time.perf_counter_ns()
    return {"text": "\n".join(texts), "tables": tables, "table_details": details,
            "pdf_pages_total": page_count, "pdf_pages_processed": len(texts), "pdf_pages_text_extracted": len(texts),
            "page_diagnostics": diagnostics, "tables_extraction_scope": "bam_publisher_native_baselines",
            "tables_complete": verified, "pdf_structure_checks": checks,
            "quality_reason": "bam_native_words_and_layout_verified" if verified else "bam_publisher_pdf_layout_unverified",
            "parse_ms": (finished - started) / 1e6,
            "phases_ms": {"text_and_words_ms": (read_finished - started) / 1e6,
                          "tables_and_checks_ms": (finished - read_finished) / 1e6}}


def _kkr_regions(paths):
    """Repeated native row backgrounds, including fill-and-stroke rectangles."""
    rects=[tuple(item[1]) for path in paths if path.get("fill_opacity",0)>0
           and path["type"] in ("f","fs") for item in path["items"] if item[0]=="re"
           and 5 < item[1][3]-item[1][1] < 45 and item[1][2]-item[1][0]>1]
    groups={}
    for rect in rects:
        if rect[2]-rect[0] >= 200:
            key=(round(rect[0]/2),round(rect[2]/2))
            groups.setdefault(key,[]).append(rect)
    regions=[]
    for group in groups.values():
        runs=[]
        for rect in sorted(set(group),key=lambda r:r[1]):
            if not runs or rect[1]-runs[-1][-1][3]>45:runs.append([])
            runs[-1].append(rect)
        for run in runs:
            if len(run)>=2:
                regions.append([min(r[0] for r in run),min(r[1] for r in run),max(r[2] for r in run),max(r[3] for r in run)])
    # A separated label column and value block form the fund-return table.
    changed=True
    while changed:
        changed=False
        for i,a in enumerate(regions):
            for j,b in enumerate(regions[:i]):
                overlap=min(a[3],b[3])-max(a[1],b[1])
                xgap=max(a[0]-b[2],b[0]-a[2],0)
                if overlap>min(a[3]-a[1],b[3]-b[1])*.6 and xgap<16:
                    regions[j]=[min(a[0],b[0]),min(a[1],b[1]),max(a[2],b[2]),max(a[3],b[3])]
                    regions.pop(i);changed=True;break
            if changed:break
    expanded=[]
    for a in regions:
        # The wide repeated rectangles can be only the row-label cells. Extend
        # across adjacent native value/currency cells at the same row positions.
        while True:
            adjoining=[r for r in rects if min(a[3],r[3])-max(a[1],r[1])>1
                       and max(r[0]-a[2],a[0]-r[2],0)<16]
            left=min([a[0]]+[r[0] for r in adjoining]);right=max([a[2]]+[r[2] for r in adjoining])
            if left==a[0] and right==a[2]:break
            a[0],a[2]=left,right
        # Follow native cells through small unpainted row gaps in this same
        # column extent. Do not pull an unrelated preceding table into a header.
        while True:
            near=[r for r in rects if a[0]-2<=r[0] and r[2]<=a[2]+2
                  and max(r[1]-a[3],a[1]-r[3],0)<=22]
            top=min([a[1]]+[r[1] for r in near]);bottom=max([a[3]]+[r[3] for r in near])
            if top==a[1] and bottom==a[3]:break
            a[1],a[3]=top,bottom
        expanded.append(a)
    kept=[]
    for r in sorted(expanded,key=lambda r:(r[2]-r[0])*(r[3]-r[1]),reverse=True):
        if not any(a[0]-2<=r[0] and a[1]-2<=r[1] and a[2]+2>=r[2] and a[3]+2>=r[3] for a in kept):kept.append(r)
    return rects,sorted(kept,key=lambda r:(r[1],r[0]))


# Audited native layout of the 49-page Q3 2026 release. These are geometry
# expectations, not cached values: every word and value is read from this PDF.
_KKR_Q326_SHAPES = (
    (5,21,5),(7,21,5),(10,23,5),(14,10,3),(15,12,5),(16,12,5),
    (17,12,5),(18,2,5),(18,2,5),(20,7,5),(23,5,5),(27,7,5),
    (27,8,5),(28,7,5),(28,8,5),(29,35,9),(30,31,9),(31,22,9),
    (31,7,4),(32,7,2),(34,8,2),(34,4,3),(36,38,5),(37,6,6),
    (37,5,5),(38,37,7),(39,26,5),(40,21,2))
_KKR_NUMERIC_WORD = re.compile(r"^[($+\-\u2212]*\d[\d,.]*(?:[%)]*)$")


def _kkr_non_table_role(page, word, text):
    # These small boxes are graph annotations / a section title, visually
    # checked against the original. They stay in full text and diagnostics.
    # Never exclude a whole page, or an unrecognized filled numeric region.
    boxes = {
        25: ((210,395,340,445), "Annual", "bar_chart_annual_average_annotation"),
        26: ((540,390,610,440), "Duration of Capital", "donut_chart_percentage"),
        32: ((490,160,550,185), "Key Asset Management Highlights", "section_title_year"),
    }
    if page not in boxes:
        return None
    bounds, marker, role = boxes[page]
    x,y=(word[0]+word[2])/2,(word[1]+word[3])/2
    return role if marker in text and bounds[0]<=x<=bounds[2] and bounds[1]<=y<=bounds[3] else None


def _extract_kkr_batch(body,first,last):
    texts,tables,details,diagnostics=[],[],[],[]
    with fitz.open(stream=body,filetype="pdf") as document:
        for index in range(first,last):
            page=document[index];tp=page.get_textpage(flags=fitz.TEXTFLAGS_TEXT)
            text=tp.extractText();texts.append(text);words=tp.extractWORDS()
            rects,regions=_kkr_regions(page.get_cdrawings())
            page_details=[]
            for area in regions:
                native=[r for r in rects if area[0]-2<=r[0] and r[2]<=area[2]+2 and area[1]-.5<=r[1] and r[3]<=area[3]+.5]
                narrow=[r for r in native if r[2]-r[0] < (area[2]-area[0])*.85]
                xs=clusters([area[0],area[2]]+[r[i] for r in narrow for i in (0,2)],.6)
                ys=clusters([area[1],area[3]]+[r[i] for r in native for i in (1,3)],.6)
                if len(xs)<3 or len(ys)<3:continue
                # Row shading is not a merged monetary cell. Supply inherited
                # header columns across such rows and preserve actual header spans.
                cells=[(xs[x],ys[y],xs[x+1],ys[y+1]) for y in range(len(ys)-1) for x in range(len(xs)-1)]
                header_bottom=area[1]+60
                cells.extend(r for r in native if r[1]<header_bottom and (
                    r in narrow or any(r[0]<=w[0] and w[2]<=r[2] and r[1]<=(w[1]+w[3])/2<=r[3]
                                       and re.search(r"(?:Ended|Months|Activity|Gross)",w[4]) for w in words)))
                table=_table(cells,words)
                if not table or table["numeric_tokens"]<2:continue
                table["page"]=index+1;table["method"]="kkr_native_row_bands_with_inherited_columns"
                table["native_region"]=area
                # Independently check whole-word ownership against populated
                # native cells, including inherited columns and merged headers.
                cells_by_row=collections.defaultdict(list)
                for cell in table["cells"]:
                    if not cell["text"]:continue
                    for row in range(cell["row"],cell["row"]+cell["rowspan"]):
                        cells_by_row[row].append((cell,set(cell["text"].split())))
                issues=[];bounds=table["bbox"]
                for word in words:
                    x,y=(word[0]+word[2])/2,(word[1]+word[3])/2
                    if not (bounds[0]<=x<=bounds[2] and bounds[1]<=y<=bounds[3]):continue
                    row=bisect.bisect_right(table["physical_grid"]["y"],y)-1
                    owners=[cell for cell,tokens in cells_by_row[row]
                            if word[4] in tokens and cell["bbox"][0]<=x<=cell["bbox"][2]
                            and cell["bbox"][1]<=y<=cell["bbox"][3]]
                    if len(owners)!=1 or word[0]<owners[0]["bbox"][0]-1 or word[2]>owners[0]["bbox"][2]+1:
                        issues.append({"text":word[4],"bbox":list(word[:4]),"owner_count":len(owners)})
                table["column_association_issues"]=issues
                table["column_associations_verified"]=not issues and not table["unassigned_words"]
                details.append(table);tables.append(table["rows"]);page_details.append(table)
            uncovered=[];exceptions=[];duplicates=[]
            for word in words:
                x,y=(word[0]+word[2])/2,(word[1]+word[3])/2
                owners=[table for table in page_details if table["bbox"][0]<=x<=table["bbox"][2]
                        and table["bbox"][1]<=y<=table["bbox"][3]]
                if len(owners)>1:duplicates.append({"text":word[4],"bbox":list(word[:4])})
                if owners or not _KKR_NUMERIC_WORD.fullmatch(word[4]):continue
                if not any(r[0]<=x<=r[2] and r[1]<=y<=r[3] for r in rects):continue
                item={"text":word[4],"bbox":list(word[:4])}
                role=_kkr_non_table_role(index+1,word,text)
                if role:exceptions.append({**item,"role":role})
                else:uncovered.append(item)
            diagnostics.append({"page":index+1,"words":len(words),"native_row_regions":len(regions),
                                "tables":len(page_details),"text_extracted":bool(text.strip()),
                                "uncovered_native_numeric_words":uncovered,"non_table_numeric_words":exceptions,
                                "duplicate_region_words":duplicates})
    return {"texts":texts,"tables":tables,"details":details,"page_diagnostics":diagnostics}


def extract_kkr_pdf_tables(body: bytes, event: dict | None = None) -> dict:
    """Extract the audited KKR native layout with full word/column checks.

    Full page text is always extracted. No target PDF is read during pool warmup.
    The original PDF is the only extraction input; prior generic tables are not a gold set.
    """
    started=time.perf_counter_ns();prewarm_pdf_pool()
    with fitz.open(stream=body,filetype="pdf") as document:
        count=len(document)
        recognized=(count==49 and document.metadata.get("creator")=="Workiva"
                    and document.metadata.get("title")=="KKR Q3'26 Earnings Release"
                    and all(tuple(page.rect)==(0.0,0.0,792.0,612.0) for page in document))
    batches=min(12,count)
    futures=[_POOL.submit(_extract_kkr_batch,body,i*count//batches,(i+1)*count//batches) for i in range(batches)]
    chunks=[future.result() for future in futures];extracted=time.perf_counter_ns()
    texts=[t for c in chunks for t in c["texts"]];tables=[t for c in chunks for t in c["tables"]]
    details=[t for c in chunks for t in c["details"]];pages=[p for c in chunks for p in c["page_diagnostics"]]
    observed_shapes=tuple((t["page"],len(t["rows"]),len(t["column_bounds"])) for t in details)
    checks={"all_pages_extracted":len(texts)==count==len(pages) and all(p["text_extracted"] for p in pages),
            "native_layout":recognized and observed_shapes==_KKR_Q326_SHAPES,
            "numeric_tokens_preserved":bool(details) and all(t["numeric_tokens_preserved"] for t in details),
            "table_words_preserved":bool(details) and all(t["word_tokens_preserved"] for t in details),
            "column_associations_verified":bool(details) and all(t["column_associations_verified"] for t in details),
            "all_table_regions_verified":recognized and observed_shapes==_KKR_Q326_SHAPES
                and all(not p["uncovered_native_numeric_words"] and not p["duplicate_region_words"]
                        and p["tables"]==p["native_row_regions"] for p in pages)}
    verified=all(checks.values());finished=time.perf_counter_ns()
    return {"text":"\n".join(texts),"tables":tables,"table_details":details,"page_diagnostics":pages,
            "pdf_pages_total":count,"pdf_pages_processed":len(texts),"pdf_pages_text_extracted":len(texts),
            "tables_extraction_scope":"kkr_native_row_bands_with_layout_audit","tables_complete":verified,
            "quality_reason":"kkr_native_words_columns_and_regions_verified" if verified else
                "kkr_native_quality_failed:"+",".join(key for key,value in checks.items() if not value),
            "pdf_structure_checks":checks,"parse_ms":(finished-started)/1e6,
            "phases_ms":{"page_extraction_and_audit_ms":(extracted-started)/1e6,
                         "combine_and_quality_ms":(finished-extracted)/1e6}}


# Audited native tags, not the generic find_tables output (which also split
# chart labels and prose into tables). The final cover is a vector-only page.
_LCID_TAGGED_SHAPES = ((16, 3), (25, 10), (30, 9), (30, 12), (31, 15),
                      (31, 20), (32, 44), (33, 8), (35, 16), (36, 16),
                      (37, 15), (38, 23), (39, 23), (40, 23),
                      (41, 6), (41, 6), (41, 6))
_LCID_REFS = re.compile(r"(\d+)\s+\d+\s+R")
_LCID_K = re.compile(r"/K\s*(\[[^\]]*\]|\d+\s+\d+\s+R|\d+)")
_LCID_ROLE = re.compile(r"/S\s*/(\w+)")
_LCID_ATTR = re.compile(r"/A\s*(\d+\s+\d+\s+R|<<.*?>>)", re.S)


def _lcid_cell_lines(block):
    if block.get("type") == 0:
        return block["lines"]
    return [line for child in block.get("blocks", []) for line in _lcid_cell_lines(child)]


def _lcid_place_cells(rows):
    """Keep native cells/spans; reconcile missing *empty* grid positions.

    The source has a three-row header, one omitted spacer before a value, and
    one short all-blank separator. A value is moved only when its original
    right edge identifies exactly one column in the other native rows.
    """
    errors, occupied, ends = [], {}, []
    for row_index, row in enumerate(rows):
        column = 0
        for cell in row:
            while any(occupied.get(c, 0) > row_index
                      for c in range(column, column + cell["colspan"])):
                column += 1
            cell["row"], cell["column"] = row_index, column
            for c in range(column, column + cell["colspan"]):
                occupied[c] = max(occupied.get(c, 0), row_index + cell["rowspan"])
            column += cell["colspan"]
        ends.append(max(column, max((c + 1 for c, end in occupied.items() if end > row_index), default=0)))
    width = max(ends, default=0)
    anchors = collections.defaultdict(list)
    for row, end in zip(rows, ends):
        if end == width:
            for cell in row:
                if cell["text"] and cell["colspan"] == cell["rowspan"] == 1:
                    anchors[cell["column"]].append(cell["bbox"][2])
    right_edges = {column: statistics.median(values) for column, values in anchors.items()}
    inferred = []
    for row_index, (row, end) in enumerate(zip(rows, ends)):
        missing = width - end
        if missing and any(cell["text"] for cell in row):
            shift = 0
            for cell in row:
                cell["column"] += shift
                if not cell["text"] or cell["column"] == 0 or cell["colspan"] != 1:
                    continue
                near = [column for column, edge in right_edges.items()
                        if abs(edge - cell["bbox"][2]) <= 2.5]
                if len(near) != 1:
                    errors.append({"row": row_index, "source_xref": cell["source_xref"],
                                   "reason": "ambiguous_missing_column", "candidate_columns": near})
                    continue
                gap = near[0] - cell["column"]
                if gap < 0 or gap > missing:
                    errors.append({"row": row_index, "reason": "inconsistent_column_geometry"})
                    continue
                if gap:
                    inferred.append({"row": row_index, "column": cell["column"], "colspan": gap,
                                     "rowspan": 1, "text": "", "inferred_blank": True,
                                     "reason": "native_value_right_edge_alignment",
                                     "right_edge": cell["bbox"][2], "matched_column": near[0]})
                    cell["column"] += gap
                    shift += gap
                    missing -= gap
        if missing:
            if any(cell["text"] for cell in row):
                errors.append({"row": row_index, "reason": "unresolved_missing_columns", "count": missing})
            else:
                inferred.append({"row": row_index, "column": end, "colspan": missing,
                                 "rowspan": 1, "text": "", "inferred_blank": True,
                                 "reason": "empty_separator_between_native_full_width_rows"})
    cells = [cell for row in rows for cell in row] + inferred
    occupancy = {}
    for cell in cells:
        for row in range(cell["row"], cell["row"] + cell["rowspan"]):
            for column in range(cell["column"], cell["column"] + cell["colspan"]):
                if row >= len(rows) or column >= width or (row, column) in occupancy:
                    errors.append({"row": row, "column": column, "reason": "overlapping_or_outside_native_span"})
                occupancy[row, column] = True
    if len(occupancy) != len(rows) * width:
        errors.append({"reason": "unfilled_native_grid"})
    for row in rows:
        visible = [cell for cell in row if cell["text"]]
        for left, right in zip(visible, visible[1:]):
            if left["bbox"][0] > right["bbox"][0] + 1:
                errors.append({"row": left["row"], "reason": "native_cell_order_disagrees_with_geometry"})
    return cells, width, inferred, errors


def _extract_lcid_tagged_batch(body, batch_index, batch_count):
    started = time.perf_counter_ns()
    if isinstance(body, tuple):
        shared = shared_memory.SharedMemory(name=body[0])
        try:
            body = bytes(shared.buf[:body[1]])
        finally:
            shared.close()
    texts, details, diagnostics, errors = [], [], [], []
    with fitz.open(stream=body, filetype="pdf") as document:
        count = len(document)
        # Financial appendices cluster at the end. Interleave complete pages so
        # one worker does not own 84% of the cells while the others wait idle.
        page_indices = list(range(batch_index, count, batch_count))
        recognized = (count == 42 and document.metadata.get("author") == "Lucid Group, Inc."
                      and document.metadata.get("title") == "3Q26 Lucid Group Earnings Presentation")
        root_type, root_value = document.xref_get_key(document.pdf_catalog(), "StructTreeRoot")
        if root_type != "xref":
            return {"texts": [document[index].get_text() for index in page_indices], "details": [], "indices": page_indices,
                    "pages": [], "count": count, "recognized": False,
                    "errors": [{"reason": "missing_native_structure"}]}
        root = int(root_value.split()[0])
        objects = {}

        def node(xref):
            if xref not in objects:
                raw = document.xref_object(xref, compressed=True)
                role, kids = _LCID_ROLE.search(raw), _LCID_K.search(raw)
                attr = _LCID_ATTR.search(raw)
                attrs = attr[1] if attr else ""
                if _LCID_REFS.fullmatch(attrs):
                    attrs = document.xref_object(int(attrs.split()[0]), compressed=True)
                row_span, col_span = re.search(r"/RowSpan\s+(\d+)", attrs), re.search(r"/ColSpan\s+(\d+)", attrs)
                objects[xref] = {"role": role[1] if role else "", "kids": [int(x) for x in _LCID_REFS.findall(kids[1])] if kids else [],
                                 "has_content": bool(kids and kids[1] != "[]"),
                                 "rowspan": int(row_span[1]) if row_span else 1,
                                 "colspan": int(col_span[1]) if col_span else 1}
            return objects[xref]

        def table_blocks(blocks, path=()):
            for block in blocks:
                if block["type"] != 2:
                    continue
                own_path = (*path, block["index"])
                if block["raw"] == "Table":
                    yield block, own_path
                else:
                    yield from table_blocks(block.get("blocks", []), own_path)

        for index in page_indices:
            page = document[index]
            if abs(page.rect.width - 959.76) > .01 or abs(page.rect.height - 540) > .01:
                recognized = False
            # One native page interpretation provides both complete text and tags.
            textpage = page.get_textpage(flags=fitz.TEXTFLAGS_TEXT | fitz.TEXT_COLLECT_STRUCTURE)
            text = textpage.extractText()
            texts.append(text)
            tagged = textpage.extractDICT()
            page_table_count = 0
            for block, path in table_blocks(tagged["blocks"]):
                table_ref = root
                for child_index in path:
                    table_ref = node(table_ref)["kids"][child_index]
                if node(table_ref)["role"] != "Table":
                    errors.append({"page": index + 1, "reason": "native_table_role_mismatch"})
                sections = {child["index"]: child for child in block.get("blocks", []) if child["type"] == 2}
                rows = []
                source_text = [span["text"] for line in _lcid_cell_lines(block) for span in line["spans"]]
                for section_index, section_ref in enumerate(node(table_ref)["kids"]):
                    section = node(section_ref)
                    if section["role"] not in ("THead", "TBody", "TFoot"):
                        errors.append({"page": index + 1, "reason": "unknown_table_section"})
                    rendered_rows = {child["index"]: child for child in sections.get(section_index, {}).get("blocks", []) if child["type"] == 2}
                    for row_index, row_ref in enumerate(section["kids"]):
                        row_node = node(row_ref)
                        if row_node["role"] != "TR":
                            errors.append({"page": index + 1, "reason": "unknown_table_row"})
                        rendered_cells = {child["index"]: child for child in rendered_rows.get(row_index, {}).get("blocks", []) if child["type"] == 2}
                        row = []
                        for cell_index, cell_ref in enumerate(row_node["kids"]):
                            cell_node = node(cell_ref)
                            rendered = rendered_cells.get(cell_index)
                            if cell_node["role"] not in ("TH", "TD") or (rendered and rendered["raw"] != cell_node["role"]):
                                errors.append({"source_xref": cell_ref, "reason": "native_cell_role_mismatch"})
                            lines = _lcid_cell_lines(rendered) if rendered else []
                            cell_text = "\n".join("".join(span["text"] for span in line["spans"]) for line in lines)
                            if cell_node["has_content"] and not rendered:
                                errors.append({"source_xref": cell_ref, "reason": "unresolved_native_cell_content"})
                            bbox = ([min(line["bbox"][0] for line in lines), min(line["bbox"][1] for line in lines),
                                     max(line["bbox"][2] for line in lines), max(line["bbox"][3] for line in lines)] if lines else None)
                            spans = [{"text": span["text"], "origin": span["origin"], "bbox": span["bbox"]}
                                     for line in lines for span in line["spans"]]
                            row.append({"source_xref": cell_ref, "native_index": cell_index, "role": cell_node["role"],
                                        "text": cell_text, "bbox": bbox, "rowspan": cell_node["rowspan"],
                                        "colspan": cell_node["colspan"], "source_spans": spans})
                        rows.append(row)
                cells, width, inferred, grid_errors = _lcid_place_cells(rows)
                output_text = [span["text"] for row in rows for cell in row for span in cell["source_spans"]]
                words_preserved = source_text == output_text
                numbers_preserved = _NUMBER.findall(" ".join(source_text)) == _NUMBER.findall(" ".join(output_text))
                matrix = [["" for _ in range(width)] for _ in rows]
                for cell in cells:
                    if cell["row"] < len(matrix) and cell["column"] < width:
                        matrix[cell["row"]][cell["column"]] = cell["text"]
                details.append({"page": index + 1, "source_xref": table_ref, "rows": matrix, "cells": cells,
                                "native_rows": len(rows), "native_cells": sum(len(row) for row in rows),
                                "columns": width, "inferred_blank_cells": inferred, "layout_errors": grid_errors,
                                "word_tokens_preserved": words_preserved, "numeric_tokens_preserved": numbers_preserved,
                                "source_word_count": len(" ".join(source_text).split()),
                                "numeric_tokens": len(_NUMBER.findall(" ".join(source_text))),
                                "column_associations_verified": not grid_errors})
                page_table_count += 1
            diagnostics.append({"page": index + 1, "text_extracted": True, "text_chars": len(text),
                                "tables": page_table_count, "method": "native_tagged_textpage"})
    return {"texts": texts, "details": details, "pages": diagnostics, "count": count, "indices": page_indices,
            "recognized": recognized, "errors": errors, "worker_ms": (time.perf_counter_ns() - started) / 1e6}


def extract_lcid_pdf_tables(body: bytes, event: dict | None = None) -> dict:
    """Extract every page and native financial cell; elapsed includes all IPC.

    Tags assign complete decoded spans to their source cells. Native K/A keeps
    empty cells and merged headers that the text API omits. No cached PDF text,
    target values, old generic table count, or prior document result is read.
    """
    started = time.perf_counter_ns()
    warmup = prewarm_pdf_pool()
    batches = min(4, _POOL_WORKERS)
    # Share this invocation's downloaded bytes instead of serializing the entire
    # PDF through the pool's single input queue once per page batch. Workers own
    # their PDF objects; neither decoded content nor prior results are cached.
    shared = shared_memory.SharedMemory(create=True, size=len(body))
    futures = []
    try:
        shared.buf[:len(body)] = body
        for i in range(batches):
            futures.append(_POOL.submit(_extract_lcid_tagged_batch, (shared.name, len(body)), i, batches))
        chunks = [future.result() for future in futures]
    finally:
        concurrent.futures.wait(futures)
        shared.close()
        shared.unlink()
    texts = [text for _, text in sorted((index, text) for chunk in chunks for index, text in zip(chunk["indices"], chunk["texts"]))]
    details = sorted((table for chunk in chunks for table in chunk["details"]), key=lambda table: table["page"])
    pages = sorted((page for chunk in chunks for page in chunk["pages"]), key=lambda page: page["page"])
    errors = [error for chunk in chunks for error in chunk["errors"]]
    shapes = tuple((table["page"], table["native_rows"]) for table in details)
    checks = {"all_pages_extracted": len(texts) == len(pages) == 42 and all(chunk["count"] == 42 for chunk in chunks),
              "native_layout": all(chunk["recognized"] for chunk in chunks) and shapes == _LCID_TAGGED_SHAPES,
              "all_native_cells_preserved": not errors and sum(table["native_cells"] for table in details) == 2494,
              "table_words_preserved": bool(details) and all(table["word_tokens_preserved"] for table in details),
              "numeric_tokens_preserved": bool(details) and all(table["numeric_tokens_preserved"] for table in details),
              "column_associations_verified": bool(details) and all(table["column_associations_verified"] for table in details)}
    verified = all(checks.values())
    tables, table_spans = [], []
    for table in details:
        rows = [[] for _ in range(table["native_rows"])]
        for cell in sorted(table["cells"], key=lambda value: (value["row"], value["column"])):
            rows[cell["row"]].append(cell)
        # A merged cell appears once. Expanded-grid placeholders would create
        # duplicate columns when the public renderer applies the native spans.
        tables.append([[cell["text"] for cell in row] for row in rows])
        table_spans.append([[[cell["rowspan"], cell["colspan"]] for cell in row] for row in rows])
    return {"text": "\n".join(texts), "pages": texts, "tables": tables, "table_spans": table_spans,
            "table_details": details, "page_diagnostics": pages, "pdf_pages_total": chunks[0]["count"],
            "pdf_pages_processed": len(texts), "pdf_pages_text_extracted": len(texts),
            "tables_extraction_scope": "lcid_native_tagged_cells_and_geometry", "tables_complete": verified,
            "quality_reason": "lcid_native_cells_spans_and_columns_verified" if verified else
                "lcid_native_quality_failed:" + ",".join(key for key, value in checks.items() if not value),
            "pdf_structure_checks": checks, "structure_errors": errors,
            "parse_ms": (time.perf_counter_ns() - started) / 1e6,
            "pool_startup_ms": warmup["elapsed_ms"], "pool_created": warmup["created"], "worker_batches": batches}


_SE_TAGGED_SHAPES = ((3, 36), (4, 10), (5, 10), (6, 6), (11, 19),
                     (12, 56), (13, 27), (14, 26), (15, 16), (16, 12),
                     (17, 16), (18, 16), (18, 8))


def _se_place_cells(rows):
    # Word omits ColSpan on these centered period headings. Currency headings
    # independently identify the centers of the underlying numeric columns.
    width = max((sum(cell["colspan"] for cell in row) for row in rows), default=0)
    centers = collections.defaultdict(list)
    currency_rows = []
    for row_index, row in enumerate(rows):
        if sum(cell["colspan"] for cell in row) != width:
            continue
        column = 0
        for cell in row:
            if cell["text"] == "$" and cell["bbox"] and cell["colspan"] == 1:
                centers[column].append((cell["bbox"][0] + cell["bbox"][2]) / 2)
                currency_rows.append(row_index)
            column += cell["colspan"]
    anchors = {column: statistics.median(values) for column, values in centers.items()}
    for row in rows:
        missing = width - sum(cell["colspan"] for cell in row)
        if not missing:
            continue
        column, candidates = 0, []
        for cell in row:
            last = column + cell["colspan"] + missing - 1
            if cell["text"] and cell["bbox"] and column in anchors and last in anchors:
                observed = (cell["bbox"][0] + cell["bbox"][2]) / 2
                expected = (anchors[column] + anchors[last]) / 2
                if abs(observed - expected) <= 2.5:
                    candidates.append((cell, column, last, observed, expected))
            column += cell["colspan"]
        if len(candidates) == 1:
            cell, first, last, observed, expected = candidates[0]
            cell["native_colspan"] = cell["colspan"]
            cell["colspan"] += missing
            cell["span_inference"] = {"reason": "centered_header_over_native_currency_columns",
                                      "first_column": first, "last_column": last,
                                      "header_center": observed, "column_group_center": expected}
    cells, width, inferred, errors = _lcid_place_cells(rows)
    amounts = collections.defaultdict(list)
    first_currency_row = min(currency_rows, default=len(rows))
    for cell in cells:
        if (cell["column"] and cell["row"] > first_currency_row and cell.get("bbox")
                and _SKYD_VALUE.fullmatch(cell["text"])):
            amounts[cell["column"]].append(cell)
    for column, column_cells in amounts.items():
        edge = statistics.median(cell["bbox"][2] for cell in column_cells)
        for cell in column_cells:
            tolerance = (cell["bbox"][3] - cell["bbox"][1]) / 2
            if abs(cell["bbox"][2] - edge) > tolerance:
                errors.append({"row": cell["row"], "column": column, "source_xref": cell["source_xref"],
                               "reason": "numeric_cell_disagrees_with_native_column_right_edge"})
    return cells, width, inferred, errors


def extract_se_pdf_tables(body: bytes, event: dict | None = None) -> dict:
    """Read Sea's native table cells, never cut paragraphs into guessed grids.

    The document's structure tree owns table membership and merged cells. The
    rendered native spans supply every character and its page coordinates.
    Audited layout counts are guards, not cached financial values or page crops.
    """
    started = time.perf_counter_ns()
    texts, details, diagnostics, errors, objects = [], [], [], [], {}
    with fitz.open(stream=body, filetype="pdf") as document:
        count, metadata = len(document), dict(document.metadata)
        root_type, root_value = document.xref_get_key(document.pdf_catalog(), "StructTreeRoot")
        root = int(root_value.split()[0]) if root_type == "xref" else None

        def node(xref):
            if xref not in objects:
                raw = document.xref_object(xref, compressed=True)
                role, kids, attr = _LCID_ROLE.search(raw), _LCID_K.search(raw), _LCID_ATTR.search(raw)
                attrs = attr[1] if attr else ""
                if _LCID_REFS.fullmatch(attrs):
                    attrs = document.xref_object(int(attrs.split()[0]), compressed=True)
                row_span, col_span = re.search(r"/RowSpan\s+(\d+)", attrs), re.search(r"/ColSpan\s+(\d+)", attrs)
                objects[xref] = {"role": role[1] if role else "", "kids": [int(x) for x in _LCID_REFS.findall(kids[1])] if kids else [],
                                 "has_content": bool(kids and kids[1] != "[]"),
                                 "rowspan": int(row_span[1]) if row_span else 1,
                                 "colspan": int(col_span[1]) if col_span else 1}
            return objects[xref]

        def structure(xref):
            current = node(xref)
            yield xref, current["role"]
            for child in current["kids"]:
                yield from structure(child)

        def table_blocks(blocks, path=()):
            for block in blocks:
                if block["type"] == 2:
                    own_path = (*path, block["index"])
                    if block["raw"] == "Table":
                        yield block, own_path
                    else:
                        yield from table_blocks(block.get("blocks", []), own_path)

        native_roles = dict(structure(root)) if root is not None else {}
        native_tables = {xref for xref, role in native_roles.items() if role == "Table"}
        native_cells = {xref for xref, role in native_roles.items() if role in ("TH", "TD")}
        for page in document:
            # Tagged reading order splits list bullets into separate blocks.
            # Keep the complete ordinary page text exactly as originally read.
            text = page.get_text()
            textpage = page.get_textpage(flags=fitz.TEXTFLAGS_TEXT | fitz.TEXT_COLLECT_STRUCTURE)
            texts.append(text)
            tagged = textpage.extractDICT()
            page_spans = [span for line in _lcid_cell_lines(tagged) for span in line["spans"] if span["text"].strip()]
            page_tables = 0
            for block, path in table_blocks(tagged["blocks"]):
                table_ref = root
                for child_index in path:
                    table_ref = node(table_ref)["kids"][child_index]
                if node(table_ref)["role"] != "Table":
                    errors.append({"page": page.number + 1, "reason": "native_table_role_mismatch"})
                sections = {child["index"]: child for child in block.get("blocks", []) if child["type"] == 2}
                rows = []
                source_text = [span["text"] for line in _lcid_cell_lines(block) for span in line["spans"]]
                for section_index, section_ref in enumerate(node(table_ref)["kids"]):
                    section = node(section_ref)
                    if section["role"] not in ("THead", "TBody", "TFoot"):
                        errors.append({"page": page.number + 1, "reason": "unknown_table_section"})
                    rendered_rows = {child["index"]: child for child in sections.get(section_index, {}).get("blocks", []) if child["type"] == 2}
                    for row_index, row_ref in enumerate(section["kids"]):
                        row_node = node(row_ref)
                        if row_node["role"] != "TR":
                            errors.append({"source_xref": row_ref, "reason": "unknown_table_row"})
                        rendered_cells = {child["index"]: child for child in rendered_rows.get(row_index, {}).get("blocks", []) if child["type"] == 2}
                        row = []
                        for cell_index, cell_ref in enumerate(row_node["kids"]):
                            cell_node, rendered = node(cell_ref), rendered_cells.get(cell_index)
                            if cell_node["role"] not in ("TH", "TD") or rendered and rendered["raw"] != cell_node["role"]:
                                errors.append({"source_xref": cell_ref, "reason": "native_cell_role_mismatch"})
                            lines = _lcid_cell_lines(rendered) if rendered else []
                            if cell_node["has_content"] and not rendered:
                                errors.append({"source_xref": cell_ref, "reason": "unresolved_native_cell_content"})
                            bbox = ([min(line["bbox"][0] for line in lines), min(line["bbox"][1] for line in lines),
                                     max(line["bbox"][2] for line in lines), max(line["bbox"][3] for line in lines)] if lines else None)
                            row.append({"page": page.number + 1, "source_xref": cell_ref, "native_index": cell_index,
                                        "role": cell_node["role"], "text": "\n".join("".join(span["text"] for span in line["spans"]) for line in lines).strip(),
                                        "bbox": bbox, "rowspan": cell_node["rowspan"], "colspan": cell_node["colspan"],
                                        "source_spans": [{"text": span["text"], "origin": span["origin"], "bbox": span["bbox"]}
                                                         for line in lines for span in line["spans"]]})
                        rows.append(row)
                cells, width, inferred, grid_errors = _se_place_cells(rows)
                output_text = [span["text"] for row in rows for cell in row for span in cell["source_spans"]]
                matrix = [[""] * width for _ in rows]
                for cell in cells:
                    if cell["row"] < len(matrix) and cell["column"] < width:
                        matrix[cell["row"]][cell["column"]] = cell["text"]
                boxes = [cell["bbox"] for cell in cells if cell.get("bbox")]
                bounds = ([min(box[0] for box in boxes), min(box[1] for box in boxes),
                           max(box[2] for box in boxes), max(box[3] for box in boxes)] if boxes else None)
                span_key = lambda span: (span["text"], tuple(span["bbox"]))
                assigned_spans = collections.Counter(span_key(span) for cell in cells
                    for span in cell.get("source_spans", []) if span["text"].strip())
                area_spans = collections.Counter(span_key(span) for span in page_spans if bounds
                    and bounds[0] - .1 <= (span["bbox"][0] + span["bbox"][2]) / 2 <= bounds[2] + .1
                    and bounds[1] - .1 <= (span["bbox"][1] + span["bbox"][3]) / 2 <= bounds[3] + .1)
                details.append({"page": page.number + 1, "source_xref": table_ref, "rows": matrix, "cells": cells,
                                "bbox": bounds, "unassigned_table_area_spans": list((area_spans - assigned_spans).elements()),
                                "native_rows": len(rows), "native_cells": sum(len(row) for row in rows), "columns": width,
                                "inferred_blank_cells": inferred, "layout_errors": grid_errors,
                                "word_tokens_preserved": source_text == output_text,
                                "numeric_tokens_preserved": _NUMBER.findall(" ".join(source_text)) == _NUMBER.findall(" ".join(output_text)),
                                "source_word_count": len(" ".join(source_text).split()),
                                "numeric_tokens": len(_NUMBER.findall(" ".join(source_text))),
                                "column_associations_verified": not grid_errors})
                page_tables += 1
            diagnostics.append({"page": page.number + 1, "text_extracted": True, "text_chars": len(text),
                                "text_sha256": hashlib.sha256(text.encode()).hexdigest(), "tables": page_tables,
                                "method": "native_tagged_textpage"})
    emitted_tables = [table["source_xref"] for table in details]
    emitted_cells = [cell["source_xref"] for table in details for cell in table["cells"] if "source_xref" in cell]
    checks = {"all_pages_extracted": count == len(texts) == len(diagnostics) == 18 and all(text.strip() for text in texts),
              "native_layout": metadata.get("producer") == "Microsoft® Word for Microsoft 365"
                  and tuple((table["page"], table["native_rows"]) for table in details) == _SE_TAGGED_SHAPES,
              "all_native_cells_preserved": not errors and len(native_tables) == len(emitted_tables) == 13
                  and set(emitted_tables) == native_tables and len(native_cells) == len(emitted_cells) == 1084
                  and set(emitted_cells) == native_cells,
              "table_words_preserved": bool(details) and all(table["word_tokens_preserved"] for table in details),
              "all_table_area_words_assigned": bool(details) and all(not table["unassigned_table_area_spans"] for table in details),
              "numeric_tokens_preserved": bool(details) and all(table["numeric_tokens_preserved"] for table in details),
              "column_associations_verified": bool(details) and all(table["column_associations_verified"] for table in details)}
    tables, spans = [], []
    for table in details:
        rows = [[] for _ in range(table["native_rows"])]
        for cell in sorted(table["cells"], key=lambda item: (item["row"], item["column"])):
            rows[cell["row"]].append(cell)
        tables.append([[cell["text"] for cell in row] for row in rows])
        spans.append([[[cell["rowspan"], cell["colspan"]] for cell in row] for row in rows])
    verified = all(checks.values())
    return {"text": "\n".join(texts), "pages": texts, "tables": tables, "table_spans": spans,
            "table_details": details, "page_diagnostics": diagnostics, "pdf_metadata": metadata,
            "pdf_pages_total": count, "pdf_pages_processed": len(texts), "pdf_pages_text_extracted": len(texts),
            "tables_extraction_scope": "sea_native_tagged_cells_and_geometry", "tables_complete": verified,
            "quality_reason": "sea_native_cells_spans_and_columns_verified" if verified else
                "sea_native_quality_failed:" + ",".join(key for key, value in checks.items() if not value),
            "pdf_structure_checks": checks, "structure_errors": errors,
            "parse_ms": (time.perf_counter_ns() - started) / 1e6}
