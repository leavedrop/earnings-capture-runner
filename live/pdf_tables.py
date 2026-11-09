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
import multiprocessing
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
        return [p["rect"] for p in page.get_cdrawings()
                if p["type"] == "f" and p.get("fill_opacity", 0) > 0
                and p["rect"][2]-p["rect"][0] > 1 and p["rect"][3]-p["rect"][1] > 1
                and (p["rect"][2]-p["rect"][0])*(p["rect"][3]-p["rect"][1]) < limit], "drawings"
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
            "native_layout":all(p["method"]=="native_stream" for p in page_diagnostics),
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
