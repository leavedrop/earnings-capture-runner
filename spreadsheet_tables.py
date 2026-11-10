"""Complete native XLSX cell extraction, with the original ZIP as the authority.

Numeric and formula-cache values stay as their original XML strings.  This
module does not calculate formulas or claim issuer/report-period acceptance.
"""
from __future__ import annotations

import hashlib
from datetime import date, timedelta
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP, localcontext
from io import BytesIO
import posixpath
import re
import time
from zipfile import ZipFile

from lxml import etree


_M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_CELL = re.compile(r"([A-Z]+)([1-9][0-9]*)\Z")
# The publisher's actual ten formats. Match the code, never a workbook-local
# numFmtId. Unrecognized formats keep the raw value and are visibly marked.
_NUMBER_FORMATS = {
    r'"$"* #,##0,,_);"$"* \(#,##0,,\);"$"* #,##0,,_);_(@_)',
    r'#0;"-"#0;#0;_(@_)',
    r'"$"* #,##0.00_);"$"* \(#,##0.00\);"$"* "—"_);_(@_)',
    r'#0.#######################;"-"#0.#######################;#0.#######################;_(@_)',
    r'""* #,##0.0,,_);""* \(#,##0.0,,\);""* #,##0.0,,_);_(@_)',
    r'""* #,##0,,_);""* \(#,##0,,\);""* "—"??_);_(@_)',
    r'_("$"* #,###.00_);_("$"* \(#,###.00\);_("$"* "-"??_);_(@_)',
    r'_(* #,###.00_);_(* \(#,###.00\);_(* "-"??_);_(@_)',
    r'"$"* #,##0,,_);"$"* \(#,##0,,\);"$"* "—"??_);_(@_)',
}
_FORMAT_TOKENS = re.compile(r'"[^"]*"|\\.|_.|\*.|[#,0]+(?:\.[#0]+)?,*|\?+|[()]|[ \t]+')


def _formatted_number(raw_value, code, date1904):
    """Apply only the formats actually present in this publisher workbook.

    Accounting fill/underscore widths become ordinary spacing; numeric scale,
    decimals, currency, signs and zero literals retain their Excel meaning.
    https://support.microsoft.com/en-us/excel/review-guidelines-for-customizing-a-number-format
    """
    if code == "General":
        return raw_value, True
    if code != "m/d/yy" and code not in _NUMBER_FORMATS:
        return raw_value + " [原值；数字格式未支持]", False
    value = Decimal(raw_value)
    if code == "m/d/yy":
        serial = int(value.to_integral_value(rounding=ROUND_FLOOR))
        if date1904:
            actual_date = date(1904, 1, 1) + timedelta(days=serial)
        elif serial == 60:  # Preserve Excel's documented 1900 leap-day convention.
            return "2/29/00", True
        else:
            actual_date = date(1899, 12, 31) + timedelta(days=serial - (serial > 60))
        return f"{actual_date.month}/{actual_date.day}/{actual_date.year % 100:02d}", True
    sections = code.split(";")
    section = sections[1 if value < 0 else 2 if value == 0 else 0]
    output = []
    for match in _FORMAT_TOKENS.finditer(section):
        token = match.group()
        if token.startswith('"'):
            output.append(token[1:-1])
        elif token.startswith("\\"):
            output.append(token[1:])
        elif token.startswith("_") or token.startswith("?"):
            continue  # Column-width padding does not change the number.
        elif token.startswith("*"):
            output.append(token[1:])
        elif token[0] in "#0":
            scaling_commas = len(token) - len(token.rstrip(","))
            pattern = token.rstrip(",")
            integer_pattern, _, fraction_pattern = pattern.partition(".")
            places = len(fraction_pattern)
            with localcontext() as context:
                context.prec = max(50, len(value.as_tuple().digits) + places + 10)
                number = abs(value) / Decimal(1000) ** scaling_commas
                number = number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
                rendered = format(number, f"{',' if ',' in integer_pattern else ''}.{places}f")
            if "#" in fraction_pattern:
                minimum = fraction_pattern.count("0")
                integer, _, fraction = rendered.partition(".")
                fraction = fraction.rstrip("0").ljust(minimum, "0")
                rendered = integer + ("." + fraction if fraction else "")
            if "0" not in integer_pattern and rendered.startswith("0."):
                rendered = rendered[1:]
            output.append(rendered)
        else:
            output.append(token)
    return "".join(output).strip(), True


def _cell_display(cell, formats, cell_formats, date1904):
    style = cell_formats[cell["style_index"]] if cell_formats else {}
    format_id = int(style.get("numFmtId", "0"))
    code = formats.get(format_id, "General" if format_id == 0 else None)
    cell["number_format_id"] = format_id
    cell["number_format_code"] = code
    cell["display_format_supported"] = True
    value = _display(cell)
    if cell["data_type"] == "n" and cell["raw_value"] is not None:
        value, supported = _formatted_number(cell["raw_value"], code, date1904)
        cell["display_format_supported"] = supported
    cell["display_value"] = value


def _position(reference):
    letters, row = _CELL.fullmatch(reference).groups()
    column = 0
    for letter in letters:
        column = column * 26 + ord(letter) - 64
    return int(row), column


def _range(reference):
    ends = reference.split(":")
    return (*_position(ends[0]), *_position(ends[-1]))


def _string(node):
    # Phonetic hints (rPh) are not part of the displayed cell string.
    return "".join(child.text or "" for child in node.iter(_M + "t")
                   if child.getparent().tag != _M + "rPh")


def _part(base, target):
    return target.lstrip("/") if target.startswith("/") else posixpath.normpath(
        posixpath.join(posixpath.dirname(base), target))


def _cell(node, strings):
    reference = node.get("r")
    row, column = _position(reference)
    data_type = node.get("t", "n")
    if len(node):
        value_node = node.find(_M + "v")
        inline = node.find(_M + "is")
        formula = node.find(_M + "f")
    else:
        value_node = inline = formula = None
    raw_value = value_node.text if value_node is not None else None
    if data_type == "s" and raw_value is not None:
        value = strings[int(raw_value)]
    elif inline is not None:
        value = _string(inline)
    else:
        value = raw_value
    formula_data = None if formula is None else {
        "text": formula.text, "attributes": dict(formula.attrib),
    }
    return {
        "coordinate": reference, "row": row, "column": column,
        "attributes": dict(node.attrib), "data_type": data_type,
        "style_index": int(node.get("s", "0")), "value": value,
        "value_present": value_node is not None, "raw_value": raw_value,
        "inline_string_present": inline is not None,
        "formula": formula_data,
        "cached_value_present": formula is not None and value_node is not None,
        "cached_value": value if formula is not None and value_node is not None else None,
        "cached_raw_value": raw_value if formula is not None else None,
        "has_content": value_node is not None or inline is not None or formula is not None,
    }


def _display(cell):
    if cell is None:
        return ""
    if cell["value"] is not None:
        return cell["value"]
    formula = cell["formula"]
    if formula is not None:
        if formula["text"] is not None:
            return "=" + formula["text"]
        return "[formula without cached value: " + str(formula["attributes"]) + "]"
    return ""


def extract_xlsx_tables(body: bytes) -> dict:
    """Extract every worksheet, explicit cell, formula/cache, and merged range.

    ``worksheets[].cells`` is the lossless structured cell record, including
    styled blank cells and formulas without caches. ``tables`` and aligned
    ``table_spans`` are a display projection in original sheet/row/column order;
    covered merge cells are represented by their anchor's span. All explicit
    cells remain in the cell records and text even if a merge visually hides
    them. ZIP-part hashes permit independent checks against the original XLSX.
    """
    started = time.perf_counter_ns()
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    with ZipFile(BytesIO(body)) as archive:
        # Reading every member verifies ZIP CRCs, including drawing/image parts.
        parts = {item.filename: archive.read(item) for item in archive.infolist()}
        manifest = [{"path": item.filename, "bytes": item.file_size,
                     "compressed_bytes": item.compress_size,
                     "sha256": hashlib.sha256(parts[item.filename]).hexdigest()}
                    for item in archive.infolist()]
    part_index = {item["path"]: item for item in manifest}
    workbook_path = "xl/workbook.xml"
    workbook = etree.fromstring(parts[workbook_path], parser)
    relationships = etree.fromstring(parts["xl/_rels/workbook.xml.rels"], parser)
    relations = {item.get("Id"): item for item in relationships}
    shared_part = next((_part(workbook_path, item.get("Target")) for item in relationships
                        if item.get("Type", "").endswith("/sharedStrings")), None)
    strings = ([] if shared_part is None else
               [_string(item) for item in etree.fromstring(parts[shared_part], parser)])
    styles_part = next((_part(workbook_path, item.get("Target")) for item in relationships
                       if item.get("Type", "").endswith("/styles")), None)
    styles = None
    formats_by_id, cell_formats = {}, []
    if styles_part is not None:
        style_root = etree.fromstring(parts[styles_part], parser)
        formats = style_root.find(_M + "numFmts")
        xfs = style_root.find(_M + "cellXfs")
        styles = {"part": styles_part,
                  "number_formats": [dict(item.attrib) for item in formats] if formats is not None else [],
                  "cell_formats": [dict(item.attrib) for item in xfs] if xfs is not None else [],
                  "xml": parts[styles_part].decode("utf-8-sig")}
        formats_by_id = {int(item["numFmtId"]): item["formatCode"] for item in styles["number_formats"]}
        cell_formats = styles["cell_formats"]
    properties = workbook.find(_M + "workbookPr")
    date1904 = properties is not None and properties.get("date1904") in ("1", "true")
    worksheets, tables, table_spans, texts = [], [], [], []
    for sheet in workbook.find(_M + "sheets"):
        relation = relations[sheet.get(_R + "id")]
        if not relation.get("Type", "").endswith("/worksheet"):
            raise ValueError("unsupported_workbook_sheet_type:" + relation.get("Type", ""))
        part = _part(workbook_path, relation.get("Target"))
        root = etree.fromstring(parts[part], parser)
        sheet_data = root.find(_M + "sheetData")
        cells = [_cell(cell, strings) for row in sheet_data for cell in row if cell.tag == _M + "c"]
        for cell in cells:
            _cell_display(cell, formats_by_id, cell_formats, date1904)
        by_position = {(cell["row"], cell["column"]): cell for cell in cells}
        merges_node = root.find(_M + "mergeCells")
        merges = [] if merges_node is None else [item.get("ref") for item in merges_node]
        merge_anchors, merge_covered = {}, set()
        for reference in merges:
            first_row, first_column, last_row, last_column = _range(reference)
            merge_anchors[first_row, first_column] = [last_row - first_row + 1,
                                                     last_column - first_column + 1]
            merge_covered.update((row, column)
                                 for row in range(first_row, last_row + 1)
                                 for column in range(first_column, last_column + 1)
                                 if (row, column) != (first_row, first_column))
        dimension = root.find(_M + "dimension")
        declared_dimension = dimension.get("ref") if dimension is not None else None
        last_row = max((cell["row"] for cell in cells), default=0)
        last_column = max((cell["column"] for cell in cells), default=0)
        for reference in merges + ([declared_dimension] if declared_dimension else []):
            _, _, end_row, end_column = _range(reference)
            last_row, last_column = max(last_row, end_row), max(last_column, end_column)
        rows, spans = [], []
        for row in range(1, last_row + 1):
            positions = [(row, column) for column in range(1, last_column + 1)
                         if (row, column) not in merge_covered]
            rows.append([by_position[position]["display_value"] if position in by_position else "" for position in positions])
            spans.append([merge_anchors.get(position, [1, 1]) for position in positions])
        columns = root.find(_M + "cols")
        worksheet = {
            "name": sheet.get("name"), "sheet_id": sheet.get("sheetId"),
            "state": sheet.get("state", "visible"), "relationship_id": sheet.get(_R + "id"),
            "part": part, "part_sha256": part_index[part]["sha256"],
            "part_bytes": len(parts[part]), "declared_dimension": declared_dimension,
            "row_count": last_row, "column_count": last_column,
            "row_attributes": [dict(row.attrib) for row in sheet_data],
            "column_attributes": [dict(column.attrib) for column in columns] if columns is not None else [],
            "cells": cells, "merged_ranges": merges,
            "explicit_cell_count": len(cells),
            "content_cell_count": sum(cell["has_content"] for cell in cells),
            "formula_count": sum(cell["formula"] is not None for cell in cells),
            "formula_without_cache_count": sum(cell["formula"] is not None and not cell["cached_value_present"] for cell in cells),
            "merge_count": len(merges), "table_index": len(tables),
            "unsupported_display_cell_count": sum(not cell["display_format_supported"] for cell in cells),
        }
        worksheets.append(worksheet)
        tables.append(rows)
        table_spans.append(spans)
        texts.append("[" + worksheet["name"] + "]")
        for cell in cells:
            if cell["has_content"]:
                line = cell["coordinate"] + "\t" + cell["display_value"]
                if cell["formula"] is not None:
                    line += "\tformula=" + str(cell["formula"]["text"])
                texts.append(line)
    # Shapes can carry real text outside cells; retain it with its ZIP part.
    drawing_text = []
    for name, data in parts.items():
        if name.startswith("xl/drawings/") and name.endswith(".xml"):
            values = [node.text or "" for node in etree.fromstring(data, parser).iter(_A + "t")]
            if values:
                drawing_text.append({"part": name, "text": values})
                texts.extend(values)
    totals = {name: sum(sheet[name] for sheet in worksheets) for name in
              ("explicit_cell_count", "content_cell_count", "formula_count",
               "formula_without_cache_count", "merge_count", "unsupported_display_cell_count")}
    result = {
        "text": "\n".join(texts), "tables": tables, "table_spans": table_spans,
        "worksheets": worksheets, "workbook_properties": dict(properties.attrib) if properties is not None else {},
        "shared_strings": strings, "shared_strings_part": shared_part,
        "styles": styles, "drawing_text": drawing_text, "zip_parts": manifest,
        "workbook_part": workbook_path, "source_sha256": hashlib.sha256(body).hexdigest(),
        "source_bytes": len(body), "xlsx_sheets_total": len(worksheets),
        "xlsx_sheets_processed": len(worksheets), **totals,
        "tables_complete": True, "tables_extraction_scope": "all_xlsx_worksheets_and_explicit_cells",
        "display_complete": totals["unsupported_display_cell_count"] == 0,
        "display_spacing": "accounting_width_padding_normalized; original format codes retained",
        "quality_reason": "all_worksheet_cells_formulas_caches_merges_and_zip_parts_preserved",
    }
    result["parse_ms"] = (time.perf_counter_ns() - started) / 1e6
    return result
