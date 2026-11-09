"""Extract a complete HTML EX-99.1 from a streamed SEC submission container."""
import re


_DOCUMENT_START = re.compile(br"(?m)^<DOCUMENT>\r?\n")
_DOCUMENT_END = re.compile(br"(?m)^</DOCUMENT>\r?\n")
_TEXT_START = re.compile(br"(?m)^<TEXT>\r?\n")
_TEXT_END = re.compile(br"(?m)^</TEXT>\r?\n")


class IncrementalExhibit:
    """Return only after TEXT and DOCUMENT have both closed on SGML lines.

    ``body`` contains the original bytes inside TEXT, including line endings.
    Container offsets count decoded HTTP bytes, not compressed wire bytes.
    """
    def __init__(self):
        self._buffer = bytearray()
        self._discarded = 0
        self._received = 0
        self._done = False

    def feed(self, chunk: bytes) -> dict | None:
        if self._done:
            return None
        self._buffer.extend(chunk)
        self._received += len(chunk)
        while True:
            opening = _DOCUMENT_START.search(self._buffer)
            if opening is None:
                # Retain enough bytes for a marker split across two chunks.
                discard = max(0, len(self._buffer) - 13)
                del self._buffer[:discard]
                self._discarded += discard
                return None
            if opening.start():
                discard = opening.start()
                del self._buffer[:discard]
                self._discarded += discard
                opening = _DOCUMENT_START.match(self._buffer)
            closing = _DOCUMENT_END.search(self._buffer, opening.end())
            if closing is None:
                return None
            document = bytes(self._buffer[opening.end():closing.start()])
            consumed = self._discarded + closing.end()
            del self._buffer[:closing.end()]
            self._discarded = consumed
            result = self._extract(document)
            if result is not None:
                self._done = True
                self._buffer.clear()
                return {**result, "container_bytes_consumed": consumed,
                        "container_bytes_received": self._received}

    @staticmethod
    def _extract(document: bytes) -> dict | None:
        start = _TEXT_START.search(document)
        if start is None:
            return None
        header = document[:start.start()]
        kind = re.search(br"(?m)^<TYPE>([^\r\n]+)", header)
        filename = re.search(br"(?m)^<FILENAME>([^\r\n]+)", header)
        if kind is None or kind.group(1).strip() != b"EX-99.1" or filename is None:
            return None
        end = _TEXT_END.search(document, start.end())
        if end is None or document[end.end():].strip():
            return None
        body = document[start.end():end.start()]
        if not re.search(br"<html(?:\s|>)", body[:2048], re.I):
            return None
        if not re.search(br"</html\s*>\s*\Z", body, re.I):
            return None
        return {"body": body, "filename": filename.group(1).strip().decode("utf-8"),
                "form": "EX-99.1"}

    def close_without_match(self) -> None:
        """Abandon incomplete containers without accepting any partial exhibit."""
        self._done = True
        self._buffer.clear()
