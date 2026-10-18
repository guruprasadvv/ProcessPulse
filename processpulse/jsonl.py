"""Incremental JSON Lines framing for byte streams from a collector pipe.

Only complete, strictly UTF-8, newline-terminated lines that decode to a JSON
object are returned. Everything else is counted, never forwarded:
oversize lines are skipped up to the next newline, a trailing line without a
newline at stream end is a partial tail.
"""

import json
from dataclasses import asdict, dataclass

MAX_LINE_BYTES = 64 * 1024


@dataclass
class FramerStats:
    lines: int = 0
    records: int = 0
    malformed_json: int = 0
    invalid_utf8: int = 0
    oversize_lines: int = 0
    partial_tail: int = 0
    not_object: int = 0

    def as_dict(self):
        return asdict(self)


class JsonlFramer:
    def __init__(self, max_line_bytes=MAX_LINE_BYTES, on_error=None):
        self.max_line_bytes = max_line_bytes
        self.stats = FramerStats()
        self._buf = bytearray()
        self._skipping = False   # inside an oversize line, discarding to '\n'
        self._on_error = on_error

    def _error(self, kind, raw):
        if self._on_error is not None:
            self._on_error(kind, bytes(raw[:200]))

    def feed(self, data):
        """Consumes bytes and returns the list of complete records they finish."""
        out = []
        self._buf += data
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                if len(self._buf) > self.max_line_bytes:
                    if not self._skipping:
                        self.stats.oversize_lines += 1
                        self._error("oversize", self._buf)
                    self._skipping = True
                    self._buf.clear()
                break
            line = bytes(self._buf[:nl])
            del self._buf[: nl + 1]
            if self._skipping:
                self._skipping = False
                continue
            if len(line) > self.max_line_bytes:
                self.stats.oversize_lines += 1
                self._error("oversize", line)
                continue
            rec = self._decode(line)
            if rec is not None:
                out.append(rec)
        return out

    def _decode(self, line):
        self.stats.lines += 1
        try:
            text = line.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self.stats.invalid_utf8 += 1
            self._error("invalid_utf8", line)
            return None
        try:
            rec = json.loads(text)
        except ValueError:
            self.stats.malformed_json += 1
            self._error("malformed_json", line)
            return None
        if not isinstance(rec, dict):
            self.stats.not_object += 1
            self._error("not_object", line)
            return None
        self.stats.records += 1
        return rec

    def close(self):
        """Marks end of stream; an unterminated final line is counted, not parsed."""
        if self._buf and not self._skipping:
            self.stats.partial_tail += 1
            self._error("partial_tail", self._buf)
        self._buf.clear()
        self._skipping = False
