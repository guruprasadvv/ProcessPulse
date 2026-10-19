"""The byte-level JSONL framing rule (docs/telemetry-v2.md §1).

A record is the UTF-8 bytes of one JSON object without its terminating LF;
it must be 1..65,536 bytes long and contain no CR or LF. v2 writers enforce
the rule (encode_record); validators check it per line (line_violations).
"""

import json

import pytest

from processpulse.jsonl import (MAX_LINE_BYTES, MAX_RECORD_BYTES, JsonlFramer, RecordTooLarge,
                                encode_record, line_violations)


def record_of_size(n, filler="a"):
    """A compact JSON object whose UTF-8 encoding is exactly n bytes."""
    head, tail = b'{"x":"', b'"}'
    unit = filler.encode("utf-8")
    body = n - len(head) - len(tail)
    assert body >= 0 and body % len(unit) == 0, (n, filler)
    raw = head + unit * (body // len(unit)) + tail
    assert len(raw) == n
    return raw


def test_limit_is_64_kib():
    assert MAX_RECORD_BYTES == MAX_LINE_BYTES == 65536


@pytest.mark.parametrize("n", [2, 65535, 65536])
def test_records_up_to_the_limit_pass(n):
    assert line_violations(record_of_size(n) if n > 8 else b"{}") == []


def test_one_byte_over_the_limit_is_oversize():
    assert line_violations(record_of_size(65537)) == ["oversize"]


def test_limit_counts_bytes_not_characters():
    # 'é' is 2 bytes in UTF-8: 65,536 bytes passes even though it is fewer characters.
    raw = b'{"x":"' + "é".encode() * 32764 + b'a"}'
    assert len(raw) == 65537 and len(raw.decode()) < 65536
    assert line_violations(raw) == ["oversize"]
    ok = b'{"x":"' + "é".encode() * 32764 + b'"}'
    assert len(ok) == 65536
    assert line_violations(ok) == []


def test_cr_and_lf_and_empty_are_violations():
    assert line_violations(b'{"a":1}\r') == ["trailing_cr"]
    assert line_violations(b'{"a":\r1}') == ["embedded_cr"]
    assert line_violations(b'{"a":\n1}') == ["embedded_lf"]
    assert line_violations(b"") == ["empty"]


def test_multiple_violations_are_all_reported():
    assert line_violations(record_of_size(65537)[:-1] + b"\r") == ["oversize", "trailing_cr"]


def test_encode_record_is_compact_ascii_and_bounded():
    text = encode_record({"type": "t", "v": 2, "s": "é\r\n"})
    assert text == '{"type":"t","v":2,"s":"\\u00e9\\r\\n"}'
    assert text.isascii() and "\r" not in text and "\n" not in text


def test_encode_record_accepts_exactly_the_limit():
    rec = json.loads(record_of_size(65536))
    assert len(encode_record(rec).encode()) == 65536


def test_encode_record_rejects_one_byte_more():
    rec = json.loads(record_of_size(65537))
    with pytest.raises(RecordTooLarge):
        encode_record(rec)


def test_encode_record_limit_is_on_bytes_after_escaping():
    # 13,000 control characters escape to 6 bytes each (\u0001) -> 78,000+ bytes.
    with pytest.raises(RecordTooLarge):
        encode_record({"x": "\x01" * 13000})


# --- the v1 stream framer keeps the same byte limit ------------------------

def test_framer_accepts_exactly_the_limit_in_small_chunks():
    raw = record_of_size(65536) + b"\n"
    f = JsonlFramer()
    out = []
    for i in range(0, len(raw), 7):
        out += f.feed(raw[i:i + 7])
    assert len(out) == 1 and f.stats.oversize_lines == 0


def test_framer_rejects_one_byte_over_in_small_chunks():
    raw = record_of_size(65537) + b"\n" + b'{"next":1}\n'
    f = JsonlFramer()
    out = []
    for i in range(0, len(raw), 7):
        out += f.feed(raw[i:i + 7])
    assert out == [{"next": 1}] and f.stats.oversize_lines == 1


def test_framer_rejects_multibyte_char_straddling_the_limit():
    # The 2-byte char occupies bytes 65,536-65,537, so a 65,536-byte cut would split it.
    raw = b'{"x":"' + b"a" * 65529 + "é".encode() + b'"}'
    assert len(raw) == 65539 and raw[:65536].decode("utf-8", "replace").endswith("�")
    f = JsonlFramer()
    assert f.feed(raw + b"\n") == [] and f.stats.oversize_lines == 1


def test_v1_framer_keeps_legacy_trailing_cr_behaviour():
    # Unchanged M1 behaviour: json.loads accepts trailing whitespace, so the v1
    # framer forwards '{...}\r'. v2 validators reject it (line_violations).
    f = JsonlFramer()
    assert f.feed(b'{"a":1}\r\n') == [{"a": 1}]
    assert line_violations(b'{"a":1}\r') == ["trailing_cr"]
