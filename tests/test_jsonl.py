"""Unit tests for processpulse.jsonl framing."""

from processpulse.jsonl import JsonlFramer


def test_records_split_across_chunks():
    f = JsonlFramer()
    assert f.feed(b'{"type":"a","v":1}\n{"ty') == [{"type": "a", "v": 1}]
    assert f.feed(b'pe":"b"}\n') == [{"type": "b"}]
    assert f.stats.records == 2 and f.stats.lines == 2


def test_malformed_lines_counted_not_forwarded():
    f = JsonlFramer()
    out = f.feed(b'not json\n[1,2]\n\xff\xfe\n{"ok":1}\n')
    assert out == [{"ok": 1}]
    assert f.stats.malformed_json == 1
    assert f.stats.not_object == 1
    assert f.stats.invalid_utf8 == 1


def test_oversize_line_skipped_until_newline():
    f = JsonlFramer(max_line_bytes=16)
    assert f.feed(b'{"x":"' + b"a" * 40) == []
    assert f.feed(b'"}\n{"y":2}\n') == [{"y": 2}]
    assert f.stats.oversize_lines == 1


def test_oversize_line_within_one_chunk():
    f = JsonlFramer(max_line_bytes=8)
    assert f.feed(b'{"x":"aaaaaaaaaa"}\n{"y":2}\n') == [{"y": 2}]
    assert f.stats.oversize_lines == 1


def test_partial_tail_counted_on_close():
    f = JsonlFramer()
    assert f.feed(b'{"a":1}\n{"b":') == [{"a": 1}]
    f.close()
    assert f.stats.partial_tail == 1
    assert f.feed(b'{"c":3}\n') == [{"c": 3}]   # buffer was cleared


def test_error_callback_receives_kind():
    seen = []
    f = JsonlFramer(on_error=lambda kind, raw: seen.append(kind))
    f.feed(b"oops\n")
    assert seen == ["malformed_json"]
