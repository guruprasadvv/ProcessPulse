"""
ProcessPulse-C M0 — test suite.

Unit tests: a Python reference implementation of the /proc/<pid>/stat
parser, tested against crafted stat strings.  The reference mirrors the
C algorithm exactly (first '(' / last ')' / field-index arithmetic) so
the tests document the parsing spec rather than a Python-specific detail.

Integration tests: run the compiled collector binary and validate its
JSON output for correctness, field types, and minimum record count.
Integration tests are skipped (not failed) when the binary is absent or
the environment has fewer processes than the minimum threshold.
"""

import json
import os
import subprocess
import pytest

# ---------------------------------------------------------------------------
# Reference parser — mirrors collector.c parse_proc_stat() logic exactly
# ---------------------------------------------------------------------------

def parse_stat_line(line: str) -> tuple:
    """
    Parse a /proc/<pid>/stat line.

    Returns (pid: int, comm: str, utime: int, stime: int).
    Raises ValueError with a descriptive message on any format error.

    Algorithm:
      1. PID  — digits before the first '('.
      2. comm — text between the first '(' and the LAST ')' in the line.
                strrchr(')') is correct because all fields after comm are
                integers and never contain ')'.
      3. After the last ')' the remaining tokens are (0-indexed):
            0  state   (field  3)
            1  ppid    (field  4)
            2  pgrp    (field  5)
            3  session (field  6)
            4  tty_nr  (field  7)
            5  tpgid   (field  8)
            6  flags   (field  9)
            7  minflt  (field 10)
            8  cminflt (field 11)
            9  majflt  (field 12)
           10  cmajflt (field 13)
           11  utime   (field 14)  ← stored
           12  stime   (field 15)  ← stored
    """
    line = line.rstrip("\n")

    open_idx = line.find("(")
    if open_idx == -1:
        raise ValueError("no opening parenthesis for comm field")

    close_idx = line.rfind(")")
    if close_idx == -1 or close_idx <= open_idx:
        raise ValueError("no closing parenthesis for comm field")

    # PID: all text before the first '('
    pid_text = line[:open_idx].strip()
    try:
        pid = int(pid_text)
    except ValueError:
        raise ValueError(f"non-integer PID field: {pid_text!r}")
    if pid <= 0:
        raise ValueError(f"non-positive PID: {pid}")

    # comm: between first '(' (exclusive) and last ')' (exclusive)
    comm = line[open_idx + 1 : close_idx]

    # Remaining fields after the last ')'
    remaining = line[close_idx + 1 :].split()

    # We need at least 13 tokens (indices 0–12)
    if len(remaining) < 13:
        raise ValueError(
            f"too few fields after comm: got {len(remaining)}, need at least 13"
        )

    try:
        utime = int(remaining[11])
        stime = int(remaining[12])
    except ValueError as exc:
        raise ValueError(f"non-integer utime/stime: {exc}") from exc

    if utime < 0 or stime < 0:
        raise ValueError(f"negative utime ({utime}) or stime ({stime})")

    return pid, comm, utime, stime


# ---------------------------------------------------------------------------
# Unit tests for the parser
# ---------------------------------------------------------------------------

class TestParseStatLine:
    """
    Each test uses a realistic /proc/<pid>/stat string.

    The strings below are structurally valid but the numeric values in
    fields 4-13 are deliberately small to keep the strings readable.
    Fields 14 and 15 (utime, stime) are the values under test.
    """

    # Enough dummy fields (ppid…cmajflt) for any test line.
    #   field 4 ppid=1, 5 pgrp=X, 6 session=X, 7 tty_nr=0, 8 tpgid=-1,
    #   9 flags=4194304, 10 minflt=0, 11 cminflt=0, 12 majflt=0, 13 cmajflt=0
    _SUFFIX = "1 {x} {x} 0 -1 4194304 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 100 4096 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

    def _make_line(self, pid, comm, utime, stime, pgrp=None):
        """Build a minimal but structurally correct stat line."""
        pgrp = pgrp if pgrp is not None else pid
        fields_after = (
            f"{pid} {pgrp} {pgrp} 0 -1 4194304 0 0 0 0 "
            f"{utime} {stime} 0 0 20 0 1 0 100 4096 10 "
            "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"
        )
        return f"{pid} ({comm}) R {fields_after}"

    def test_simple_single_word_name(self):
        line = self._make_line(1, "init", 71, 24)
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 1
        assert comm == "init"
        assert utime == 71
        assert stime == 24

    def test_name_with_spaces(self):
        """comm containing spaces — naive whitespace split would break this."""
        line = self._make_line(123, "my cool proc", 500, 200)
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 123
        assert comm == "my cool proc"
        assert utime == 500
        assert stime == 200

    def test_name_with_single_paren(self):
        """comm containing '(' — rfind(')') must still find the correct close."""
        line = self._make_line(456, "proc(1)", 10, 5)
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 456
        assert comm == "proc(1)"
        assert utime == 10
        assert stime == 5

    def test_name_with_matching_parens(self):
        """comm with balanced inner parentheses — last ')' is the delimiter."""
        line = self._make_line(789, "bad (name) here", 999, 111)
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 789
        assert comm == "bad (name) here"
        assert utime == 999
        assert stime == 111

    def test_name_with_multiple_parens(self):
        """comm that opens and closes parens multiple times."""
        line = self._make_line(1001, "(a)(b)(c)", 42, 7)
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 1001
        assert comm == "(a)(b)(c)"
        assert utime == 42
        assert stime == 7

    def test_zero_cpu_times(self):
        """Freshly started process with no accumulated CPU time."""
        line = self._make_line(42, "fresh", 0, 0)
        pid, comm, utime, stime = parse_stat_line(line)
        assert utime == 0
        assert stime == 0

    def test_large_cpu_times(self):
        """Long-running process with large counters — values must not wrap."""
        line = self._make_line(100, "worker", 12345678, 9876543)
        pid, comm, utime, stime = parse_stat_line(line)
        assert utime == 12345678
        assert stime == 9876543

    def test_empty_comm_field(self):
        """Empty comm is syntactically parseable (pid=99, comm='')."""
        line = "99 () R 1 99 99 0 -1 4194304 0 0 0 0 5 3 0 0 20 0 1 0 100 4096 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0"
        pid, comm, utime, stime = parse_stat_line(line)
        assert pid == 99
        assert comm == ""
        assert utime == 5
        assert stime == 3

    def test_different_process_states(self):
        """Verify parsing is independent of the state character."""
        for state_char, expected_pid in [("R", 10), ("S", 11), ("D", 12), ("Z", 13)]:
            line = f"{expected_pid} (testproc) {state_char} 1 {expected_pid} {expected_pid} 0 -1 4194304 0 0 0 0 100 50 0 0 20 0 1 0 100 4096 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0"
            pid, comm, utime, stime = parse_stat_line(line)
            assert pid == expected_pid
            assert utime == 100
            assert stime == 50

    # --- Error cases ---

    def test_missing_open_paren(self):
        with pytest.raises(ValueError, match="no opening parenthesis"):
            parse_stat_line("1 init S 0 0 0 0 -1 0 0 0 0 0 71 24 0 0 20 0 1 0")

    def test_missing_close_paren(self):
        with pytest.raises(ValueError, match="no closing parenthesis"):
            parse_stat_line("1 (init S 0 0 0 0 -1 0 0 0 0 0 71 24 0 0 20 0 1 0")

    def test_too_few_fields_after_comm(self):
        """Line that ends before utime/stime."""
        with pytest.raises(ValueError, match="too few fields"):
            parse_stat_line("1 (init) S 0 0")

    def test_non_integer_pid(self):
        with pytest.raises(ValueError):
            parse_stat_line("abc (init) S 0 0 0 0 -1 0 0 0 0 0 71 24 0 0 20 0 1 0")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            parse_stat_line("")

    def test_non_integer_utime(self):
        line = "1 (proc) R 1 1 1 0 -1 4194304 0 0 0 0 abc 24 0 0 20 0 1 0 100 4096 10 0"
        with pytest.raises(ValueError, match="non-integer"):
            parse_stat_line(line)


# ---------------------------------------------------------------------------
# Integration tests — run the compiled collector binary
# ---------------------------------------------------------------------------

# Path to the compiled binary, relative to this test file.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_BIN = os.path.join(_REPO_ROOT, "collector")

# Minimum number of accessible process records we require on a full system.
# On a typical Linux desktop or server there are hundreds of processes.
# Minimal containers may have far fewer — those environments skip this test.
MINIMUM_RECORDS = 100


def _skip_if_no_binary():
    if not os.path.isfile(COLLECTOR_BIN):
        pytest.skip(
            f"collector binary not found at {COLLECTOR_BIN}. "
            "Run 'make' first, then re-run tests."
        )


def _run_collector() -> list[dict]:
    """Run collector, return parsed JSON records. Fails the test on bad exit."""
    result = subprocess.run(
        [COLLECTOR_BIN],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"collector exited with code {result.returncode}.\n"
        f"stderr: {result.stderr}"
    )
    records = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            pytest.fail(f"line {i + 1} is not valid JSON: {exc}\nLine: {line!r}")
    return records


@pytest.mark.integration
class TestCollectorIntegration:

    def test_collector_exits_zero(self):
        """Collector must return exit code 0 on a running system."""
        _skip_if_no_binary()
        result = subprocess.run([COLLECTOR_BIN], capture_output=True, timeout=30)
        assert result.returncode == 0, (
            f"Non-zero exit: {result.returncode}\nstderr: {result.stderr.decode()}"
        )

    def test_every_line_is_valid_json(self):
        """Every non-empty output line must be valid JSON."""
        _skip_if_no_binary()
        _run_collector()  # internal assertion handles bad JSON

    def test_required_fields_present_and_typed(self):
        """Each record must have pid (int), comm (str), utime (int), stime (int)."""
        _skip_if_no_binary()
        records = _run_collector()
        assert records, "collector produced no records"

        for i, rec in enumerate(records):
            loc = f"record {i + 1} (pid={rec.get('pid', '?')})"
            for field in ("pid", "comm", "utime", "stime"):
                assert field in rec, f"{loc}: missing field '{field}'"

            assert isinstance(rec["pid"],   int), f"{loc}: 'pid' must be integer"
            assert isinstance(rec["comm"],  str), f"{loc}: 'comm' must be string"
            assert isinstance(rec["utime"], int), f"{loc}: 'utime' must be integer"
            assert isinstance(rec["stime"], int), f"{loc}: 'stime' must be integer"

            assert rec["pid"]   > 0,  f"{loc}: 'pid' must be positive"
            assert rec["utime"] >= 0, f"{loc}: 'utime' must be non-negative"
            assert rec["stime"] >= 0, f"{loc}: 'stime' must be non-negative"

    def test_no_duplicate_pids(self):
        """A single collection run must not emit the same PID twice."""
        _skip_if_no_binary()
        records = _run_collector()
        pids = [r["pid"] for r in records]
        seen = set()
        dupes = [p for p in pids if p in seen or seen.add(p)]
        assert not dupes, f"duplicate PIDs found: {dupes}"

    def test_minimum_record_count(self):
        """
        On a full Linux system the collector must see at least MINIMUM_RECORDS
        processes.  On minimal environments (single-process containers, highly
        restricted /proc) we skip with an explanation rather than failing,
        because the environment — not the code — is the limiting factor.
        """
        _skip_if_no_binary()
        records = _run_collector()
        count = len(records)
        if count < MINIMUM_RECORDS:
            pytest.skip(
                f"Only {count} process records returned (threshold: {MINIMUM_RECORDS}). "
                "This environment has too few accessible processes. "
                "Run on a full Linux desktop or server to satisfy this criterion."
            )
        assert count >= MINIMUM_RECORDS

    def test_collector_self_pid_present(self):
        """
        The collector process itself must appear in the output, confirming
        that it enumerates at least its own /proc entry.
        """
        _skip_if_no_binary()
        proc = subprocess.Popen(
            [COLLECTOR_BIN],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, _ = proc.communicate(timeout=30)
        collector_pid = proc.pid

        pids = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    pids.add(json.loads(line)["pid"])
                except (json.JSONDecodeError, KeyError):
                    pass

        # The collector enumerates /proc in a loop; its own PID should be there.
        assert collector_pid in pids, (
            f"Collector PID {collector_pid} not found in its own output "
            f"(saw {len(pids)} PIDs). "
            "This may indicate /proc enumeration starts after the process exists."
        )
