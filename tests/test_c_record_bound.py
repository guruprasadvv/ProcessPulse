"""T-F5: the C collector's largest possible `proc` record fits the 64 KiB rule.

The collector prints records piecewise, so the bound is computed: a maximal
record (every number at 20 digits, every value/error pair on its longer side)
plus the worst-case escaped comm and cgroup path, using the constants read
from the C sources so the test follows them if they change. The record model
is first checked against real collector output.
"""

import json
import os
import re
import subprocess

import pytest

from processpulse.jsonl import MAX_RECORD_BYTES
from processpulse.validate import load_schema

pytestmark = pytest.mark.integration

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
U64_MAX = (1 << 64) - 1


def _define(rel, name):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        m = re.search(rf"#define\s+{name}\s+(\d+)\b", f.read())
    assert m, f"{name} not found in {rel}"
    return int(m.group(1))


def _escape_factor():
    with open(os.path.join(REPO, "src", "jsonl.h"), encoding="utf-8") as f:
        m = re.search(r"#define\s+PP_JSON_ESCAPED_MAX\(n\)\s+\(\(n\)\s*\*\s*(\d+)\s*\+\s*1\)", f.read())
    assert m
    return int(m.group(1))


def _dumps(r):
    return json.dumps(r, separators=(",", ":"))


def _maximal_proc():
    """Longest-possible field values, with comm and cgroup empty (added separately)."""
    props = load_schema()["$defs"]["proc"]["properties"]
    rec = {}
    for name, node in props.items():
        ref = node.get("$ref", "")
        if name in ("comm", "cgroup"):
            rec[name] = ""
        elif name == "type":
            rec[name] = "proc"
        elif name == "state":
            rec[name] = "R"
        elif name == "io":
            rec[name] = {k: U64_MAX for k in node["properties"]}
        elif ref.endswith("err_or_null"):
            rec[name] = None            # a set value (20 digits) is longer than null + "UNSUPPORTED"
        elif node.get("type") == "boolean":
            rec[name] = False
        else:
            rec[name] = U64_MAX
    return rec


def test_record_model_matches_real_collector_output(collector_bin):
    out = subprocess.run([collector_bin, "--v1", "--count", "1"], capture_output=True,
                         check=True, timeout=30).stdout
    checked = 0
    for raw in out.split(b"\n"):
        if not raw:
            continue
        rec = json.loads(raw)
        plain = all(isinstance(rec.get(k), str) and rec[k].isascii() and rec[k].isprintable()
                    and '"' not in rec[k] and "\\" not in rec[k]
                    for k in ("comm", "cgroup") if rec.get(k) is not None)
        if rec["type"] == "proc" and plain:
            assert len(raw) == len(_dumps(rec).encode()), raw[:120]
            checked += 1
    assert checked > 0


def test_worst_case_proc_record_is_under_64_kib():
    cgroup_max = _define("src/collector.c", "CGROUP_PATH_MAX") - 1     # NUL-terminated buffer
    comm_max = _define("src/procfs.h", "PP_COMM_MAX")
    k = _escape_factor()
    fixed = len(_dumps(_maximal_proc()).encode())
    worst = fixed + k * cgroup_max + k * comm_max
    assert worst < MAX_RECORD_BYTES, (fixed, worst)
