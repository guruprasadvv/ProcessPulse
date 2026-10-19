"""Unified BPF collector: capability selection and source assembly (no root needed)."""

import re

import pytest

from processpulse import bpf_collector as bc
from processpulse.vocab import SYSCALLS


def test_only_counts_is_implemented():
    assert list(bc.CAPABILITIES) == ["counts"]
    assert bc.check_capabilities(("counts",)) == ("counts",)


@pytest.mark.parametrize("caps", [(), ("counts", "counts"), ("nosuch",)])
def test_invalid_selections_are_refused(caps):
    with pytest.raises(ValueError):
        bc.check_capabilities(caps)


@pytest.mark.parametrize("name", ["bigrams", "priv", "net"])
def test_later_stage_capabilities_are_refused(name):
    with pytest.raises(ValueError, match="not implemented"):
        bc.check_capabilities(("counts", name))
    with pytest.raises(ValueError):
        bc.BpfCollector(capabilities=(name,))


def test_required_tracepoints_follow_the_vocabulary():
    tps = bc.required_tracepoints()
    assert tps == tuple(f"syscalls:sys_enter_{s}" for s in SYSCALLS) + (
        "sched:sched_process_exit", "sched:sched_process_exec")


def test_unified_source_is_one_unit_in_the_documented_order():
    src = bc.build_source(("counts",))
    order = [src.index(m) for m in ("BPF_HASH(threads", "BPF_HASH(counts",
                                    "TRACEPOINT_PROBE(sched, sched_process_exit)",
                                    "TRACEPOINT_PROBE(syscalls, sys_enter_execve)")]
    assert order == sorted(order)
    probes = re.findall(r"TRACEPOINT_PROBE\(syscalls, sys_enter_(\w+)\)\n\{\n    return count_syscall\((\d+)\);",
                        src)
    assert probes == [(s, str(i)) for i, s in enumerate(SYSCALLS)]
    definitions = re.findall(r"^TRACEPOINT_PROBE\((\w+), (\w+)\)", src, re.M)   # not comments
    assert len(definitions) == len(SYSCALLS) + 2
    assert sorted(f"{a}:{b}" for a, b in definitions) == sorted(bc.required_tracepoints())


def test_shared_definitions_are_not_duplicated():
    src = bc.build_source(("counts",))
    for decl in ("struct pkey {", "static __always_inline int resolve(", "BPF_HASH(excluded",
                 "BPF_ARRAY(health", "static __always_inline void hinc("):
        assert src.count(decl) == 1, decl
    with open(bc.BPF_DIR + "/syscall_counter.bpf.c") as f:
        assert "struct pkey {" not in f.read()


def test_no_later_stage_hooks_are_present():
    src = bc.build_source(("counts",))
    for hook in ("sock_send_length", "sock_recv_length", "inet_sock_set_state", "setuid",
                 "bigram", "sys_exit_"):
        assert hook not in src, hook


def test_health_fields_keep_the_m1_prefix():
    assert bc.V1_HEALTH_FIELDS == ("counts_map_full", "info_map_full", "unresolved_events",
                                   "self_excluded_events", "exit_events")
    with open(bc.BPF_DIR + "/common.h") as f:
        text = f.read()
    indices = [int(v) for v in re.findall(r"#define H_\w+\s+(\d+)", text)]
    assert sorted(indices) == list(range(len(bc.HEALTH_FIELDS)))
    assert int(re.search(r"#define NHEALTH\s+(\d+)", text).group(1)) == len(bc.HEALTH_FIELDS)
    c_names = {"H_COUNTS_FULL": "counts_map_full", "H_INFO_FULL": "info_map_full",
               "H_UNRESOLVED": "unresolved_events", "H_SELF": "self_excluded_events",
               "H_EXIT": "exit_events", "H_THREAD_FULL": "thread_map_full",
               "H_THREAD_STALE": "thread_slot_stale", "H_THREAD_CLEANED": "thread_slots_cleaned",
               "H_EXEC_REFRESH": "exec_refreshes"}
    for macro, idx in re.findall(r"#define (H_\w+)\s+(\d+)", text):
        assert bc.HEALTH_FIELDS[int(idx)] == c_names[macro], macro


def test_preflight_checks_every_attached_tracepoint(monkeypatch):
    from processpulse import preflight
    assert preflight.required_tracepoints is bc.required_tracepoints
    assert "sched:sched_process_exec" in preflight.required_tracepoints()
