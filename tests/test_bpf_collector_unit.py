"""Unified BPF collector: capability selection and source assembly (no root needed)."""

import re
from types import SimpleNamespace

import pytest

from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.snapshots import BIGRAM_HEALTH_FIELDS
from processpulse.vocab import SYSCALLS


def test_counts_and_bigrams_are_implemented():
    assert list(bc.CAPABILITIES) == ["counts", "bigrams"]
    assert bc.check_capabilities(("counts",)) == ("counts",)
    assert bc.check_capabilities(("counts", "bigrams")) == ("counts", "bigrams")
    assert bc.check_capabilities(("bigrams", "counts")) == ("counts", "bigrams")   # canonical order


@pytest.mark.parametrize("caps", [(), ("counts", "counts"), ("nosuch",), ("bigrams",),
                                  ("bigrams", "bigrams"), ("counts", "bigrams", "bigrams")])
def test_invalid_selections_are_refused(caps):
    with pytest.raises(ValueError):
        bc.check_capabilities(caps)


def test_bigrams_require_counts():
    with pytest.raises(ValueError, match="requires"):
        bc.check_capabilities(("bigrams",))
    with pytest.raises(ValueError, match="requires"):
        bc.BpfCollector(capabilities=("bigrams",))


@pytest.mark.parametrize("name", ["priv", "net"])
def test_later_stage_capabilities_are_refused(name):
    with pytest.raises(ValueError, match="not implemented"):
        bc.check_capabilities(("counts", name))
    with pytest.raises(ValueError):
        bc.BpfCollector(capabilities=(name,))


def test_required_tracepoints_follow_the_vocabulary():
    tps = bc.required_tracepoints()
    assert tps == tuple(f"syscalls:sys_enter_{s}" for s in SYSCALLS) + (
        "sched:sched_process_exit", "sched:sched_process_exec")


def test_bigrams_attach_no_tracepoint_of_their_own():
    assert bc.required_tracepoints(("counts", "bigrams")) == bc.required_tracepoints(("counts",))


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


def test_bigram_source_is_assembled_before_the_counter_that_calls_it():
    src = bc.build_source(("counts", "bigrams"))
    order = [src.index(m) for m in ("BPF_HASH(threads", "BPF_HASH(bigrams", "BPF_HASH(counts",
                                    "TRACEPOINT_PROBE(sched, sched_process_exit)",
                                    "TRACEPOINT_PROBE(syscalls, sys_enter_execve)")]
    assert order == sorted(order)
    definitions = re.findall(r"^TRACEPOINT_PROBE\((\w+), (\w+)\)", src, re.M)
    assert len(definitions) == len(SYSCALLS) + 2                      # no extra hooks


def _without_bigram_blocks(src):
    """The source with every '#ifdef PPC_CAP_BIGRAMS ... #endif' block removed."""
    out, depth = [], 0
    for line in src.splitlines():
        s = line.strip()
        if depth:
            if s.startswith("#if"):
                depth += 1
            elif s.startswith("#endif"):
                depth -= 1
            continue
        if s == "#ifdef PPC_CAP_BIGRAMS":
            depth = 1
            continue
        out.append(line)
    return "\n".join(out)


def test_counts_only_source_compiles_no_bigram_code():
    src = bc.build_source(("counts",))
    effective = _without_bigram_blocks(src)
    for token in ("BPF_HASH(bigrams", "BPF_ARRAY(bglobal", "bigram_on_", "bigram_count_lost",
                  "pairs_lost", "M_START_", "MAX_PAIRS"):
        assert token not in effective, token
    with open(bc.BPF_DIR + "/bigrams.bpf.c") as f:
        assert "BPF_HASH(bigrams" in f.read()
    assert "BPF_HASH(bigrams" not in src                              # file not even included


def test_shared_definitions_are_not_duplicated():
    for caps in (("counts",), ("counts", "bigrams")):
        src = bc.build_source(caps)
        for decl in ("struct pkey {", "struct tslot {", "static __always_inline int resolve(",
                     "BPF_HASH(excluded", "BPF_ARRAY(health", "static __always_inline void hinc("):
            assert src.count(decl) == 1, (caps, decl)
    for name in ("syscall_counter.bpf.c", "bigrams.bpf.c"):
        with open(bc.BPF_DIR + "/" + name) as f:
            text = f.read()
        assert "struct pkey {" not in text and "struct tslot {" not in text


def test_no_later_stage_hooks_are_present():
    src = bc.build_source(("counts", "bigrams"))
    for hook in ("sock_send_length", "sock_recv_length", "inet_sock_set_state", "setuid",
                 "sys_exit_"):
        assert hook not in src, hook


def test_marker_codes_in_bpf_match_the_decoder():
    with open(bc.BPF_DIR + "/bigrams.bpf.c") as f:
        text = f.read()
    found = dict(re.findall(r"#define (M_\w+)\s+\(NSYSCALLS \+ (\d)\)", text))
    names = {"M_START_NEW": "START_NEW", "M_START_ATTACH": "START_ATTACH",
             "M_START_LOST": "START_LOST", "M_EXEC": "EXEC"}
    assert set(found) == set(names)
    for macro, offset in found.items():
        assert len(SYSCALLS) + int(offset) == bg.MARKER_CODES[names[macro]]
    assert bg.MARKER_CODES == {"START_NEW": 9, "START_ATTACH": 10, "START_LOST": 11, "EXEC": 12}


def test_health_fields_keep_the_m1_prefix():
    assert bc.V1_HEALTH_FIELDS == ("counts_map_full", "info_map_full", "unresolved_events",
                                   "self_excluded_events", "exit_events")
    assert bc.THREAD_HEALTH_FIELDS == ("thread_map_full", "thread_slot_stale",
                                       "thread_slots_cleaned", "exec_refreshes")
    with open(bc.BPF_DIR + "/common.h") as f:
        text = f.read()
    indices = [int(v) for v in re.findall(r"#define H_\w+\s+(\d+)", text)]
    assert sorted(indices) == list(range(len(bc.HEALTH_FIELDS)))
    assert int(re.search(r"#define NHEALTH\s+(\d+)", text).group(1)) == len(bc.HEALTH_FIELDS)
    c_names = {"H_COUNTS_FULL": "counts_map_full", "H_INFO_FULL": "info_map_full",
               "H_UNRESOLVED": "unresolved_events", "H_SELF": "self_excluded_events",
               "H_EXIT": "exit_events", "H_THREAD_FULL": "thread_map_full",
               "H_THREAD_STALE": "thread_slot_stale", "H_THREAD_CLEANED": "thread_slots_cleaned",
               "H_EXEC_REFRESH": "exec_refreshes", "H_BIGRAM_FULL": "bigram_map_full",
               "H_BIGRAM_DROPPED": "bigram_dropped", "H_PRE_ARM": "pre_arm_events"}
    for macro, idx in re.findall(r"#define (H_\w+)\s+(\d+)", text):
        assert bc.HEALTH_FIELDS[int(idx)] == c_names[macro], macro


def _stub_collector(caps=("counts", "bigrams"), health=None):
    c = bc.BpfCollector(capabilities=caps)
    c._health_all = lambda: dict(dict.fromkeys(bc.HEALTH_FIELDS, 0), **(health or {}))
    return c


def test_global_losses_are_the_exact_check_counters():
    c = _stub_collector(health={"counts_map_full": 1, "thread_map_full": 2,
                                "bigram_map_full": 3, "pre_arm_events": 4, "exit_events": 9})
    assert c.global_losses() == {"counts_map_full": 1, "thread_map_full": 2,
                                 "bigram_map_full": 3, "pre_arm_events": 4}
    assert tuple(c.global_losses()) == bg.GLOBAL_LOSS_FIELDS


def test_bigram_health_has_the_end_record_fields():
    c = _stub_collector(health={"bigram_dropped": 7, "pre_arm_events": 2})
    c.purged = {"counts": 5, "pairs": 3, "pairs_lost": 2}
    h = c.bigram_health()
    assert tuple(h) == BIGRAM_HEALTH_FIELDS
    assert h["bigram_dropped"] == 7 and h["pre_arm_events"] == 2
    assert (h["purged_counts"], h["purged_pairs"], h["purged_pairs_lost"]) == (5, 3, 2)
    with pytest.raises(RuntimeError):
        _stub_collector(caps=("counts",)).bigram_health()


# --- grouping raw map entries by process before decoding (fake maps) --------

class FakeTable:
    def __init__(self, items, batch=True):
        self._items, self._batch = items, batch
        self.deleted = []

    def items(self):
        return list(self._items)

    def items_lookup_batch(self):
        if not self._batch:
            raise AttributeError("no batch support")
        return iter(list(self._items))

    def __delitem__(self, k):
        self.deleted.append(k)


def bkey(start, tgid, a, b):
    return SimpleNamespace(proc=SimpleNamespace(start_ns=start, tgid=tgid), a=a, b=b)


def ckey(start, tgid):
    return SimpleNamespace(start_ns=start, tgid=tgid)


def val(n):
    return SimpleNamespace(value=n)


def lost(n):
    return SimpleNamespace(pairs_lost=n)


def _reader(bigram_items, count_items, batch=True):
    c = bc.BpfCollector(capabilities=("counts", "bigrams"))
    c.b = {"bigrams": FakeTable(bigram_items, batch), "counts": FakeTable(count_items)}
    return c


@pytest.mark.parametrize("batch", [True, False])
def test_read_bigrams_groups_by_process_then_decodes(batch):
    c = _reader([(bkey(1, 10, 9, 3), val(1)), (bkey(1, 10, 3, 3), val(4)),
                 (bkey(2, 20, 10, 0), val(2)), (bkey(1, 10, 3, 5), val(0)),   # zero entry
                 (bkey(9, 99, 3, 3), val(1))],                                # no counts entry
                [(ckey(1, 10), lost(1)), (ckey(2, 20), lost(0)), (ckey(3, 30), lost(0))],
                batch=batch)
    r = c.read_bigrams()
    assert r["tables"][(1, 10)] == {("START_NEW", "openat"): 1, ("openat", "openat"): 4}
    assert r["tables"][(2, 20)] == {("START_ATTACH", "execve"): 2}
    assert r["tables"][(3, 30)] == {}                                  # counted, no pair: empty
    assert r["pairs_lost"] == {(1, 10): 1, (2, 20): 0, (3, 30): 0}
    assert r["zero_entries"] == 1 and r["orphan_entries"] == 1 and r["entries"] == 5
    assert r["method"] == ("batch" if batch else "items")
    assert (9, 99) not in r["tables"]                                  # orphans are not tables


def test_read_bigrams_refuses_a_marker_as_second_element():
    c = _reader([(bkey(1, 10, 3, 9), val(1))], [(ckey(1, 10), lost(0))])
    with pytest.raises(bg.DecodeError, match="I-B5"):
        c.read_bigrams()


def test_read_bigrams_needs_the_capability():
    c = bc.BpfCollector(capabilities=("counts",))
    with pytest.raises(RuntimeError):
        c.read_bigrams()


# --- exclusion purge: barrier ordering (S2.3 audit, finding 2) ---------------------

class LoggingTable(FakeTable):
    def __init__(self, name, log, items=()):
        super().__init__(list(items))
        self.name, self.log = name, log

    def items(self):
        self.log.append(("read", self.name))
        return super().items()

    def __setitem__(self, k, v):
        self.log.append(("set", self.name))

    def __delitem__(self, k):
        self.log.append(("delete", self.name))


@pytest.mark.parametrize("caps", [("counts",), ("counts", "bigrams")])
def test_exclude_sets_the_flag_then_waits_then_purges(monkeypatch, caps):
    log = []
    monkeypatch.setattr(bc, "rcu_barrier", lambda: log.append(("barrier", None)))
    c = bc.BpfCollector(capabilities=caps)
    cv = SimpleNamespace(c=[1] + [0] * (len(SYSCALLS) - 1), pairs_lost=0)
    c.b = {"excluded": LoggingTable("excluded", log),
           "counts": LoggingTable("counts", log, [(ckey(1, 10), cv)]),
           "info": LoggingTable("info", log),
           "threads": LoggingTable("threads", log,
                                   [(5, SimpleNamespace(proc=SimpleNamespace(tgid=10)))]),
           "bigrams": LoggingTable("bigrams", log, [(bkey(1, 10, 9, 0), val(1))])}
    c.exclude(10)
    assert log[0] == ("set", "excluded") and log[1] == ("barrier", None)
    assert log.count(("barrier", None)) == 1
    touched = {name for op, name in log[2:]}
    assert {"counts", "info", "threads"} <= touched
    assert ("bigrams" in touched) == ("bigrams" in caps)


def test_rcu_barrier_refuses_without_kernel_support():
    with pytest.raises(RuntimeError, match="MEMBARRIER_CMD_GLOBAL"):
        bc.rcu_barrier(_syscall=lambda nr, cmd, flags, cpu: 0)          # query: unsupported
    with pytest.raises(RuntimeError, match="MEMBARRIER_CMD_GLOBAL"):
        bc.rcu_barrier(_syscall=lambda nr, cmd, flags, cpu: -1)         # query failed
    calls = []

    def failing(nr, cmd, flags, cpu):
        calls.append(cmd)
        return 1 if cmd == 0 else -1
    with pytest.raises(OSError):
        bc.rcu_barrier(_syscall=failing)
    assert calls == [0, 1]                                             # query, then GLOBAL
    ok = []
    bc.rcu_barrier(_syscall=lambda nr, cmd, flags, cpu: ok.append(cmd) or (1 if cmd == 0 else 0))
    assert ok == [0, 1]


def test_exit_hook_skips_excluded_processes_before_touching_their_entries():
    with open(bc.BPF_DIR + "/core.bpf.c") as f:
        text = f.read()
    exit_hook = text[text.index("sched_process_exit"):text.index("sched_process_exec")]
    gate = exit_hook.index("if (excluded.lookup(&k.tgid))")
    assert gate < exit_hook.index("counts_on_exit(&k)")
    assert exit_hook.index("thread_exit()") < gate          # deleting its own slot stays first


def test_preflight_checks_every_attached_tracepoint(monkeypatch):
    from processpulse import preflight
    assert preflight.required_tracepoints is bc.required_tracepoints
    assert "sched:sched_process_exec" in preflight.required_tracepoints()
