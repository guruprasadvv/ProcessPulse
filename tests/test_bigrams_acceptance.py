"""M1b S2.4 scripted acceptance for the bigrams capability (privileged).

Every configuration checks one helper process's *complete* pair table and
counts against the oracle (processpulse.bigrams.expected_pairs) built from the
script alone, never from collector data. The script includes how the helper
starts: it is forked after arming, makes one tracked call (the execve that
loads it), and its image makes none before the first command. If any other
tracked call happened, the exact checks fail. Each configuration also checks
I-B5, I-B1, I-B1', I-B3', exact I-B3/I-B4 (with the global losses of the
helper's lifetime window, which must be zero), the scoped ground truth of I-B2,
and that no stale thread slot appeared.

Repeated in fresh processes by tools/acceptance/bigram_exact.sh (10 runs,
N in {1, 1000, 100000} as in M1 acceptance B). Run as root.
"""

import os
import shutil

import pytest

from conftest import Helper
from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.identity import CgroupResolver
from processpulse.vocab import SYSCALLS

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "bigrams")
LAUNCH = [("thread", "m", "new"), ("call", "m", "execve"), ("exec", "m")]
NO_LOSS = dict.fromkeys(bg.GLOBAL_LOSS_FIELDS, 0)


@pytest.fixture(scope="module")
def col():
    c = bc.BpfCollector(capabilities=CAPS, resolver=CgroupResolver(min_rescan_s=0)).start()
    yield c
    c.close()


@pytest.fixture
def exec_target(tmp_path, helper_bin):
    path = tmp_path / "ppc_execd"
    shutil.copy2(helper_bin, path)
    os.chmod(tmp_path, 0o755)
    return str(path)


def state(c, pid):
    r = c.read_bigrams()
    keys = [k for k in r["tables"] if k[1] == pid]
    assert len(keys) == 1, keys
    k = keys[0]
    for ck, v in c.b["counts"].items():
        if (ck.start_ns, ck.tgid) == k:
            counts = dict(zip(SYSCALLS, list(v.c)[:len(SYSCALLS)]))
    return {"counts": counts, "pairs_lost": r["pairs_lost"][k]}, r["tables"][k]


class Window:
    """Global loss counters and stale-slot count over a helper's lifetime."""

    def __init__(self, c):
        self.c = c
        self.g0 = c.global_losses()
        self.stale0 = c.thread_health()["thread_slot_stale"]

    def close(self):
        return (bg.loss_window(self.g0, self.c.global_losses()),
                self.c.thread_health()["thread_slot_stale"] - self.stale0)


def assert_exact(record_property, p, t, oracle, losses, stale, tally):
    observed = sum(p["counts"].values())
    record_property("expected", tally)
    record_property("observed", observed)
    record_property("pairs_exact", int(t == oracle.pairs))
    record_property("losses", sum(losses.values()))
    record_property("thread_slot_stale", stale)
    assert losses == NO_LOSS, f"global losses in the window: {losses}"
    assert stale == 0
    assert p["counts"] == oracle.counts
    assert t == oracle.pairs
    assert p["pairs_lost"] == 0
    results = [bg.check_ib5(t),
               bg.check_ib1(p, t, "asserted"), bg.check_ib1_prime(p, t, "asserted"),
               bg.check_ib3_prime(p, t, "asserted"),
               bg.check_ib3_exact(p, t, oracle, "asserted", losses=losses),
               bg.check_ib4_exact(p, t, oracle, "asserted", losses=losses),
               bg.check_ib2_ground_truth_scope([(p, t)], tally, "asserted", losses)]
    for r in results:
        assert r.status == bg.PASS, r
    record_property("checks_passed", len(results))


def run_commands(col, spawn_helper, commands):
    w = Window(col)
    h = spawn_helper()
    script = list(LAUNCH)
    for cmd, n in commands:
        h.do(cmd, n)
        script += [("call", "m", cmd)] * n
    p, t = state(col, h.pid)
    losses, stale = w.close()
    return p, t, bg.expected_pairs(script), losses, stale, 1 + sum(n for _c, n in commands)


@pytest.mark.parametrize("n", [1, 1000])
@pytest.mark.parametrize("cmd", ["openat", "open", "execve", "clone"])
def test_exact_pairs(col, spawn_helper, record_property, cmd, n):
    assert_exact(record_property, *run_commands(col, spawn_helper, [(cmd, n)]))


@pytest.mark.slow
@pytest.mark.parametrize("cmd", ["openat", "execve", "clone"])
def test_exact_pairs_100000(col, spawn_helper, record_property, cmd):
    assert_exact(record_property, *run_commands(col, spawn_helper, [(cmd, 100000)]))


def test_exact_pairs_mixed_sequence(col, spawn_helper, record_property):
    """The plan's example shape: several syscalls in one segment."""
    cmds = [("openat", 3), ("execve", 2), ("clone", 1), ("open", 4), ("openat", 1)]
    assert_exact(record_property, *run_commands(col, spawn_helper, cmds))


def test_exact_pairs_across_an_exec(col, helper_bin, exec_target, record_property):
    w = Window(col)
    h = Helper([helper_bin, exec_target])
    try:
        h.do("openat", 2)
        h.do("exec", 0)                                     # libc execve: one entry, then exec
        line = h.proc.stdout.readline().split()
        assert line and line[0] == "READY", line
        h.do("openat", 1)
        p, t = state(col, h.pid)
        losses, stale = w.close()
        script = LAUNCH + [("call", "m", "openat")] * 2 + [("call", "m", "execve"), ("exec", "m"),
                                                            ("call", "m", "openat")]
        assert_exact(record_property, p, t, bg.expected_pairs(script), losses, stale, 5)
    finally:
        h.exit()


def test_ground_truth_over_a_scope_with_exit_and_purge(col, spawn_helper, record_property):
    """Three scripted helpers: one live, one exited (not yet reclaimed), one purged
    by self-exclusion. Their entries, counted by the script, must equal the counts
    side and the pairs side, with the purge totals for the purged one."""
    w = Window(col)
    a, b, c = spawn_helper(), spawn_helper(), spawn_helper()
    a.do("openat", 10)
    b.do("open", 5)
    c.do("execve", 3)
    tally = (1 + 10) + (1 + 5) + (1 + 3)
    pa, ta = state(col, a.pid)
    assert b.exit() == 0
    pb, tb = state(col, b.pid)
    purged0 = dict(col.purged)
    col.exclude(c.pid)
    try:
        purged = {k: col.purged[k] - purged0[k] for k in purged0}
    finally:
        col.unexclude(c.pid)
    losses, stale = w.close()
    record_property("expected", tally)
    record_property("observed", sum(pa["counts"].values()) + sum(pb["counts"].values())
                    + purged["counts"])
    assert losses == NO_LOSS and stale == 0
    assert purged == {"counts": 4, "pairs": 4, "pairs_lost": 0}
    r = bg.check_ib2_ground_truth_scope([(pa, ta), (pb, tb)], tally, "asserted", losses, purged)
    assert r.status == bg.PASS, r
    # the same data without the purged helper, or with a helper twice, is caught
    assert bg.check_ib2_ground_truth_scope([(pa, ta), (pb, tb)], tally, "asserted", losses,
                                           None).status == bg.FAIL
    assert bg.check_ib2_ground_truth_scope([(pa, ta), (pb, tb), (pb, tb)], tally, "asserted",
                                           losses, purged).status == bg.FAIL
    for p, t, cmd, n in ((pa, ta, "openat", 10), (pb, tb, "open", 5)):
        o = bg.expected_pairs(LAUNCH + [("call", "m", cmd)] * n)
        assert p["counts"] == o.counts and t == o.pairs
        assert bg.check_ib3_exact(p, t, o, "asserted", losses=losses).status == bg.PASS
        assert bg.check_ib4_exact(p, t, o, "asserted", losses=losses).status == bg.PASS
