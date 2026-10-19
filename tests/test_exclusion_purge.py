"""Privileged tests of the exclusion purge (S2.3 audit, finding 2).

BpfCollector.exclude() sets the exclusion, waits for an RCU grace period
(membarrier MEMBARRIER_CMD_GLOBAL -> synchronize_rcu), then reads and deletes
the process's entries. Probe invocations run under rcu_read_lock(), so after the
barrier none that missed the exclusion is still running, and every later one
returns before writing (the exit hook included). The purge therefore reads
final values and no late update can land in a deleted or reused entry.

A race cannot be forced on demand, so these tests exclude helpers that are
busy making tracked calls, many times over, and check exact outcomes:
- per purge, purged counts = purged pairs + purged pairs_lost (I-B1' of the
  purged entry; an in-flight update would break it);
- no entry of the excluded process exists after exclude() or appears later;
- an unrelated helper, busy the whole time, ends with exactly the counts and
  pair table its script implies (no update of the excluded process landed in
  one of its entries).
Activity is synchronised on observed conditions, not on sleep lengths.

Run as root:  make test-privileged
"""

import subprocess

import pytest

from conftest import Helper, wait_until
from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.vocab import SYSCALLS

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "bigrams")


@pytest.fixture(scope="module")
def col():
    c = bc.BpfCollector(capabilities=CAPS).start()
    yield c
    c.close()


def entries_of(c, tgid):
    """Every map entry that belongs to tgid, by map."""
    out = {"counts": [k for k in c.b["counts"].keys() if k.tgid == tgid],
           "info": [k for k in c.b["info"].keys() if k.tgid == tgid],
           "threads": [k for k, s in c.b["threads"].items() if s.proc.tgid == tgid]}
    if c.has_bigrams:
        out["bigrams"] = [k for k in c.b["bigrams"].keys() if k.proc.tgid == tgid]
    return out


def no_entries(c, tgid):
    return all(not v for v in entries_of(c, tgid).values())


def openat_count(c, tgid):
    for k, v in c.b["counts"].items():
        if k.tgid == tgid:
            return v.c[SYSCALLS.index("openat")]
    return None


def send(h, cmd, n):
    """Starts a command without waiting for its reply."""
    h.proc.stdin.write(f"{cmd} {n}\n")
    h.proc.stdin.flush()


def reply(h, cmd, n):
    r = h.proc.stdout.readline().split()
    assert r[:4] == ["DONE", cmd, str(n), "errors=0"], r


def wait_active(c, tgid, above):
    """Until tgid's openat count exceeds `above` (the helper is inside its loop)."""
    assert wait_until(lambda: (openat_count(c, tgid) or 0) > above, timeout=20, step=0.001), \
        "helper never became active"


def purge_delta(c, before):
    return {k: c.purged[k] - before[k] for k in before}


def assert_purge_balanced(d):
    assert d["counts"] == d["pairs"] + d["pairs_lost"], d          # I-B1' of the purged entry


class Background:
    """A helper that keeps making openat calls; its exact total is tallied."""

    def __init__(self, c, spawn_helper):
        self.c = c
        self.h = spawn_helper()
        self.h.do("openat", 1)                                     # prev := openat
        self.tally = 1
        self.pending = None

    def start(self, n):
        send(self.h, "openat", n)
        self.pending = n

    def finish(self):
        reply(self.h, "openat", self.pending)
        self.tally += self.pending
        self.pending = None

    def check_exact(self):
        """Counts and pair table equal what the script implies, at quiescence."""
        r = self.c.read_bigrams()
        (key,) = [k for k in r["tables"] if k[1] == self.h.pid]
        table, lost = r["tables"][key], r["pairs_lost"][key]
        counts = {s: 0 for s in SYSCALLS}
        for k, v in self.c.b["counts"].items():
            if (k.start_ns, k.tgid) == key:
                counts = dict(zip(SYSCALLS, list(v.c)[:len(SYSCALLS)]))
        assert counts == dict(dict.fromkeys(SYSCALLS, 0), execve=1, openat=self.tally)
        assert table == {("START_NEW", "execve"): 1, ("EXEC", "openat"): 1,
                         ("openat", "openat"): self.tally - 1}
        assert lost == 0
        proc = {"counts": counts, "pairs_lost": lost}
        for check in (bg.check_ib1, bg.check_ib1_prime, bg.check_ib3_prime):
            assert check(proc, table, "asserted").status == bg.PASS


def test_exclude_an_idle_process(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 3)
    before = dict(col.purged)
    col.exclude(h.pid)
    try:
        d = purge_delta(col, before)
        assert d == {"counts": 4, "pairs": 4, "pairs_lost": 0}       # execve + 3 openat
        assert no_entries(col, h.pid)
        h.do("openat", 5)
        assert no_entries(col, h.pid)
    finally:
        col.unexclude(h.pid)


def test_exclude_busy_processes_while_another_stays_exact(col, spawn_helper):
    bgnd = Background(col, spawn_helper)
    for _ in range(10):
        a = spawn_helper()
        bgnd.start(200000)
        send(a, "openat", 200000)
        wait_active(col, a.pid, 1000)
        wait_active(col, bgnd.h.pid, bgnd.tally + 1000)
        before = dict(col.purged)
        col.exclude(a.pid)                                          # while a is in its loop
        try:
            assert no_entries(col, a.pid)                           # nothing survives the purge
            d = purge_delta(col, before)
            assert d["counts"] > 1000
            assert_purge_balanced(d)
            reply(a, "openat", 200000)                              # rest of a's loop: excluded
            assert no_entries(col, a.pid)                           # no late recreation
            bgnd.finish()
        finally:
            col.unexclude(a.pid)
            a.exit()
    bgnd.check_exact()


def test_exclude_immediately_after_spawn_like_the_agent(col, spawn_helper, helper_bin):
    """resource.py calls exclude(pid) right after Popen returns, while the child
    is still starting up (exec, then its own work)."""
    bgnd = Background(col, spawn_helper)
    bgnd.start(1000000)
    wait_active(col, bgnd.h.pid, bgnd.tally + 1000)
    try:
        for _ in range(20):
            p = subprocess.Popen([helper_bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True)
            before = dict(col.purged)
            col.exclude(p.pid)                                      # as on_spawn does
            try:
                assert_purge_balanced(purge_delta(col, before))
                assert p.stdout.readline().startswith("READY")
                p.stdin.write("openat 1000\n")
                p.stdin.flush()
                assert p.stdout.readline().split()[:4] == ["DONE", "openat", "1000", "errors=0"]
                assert no_entries(col, p.pid)
                p.stdin.write("exit\n")
                p.stdin.flush()
                assert p.wait(timeout=10) == 0
                assert no_entries(col, p.pid)                       # exit wrote nothing either
            finally:
                col.unexclude(p.pid)
                if p.poll() is None:
                    p.kill()
                    p.wait()
    finally:
        bgnd.finish()
    bgnd.check_exact()


def test_exit_hook_does_not_touch_an_excluded_process(col, spawn_helper):
    """Deterministic check of the exit-hook gate: an info entry planted for an
    excluded process keeps exited = 0 when the process exits."""
    h = spawn_helper()
    h.do("openat", 1)
    (real,) = [k for k in col.b["counts"].keys() if k.tgid == h.pid]
    col.exclude(h.pid)
    try:
        info = col.b["info"]
        k = info.Key()
        k.start_ns, k.tgid = real.start_ns, real.tgid               # the key the exit hook resolves
        info[k] = info.Leaf()                                       # exited = 0
        assert h.exit() == 0
        assert info[k].exited == 0                                  # the exit hook skipped it
        del info[k]
    finally:
        col.unexclude(h.pid)


def test_counts_only_build_purges_a_busy_process_exactly(spawn_helper):
    c = bc.BpfCollector(capabilities=("counts",)).start()
    try:
        b = spawn_helper()
        b.do("openat", 1)
        b_total = 1
        for _ in range(5):
            a = spawn_helper()
            send(a, "openat", 200000)
            send(b, "openat", 100000)
            wait_active(c, a.pid, 1000)
            self0 = c._purged_self
            c.exclude(a.pid)
            try:
                assert no_entries(c, a.pid)
                assert c._purged_self - self0 > 1000
                reply(a, "openat", 200000)
                assert no_entries(c, a.pid)
                reply(b, "openat", 100000)
                b_total += 100000
            finally:
                c.unexclude(a.pid)
                a.exit()
        counts = None
        for k, v in c.b["counts"].items():
            if k.tgid == b.pid:
                counts = dict(zip(SYSCALLS, list(v.c)[:len(SYSCALLS)]))
        assert counts == dict(dict.fromkeys(SYSCALLS, 0), execve=1, openat=b_total)
    finally:
        c.close()
