"""Privileged tests of the net capability (M1b S3.1/S3.2): connect and accept
tracking on the real kernel.

The helper (tests/helpers/net_helper.py) makes every connect/accept as ONE
raw syscall and reports its return value and errno; the expected net object
(processpulse.net.expected_net) is built from those replies and the address
classes the contract defines, never from collector data. Only loopback TCP,
UDP connect() (which sends no packet) and local sockets are used: nothing
leaves the host, and no container or network is created.

Run as root:  make test-privileged
"""

import copy
import ctypes
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from conftest import wait_until
from processpulse import bpf_collector as bc
from processpulse import net as nt
from processpulse.identity import CgroupResolver

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "net")
HELPER = os.path.join(os.path.dirname(__file__), "helpers", "net_helper.py")
EINPROGRESS, ECONNREFUSED = 115, 111
AF_INET, AF_INET6, AF_UNIX, AF_NETLINK, AF_PACKET = 2, 10, 1, 16, 17
STREAM, DGRAM = 1, 2


class NetHelper:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, HELPER], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        self._ready()

    def _ready(self):
        line = self.p.stdout.readline().split()
        assert line and line[0] == "READY", line
        f = dict(x.split("=") for x in line[1:])
        self.pid, self.tid = int(f["pid"]), int(f["tid"])

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def reply(self):
        return self.p.stdout.readline().split()

    def cmd(self, line):
        self.send(line)
        return self.reply()

    def fd(self, line):
        r = self.cmd(line)
        assert r[0] == "FD", r
        return int(r[1]), (int(r[3]) if len(r) > 3 else None)

    def call(self, line):
        r = self.cmd(line)
        assert r[0] == "DONE", r
        return int(r[1]), int(r[2])

    def exec_(self):
        self.send("exec")
        self._ready()

    def exit(self):
        if self.p.poll() is None:
            try:
                self.send("exit")
                self.p.wait(timeout=10)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.p.kill()
                self.p.wait()
        return self.p.returncode


@pytest.fixture
def helpers():
    made = []

    def make():
        h = NetHelper()
        made.append(h)
        return h
    yield make
    for h in made:
        h.exit()


def fresh(**kw):
    return bc.BpfCollector(capabilities=kw.pop("caps", CAPS),
                           resolver=CgroupResolver(min_rescan_s=0), **kw).start()


@pytest.fixture(scope="module")
def col():
    c = fresh()
    yield c
    c.close()


def result_name(op, ret, err):
    if op == "connect":
        if ret == 0:
            return "connect_ok"
        return {EINPROGRESS: "connect_pending", ECONNREFUSED: "connect_refused"}.get(err,
                                                                                     "connect_err")
    return "accept_ok" if ret >= 0 else "accept_err"


def net_of(c, pid):
    nets = [n for k, n in c.read_net()["nets"].items() if k[1] == pid]
    assert len(nets) == 1, nets
    return nets[0]


def host_tid(c, distro_tid):
    for dtid, htid, _start, _proc in c.thread_slots():
        if dtid == distro_tid:
            return htid
    raise AssertionError(f"no thread slot for tid {distro_tid}")


class Script:
    """The helper's own tally, turned into the expected net object."""

    def __init__(self, h):
        self.h, self.steps = h, []

    def connect(self, fd, cls, family, addr, port, dest, addrlen=None):
        ret, err = self.h.call(f"connect {fd} {family} {addr} {port}"
                               + (f" {addrlen}" if addrlen is not None else ""))
        self.steps.append(("connect", cls, dest, result_name("connect", ret, err)))
        return ret, err

    def accept(self, op, fd, cls):
        ret, err = self.h.call(f"{op} {fd}")
        self.steps.append((op, cls, result_name(op, ret, err)))
        return ret, err

    def expected(self):
        return nt.expected_net(self.steps)


def assert_exact(c, h, script, h0, record_property=None, name=""):
    got = net_of(c, h.pid)
    exp = script.expected()
    assert got == exp, json.dumps({"got": got, "expected": exp}, indent=1)
    assert nt.check_in1(got).status == nt.PASS
    r = nt.check_in6(got, exp, losses=nt.loss_window(h0, c.net_health()))
    assert r.status in (nt.PASS, nt.NOT_APPLICABLE), r
    if record_property:
        record_property(f"{name}I-N6", r.status)
        record_property(f"{name}steps", len(script.steps))
    return r


# Address classes the contract defines (vocab.NET_DEST_CLASSES), checked at the boundaries.
V4 = [("127.0.0.1", "loopback"), ("127.255.255.254", "loopback"), ("10.0.0.1", "private"),
      ("10.255.255.255", "private"), ("172.15.255.255", "public"), ("172.16.0.1", "private"),
      ("172.31.255.255", "private"), ("172.32.0.1", "public"), ("192.167.255.255", "public"),
      ("192.168.0.1", "private"), ("192.169.0.1", "public"), ("169.254.1.1", "link_local"),
      ("169.255.0.1", "public"), ("100.64.0.1", "public"), ("8.8.8.8", "public"),
      ("0.0.0.0", "special"), ("224.0.0.1", "special"), ("239.255.255.255", "special"),
      ("240.0.0.1", "special"), ("255.255.255.255", "special")]
V6 = [("::1", "loopback"), ("::", "special"), ("fc00::1", "private"), ("fdff::1", "private"),
      ("fe80::1", "link_local"), ("febf::1", "link_local"), ("fec0::1", "public"),
      ("ff02::1", "special"), ("::ffff:10.0.0.1", "private"), ("::ffff:127.0.0.1", "loopback"),
      ("::ffff:8.8.8.8", "public"), ("2001:db8::1", "public"), ("2606:4700::1111", "public")]


def test_udp_connect_destination_classes_ipv4_and_ipv6(col, helpers, record_property):
    """UDP connect() only selects a route: no packet is sent to any address."""
    h = helpers()
    h0 = col.net_health()
    s = Script(h)
    fd4, _ = h.fd(f"socket {AF_INET} {DGRAM}")
    for addr, dest in V4:
        s.connect(fd4, "inet4_udp", AF_INET, addr, 9, dest)
    fd6, _ = h.fd(f"socket {AF_INET6} {DGRAM}")
    for addr, dest in V6:
        s.connect(fd6, "inet6_udp", AF_INET6, addr, 9, dest)
    # AF_UNSPEC (dissolve the association) and a too-short address: destination unknown
    s.connect(fd4, "inet4_udp", 0, "x", 0, "unknown")
    s.connect(fd4, "inet4_udp", AF_INET, "127.0.0.1", 9, "unknown", addrlen=4)
    assert_exact(col, h, s, h0, record_property)


def test_tcp_loopback_connect_and_accept(col, helpers, record_property):
    srv, cli = helpers(), helpers()
    h0 = col.net_health()
    ss, sc = Script(srv), Script(cli)
    for fam, addr, cls in ((AF_INET, "127.0.0.1", "inet4_tcp"), (AF_INET6, "::1", "inet6_tcp")):
        lfd, port = srv.fd(f"listen {fam} {STREAM} {addr}")
        c1, _ = cli.fd(f"socket {fam} {STREAM}")
        assert sc.connect(c1, cls, fam, addr, port, "loopback") == (0, 0)
        assert ss.accept("accept4", lfd, cls)[0] >= 0
        c2, _ = cli.fd(f"socket {fam} {STREAM}")
        assert sc.connect(c2, cls, fam, addr, port, "loopback") == (0, 0)
        assert ss.accept("accept", lfd, cls)[0] >= 0
        srv.call(f"nonblock {lfd}")
        assert ss.accept("accept4", lfd, cls)[0] < 0                 # EAGAIN: accept_err
        # a port nobody listens on: refused
        tmp = socket.socket(fam, socket.SOCK_STREAM)
        tmp.bind((addr, 0))
        closed = tmp.getsockname()[1]
        tmp.close()
        c3, _ = cli.fd(f"socket {fam} {STREAM}")
        assert sc.connect(c3, cls, fam, addr, closed, "loopback")[1] == ECONNREFUSED
    assert_exact(col, srv, ss, h0, record_property, "server_")
    assert_exact(col, cli, sc, h0, record_property, "client_")
    cls_cli = net_of(col, cli.pid)["classes"]
    assert cls_cli["inet4_tcp"]["connect_refused"] == 1 and cls_cli["inet6_tcp"]["connect_ok"] == 2


def test_local_ipc_other_and_unknown_families(col, helpers, record_property):
    srv, cli = helpers(), helpers()
    h0 = col.net_health()
    ss, sc = Script(srv), Script(cli)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "s")
        lfd, _ = srv.fd(f"listen {AF_UNIX} {STREAM} {path}")
        u, _ = cli.fd(f"socket {AF_UNIX} {STREAM}")
        assert sc.connect(u, "local_ipc", AF_UNIX, path, 0, None) == (0, 0)
        assert ss.accept("accept4", lfd, "local_ipc")[0] >= 0
        u2, _ = cli.fd(f"socket {AF_UNIX} {STREAM}")
        assert sc.connect(u2, "local_ipc", AF_UNIX, path + ".missing", 0, None)[0] < 0
        nl, _ = cli.fd(f"socket {AF_NETLINK} {DGRAM}")
        sc.connect(nl, "local_ipc", AF_NETLINK, "x", 0, None)
        pk, _ = cli.fd(f"socket {AF_PACKET} {DGRAM}")
        sc.connect(pk, "other", AF_PACKET, "x", 0, None)               # EOPNOTSUPP
        null, _ = cli.fd("open_null")
        assert sc.connect(null, "unknown", AF_INET, "8.8.8.8", 9, None)[1] == 88   # ENOTSOCK
        assert sc.connect(9999, "unknown", AF_INET, "8.8.8.8", 9, None)[1] == 9    # EBADF
        nnull, _ = srv.fd("open_null")
        assert ss.accept("accept", nnull, "unknown")[1] == 88
    assert_exact(col, srv, ss, h0, record_property, "server_")
    got = assert_exact(col, cli, sc, h0, record_property, "client_")
    assert got.status in (nt.PASS, nt.NOT_APPLICABLE)
    n = net_of(col, cli.pid)
    assert "dest" not in n["classes"]["local_ipc"] and "dest" not in n["classes"]["unknown"]
    assert not any(c.startswith("inet") for c in n["classes"])           # I-N1: IPC is not IP


def test_exec_keeps_the_process_key_and_its_counters(col, helpers):
    h = helpers()
    fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
    h.call(f"connect {fd} {AF_INET} 127.0.0.1 9")
    key0 = [k for k in col.read_net()["nets"] if k[1] == h.pid]
    h.exec_()
    fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
    h.call(f"connect {fd} {AF_INET} 10.0.0.1 9")
    key1 = [k for k in col.read_net()["nets"] if k[1] == h.pid]
    assert key0 == key1 and len(key1) == 1
    n = net_of(col, h.pid)
    assert n["entry_observed"]["connect"] == 2
    assert n["classes"]["inet4_udp"]["dest"] == dict(dict.fromkeys(n["classes"]["inet4_udp"]["dest"], 0),
                                                     loopback=1, private=1)


def _blocked_accept(srv, cli_family=AF_INET):
    lfd, port = srv.fd(f"listen {cli_family} {STREAM} 127.0.0.1")
    srv.send(f"accept4 {lfd}")                                       # blocks until a client
    return lfd, port


def _stash_of(c, pid):
    return [(tid.value, s.sc) for tid, s in c.b["net_stash"].items() if s.proc.tgid == pid]


def test_an_exit_whose_entry_is_missing_is_counted_not_recorded(col, helpers):
    srv, cli = helpers(), helpers()
    _lfd, port = _blocked_accept(srv)
    assert wait_until(lambda: _stash_of(col, srv.pid), timeout=10, step=0.01)
    h0 = col.net_health()["hooks"]["accept4"]
    for tid, _sc in _stash_of(col, srv.pid):
        del col.b["net_stash"][ctypes.c_uint(tid)]                   # the entry is lost
    c, _ = cli.fd(f"socket {AF_INET} {STREAM}")
    assert cli.call(f"connect {c} {AF_INET} 127.0.0.1 {port}") == (0, 0)
    r = srv.reply()
    assert r[0] == "DONE" and int(r[1]) >= 0
    h1 = col.net_health()["hooks"]["accept4"]
    assert h1["exit_without_entry"] - h0["exit_without_entry"] >= 1
    assert "inet4_tcp" not in net_of(col, srv.pid)["classes"]            # never guessed


def test_a_stale_thread_identity_is_orphaned_and_replaced(col, helpers):
    h = helpers()
    fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
    htid = host_tid(col, h.tid)
    st = col.b["net_stash"]
    leaf = st.Leaf()
    leaf.thread_start_ns, leaf.sc, leaf.cls, leaf.dest = 1, 1, 8, 0xffff   # a dead thread's accept
    leaf.proc.start_ns, leaf.proc.tgid = 1, h.pid
    st[ctypes.c_uint(htid)] = leaf
    h0 = col.net_health()["hooks"]
    assert h.call(f"connect {fd} {AF_INET} 127.0.0.1 9") == (0, 0)
    h1 = col.net_health()["hooks"]
    assert h1["accept"]["stash_orphaned"] - h0["accept"]["stash_orphaned"] == 1
    assert h1["connect"]["matched"] - h0["connect"]["matched"] >= 1
    assert net_of(col, h.pid)["classes"]["inet4_udp"]["connect_ok"] == 1


def test_thread_exit_with_a_stashed_entry_is_orphaned(col, helpers):
    h = helpers()
    h.fd(f"socket {AF_INET} {DGRAM}")
    htid = host_tid(col, h.tid)
    st = col.b["net_stash"]
    leaf = st.Leaf()
    leaf.thread_start_ns, leaf.sc, leaf.cls, leaf.dest = 1, 0, 8, 0xffff
    leaf.proc.start_ns, leaf.proc.tgid = 1, h.pid
    st[ctypes.c_uint(htid)] = leaf
    h0 = col.net_health()["hooks"]["connect"]["stash_orphaned"]
    assert h.exit() == 0
    assert col.net_health()["hooks"]["connect"]["stash_orphaned"] - h0 == 1
    assert htid not in [k.value for k in st.keys()]


def test_exit_reclaim_removes_net_entries_after_one_report(col, helpers):
    h = helpers()
    fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
    h.call(f"connect {fd} {AF_INET} 127.0.0.1 9")
    pid = h.pid
    vals = net_of(col, pid)
    rec0 = copy.deepcopy(col.reclaimed_net)
    assert h.exit() == 0
    col.snapshot()                                                    # reported exited
    assert any(k.proc.tgid == pid for k in col.b["netc"].keys())
    col.snapshot()                                                    # reclaimed
    assert not any(k.proc.tgid == pid for k in col.b["netc"].keys())
    assert col.reclaimed_net["entry"]["connect"] - rec0["entry"]["connect"] >= \
        vals["entry_observed"]["connect"]


def test_exclusion_purges_net_entries_and_stash_slots(col, helpers):
    a, srv, cli = helpers(), helpers(), helpers()
    fd, _ = a.fd(f"socket {AF_INET} {DGRAM}")
    a.call(f"connect {fd} {AF_INET} 127.0.0.1 9")
    a.call(f"connect {fd} {AF_INET} 8.8.8.8 9")
    p0 = copy.deepcopy(col.purged_net)
    col.exclude(a.pid)
    try:
        assert col.purged_net["entry"]["connect"] - p0["entry"]["connect"] == 2
        assert col.purged_net["results"]["connect"] - p0["results"]["connect"] == 2
        assert not any(k.proc.tgid == a.pid for k in col.b["netc"].keys())
    finally:
        col.unexclude(a.pid)
    _lfd, port = _blocked_accept(srv)
    assert wait_until(lambda: _stash_of(col, srv.pid), timeout=10, step=0.01)
    p1 = copy.deepcopy(col.purged_net)
    col.exclude(srv.pid)
    try:
        assert col.purged_net["stash"]["accept4"] - p1["stash"]["accept4"] == 1
        assert _stash_of(col, srv.pid) == []
        c, _ = cli.fd(f"socket {AF_INET} {STREAM}")
        assert cli.call(f"connect {c} {AF_INET} 127.0.0.1 {port}") == (0, 0)
        assert srv.reply()[0] == "DONE"
        assert not any(k.proc.tgid == srv.pid for k in col.b["netc"].keys())   # nothing written
    finally:
        col.unexclude(srv.pid)


# --- capacity failures (separate small programs) ---------------------------------------------

def _fill(table, make_key, make_leaf):
    keys = []
    for i in range(1, 1 << 16):
        k = make_key(table, i)
        try:
            table[k] = make_leaf(table)
        except Exception:
            break
        keys.append(k)
    return keys


def test_a_full_net_map_drops_and_counts_never_attributes(helpers):
    c = fresh(max_net=64)
    try:
        h = helpers()
        fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")

        def key(t, i):
            k = t.Key()
            k.proc.start_ns, k.proc.tgid, k.cls = i, 0, 0             # tgid 0: no process
            return k
        dummies = _fill(c.b["netc"], key, lambda t: t.Leaf())
        h0 = c.net_health()
        assert h.call(f"connect {fd} {AF_INET} 127.0.0.1 9") == (0, 0)
        h1 = c.net_health()
        assert h1["hooks"]["connect"]["dropped_enter"] > h0["hooks"]["connect"]["dropped_enter"]
        assert h1["net_map_full"] > h0["net_map_full"]
        assert h1["hooks"]["connect"]["exit_without_entry"] > h0["hooks"]["connect"]["exit_without_entry"]
        assert net_of(c, h.pid) == nt.empty_net()                     # nothing attributed
        for k in dummies:
            del c.b["netc"][k]
        # the counted losses keep I-N2 and I-N4 balanced on the drained read
        r = c.drain()
        assert r["drained"], r
        assert nt.check_in2(r["net_terms"]).status == nt.PASS, nt.check_in2(r["net_terms"])
        assert nt.check_in4(r["net_terms"]).status == nt.PASS
    finally:
        c.close()


def test_a_full_stash_counts_the_entry_and_the_unmatched_exit(helpers):
    c = fresh(max_net_stash=16)
    try:
        h = helpers()
        fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")

        def key(t, i):
            return ctypes.c_uint(0x7FFF0000 + i)                     # above any pid_max

        def leaf(t):
            v = t.Leaf()
            v.sc, v.cls, v.dest = 2, 8, 0xffff
            return v
        dummies = _fill(c.b["net_stash"], key, leaf)
        h0 = c.net_health()["hooks"]["connect"]
        assert h.call(f"connect {fd} {AF_INET} 127.0.0.1 9") == (0, 0)
        h1 = c.net_health()["hooks"]["connect"]
        assert h1["stash_full"] - h0["stash_full"] >= 1
        assert h1["exit_without_entry"] - h0["exit_without_entry"] >= 1
        n = net_of(c, h.pid)
        assert n["entry_observed"]["connect"] == 1 and n["classes"] == {}   # entry seen, no result
        for k in dummies:
            del c.b["net_stash"][k]
        r = c.drain()
        assert r["drained"]
        # the dummies were planted and removed from userspace, never by a probe, so
        # they are in no term; every real entry is (stash_full included)
        assert nt.check_in2(r["net_terms"]).status == nt.PASS, nt.check_in2(r["net_terms"])
        assert nt.check_in4(r["net_terms"]).status == nt.PASS, nt.check_in4(r["net_terms"])
    finally:
        c.close()


# --- drain ----------------------------------------------------------------------------------------

def test_drained_accounting_balances_with_reclaim_purge_and_a_blocked_accept(helpers,
                                                                             record_property):
    c = fresh()
    try:
        a, b, p, srv, cli = (helpers() for _ in range(5))
        for h, addr in ((a, "127.0.0.1"), (b, "10.0.0.1"), (p, "8.8.8.8")):
            fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
            h.call(f"connect {fd} {AF_INET} {addr} 9")
        assert b.exit() == 0
        c.snapshot()
        c.snapshot()                                                  # b reclaimed
        c.exclude(p.pid)                                              # p purged
        _lfd, port = _blocked_accept(srv)                             # in flight at the drain
        assert wait_until(lambda: _stash_of(c, srv.pid), timeout=10, step=0.01)
        r = c.drain()
        assert r["drained"], r
        t = r["net_terms"]
        record_property("stash_live_accept4", t["hooks"]["accept4"]["stash_live"])
        record_property("recorded", json.dumps(t["recorded"]))
        assert t["hooks"]["accept4"]["stash_live"] >= 1
        assert t["recorded"]["entry"]["connect"] >= 2
        assert nt.check_in2(t).status == nt.PASS, nt.check_in2(t)
        assert nt.check_in4(t).status == nt.PASS, nt.check_in4(t)
        for key, (proc, _table) in c.drained_processes().items():
            assert nt.check_in1(proc["net"], key).status == nt.PASS
        c3, _ = cli.fd(f"socket {AF_INET} {STREAM}")                 # after the drain:
        cli.call(f"connect {c3} {AF_INET} 127.0.0.1 {port}")         # nothing is counted
        srv.reply()
        c.snapshot()                                                  # raises if maps changed
        assert c.last_snapshot_drained
    finally:
        c.close()


# --- agent: strict startup, cleanup, end to end -----------------------------------------------------

def own_fds():
    out = {}
    for fd in os.listdir("/proc/self/fd"):
        try:
            k = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if k in ("anon_inode:[perf_event]", "anon_inode:bpf-prog", "anon_inode:bpf-map"):
            out[k] = out.get(k, 0) + 1
    return out


@pytest.fixture
def net_start_fails_after_attach(monkeypatch):
    real = bc.BpfCollector.exclude
    seen = {}

    def exclude(self, tgid):
        if self.has_net:
            seen["attached"] = len(self.attached_tracepoints())
            raise OSError(22, "injected: membarrier failed")
        return real(self, tgid)
    monkeypatch.setattr(bc.BpfCollector, "exclude", exclude)
    return seen


def test_strict_net_startup_failure_releases_every_handle(tmp_path, collector_bin,
                                                          net_start_fails_after_attach):
    from processpulse.agent import Agent, StartupError
    before = own_fds()
    with pytest.raises(StartupError):
        Agent(str(tmp_path), duration_s=1, collector=collector_bin, schema=2,
              capabilities=CAPS).run()
    assert net_start_fails_after_attach["attached"] == 17
    assert own_fds() == before
    m = json.load(open(tmp_path / "manifest.json"))
    assert m["status"] == "failed" and m["error"]["capability"] == "net"


def test_degraded_net_startup_runs_counts_only(tmp_path, collector_bin,
                                               net_start_fails_after_attach):
    from processpulse.agent import Agent
    before = own_fds()
    m = Agent(str(tmp_path), interval_ms=200, duration_s=1.5, collector=collector_bin, schema=2,
              capabilities=CAPS, allow_degraded=True).run()
    assert own_fds() == before
    assert m["degraded"] is True and m["capabilities"]["active"] == ["counts"]
    recs = [json.loads(l) for l in open(tmp_path / "bpf.jsonl")]
    assert recs[0]["capabilities"]["net"]["status"] == "unavailable"
    assert all(r["net"] is None and r["net_err"] == "UNSUPPORTED" for r in recs
               if r["type"] == "bpf_proc")


@pytest.mark.parametrize("caps", [("counts", "net"), ("counts", "bigrams", "net")])
def test_agent_end_to_end_net_stream(tmp_path, collector_bin, helpers, record_property, caps):
    from processpulse import bigrams as bg
    from processpulse.agent import Agent
    from processpulse.snapshots import Reconstructor
    from processpulse.validate import Validator
    before = own_fds()
    out = tmp_path / "run"
    agent = Agent(str(out), interval_ms=200, duration_s=120, collector=collector_bin, schema=2,
                  capabilities=caps)
    res = {}
    t = threading.Thread(target=lambda: res.setdefault("m", agent.run()))
    t.start()
    try:
        assert wait_until(lambda: os.path.exists(out / "bpf.jsonl")
                          and b"bpf_snapshot_end" in open(out / "bpf.jsonl", "rb").read(),
                          timeout=120, step=0.1)
        h = helpers()
        s = Script(h)
        fd, _ = h.fd(f"socket {AF_INET} {DGRAM}")
        for addr, dest in V4[:6]:
            s.connect(fd, "inet4_udp", AF_INET, addr, 9, dest)
        time.sleep(1.0)
    finally:
        agent.request_stop()
        t.join(timeout=120)
    m = res["m"]
    assert m["drain"]["status"] == "drained" and m["drain"]["final_snapshot"]["drained"] is True
    assert nt.check_in2(m["drain"]["net_terms"]).status == nt.PASS      # collector side
    assert nt.check_in4(m["drain"]["net_terms"]).status == nt.PASS
    v = Validator()
    recs = [json.loads(l) for l in open(out / "bpf.jsonl")]
    assert all(v.errors(r) == [] for r in recs)
    rc = Reconstructor()
    for r in recs:
        rc.feed(r)
    rc.finish()
    assert rc.valid and rc.last.drained, rc.errors
    terms = nt.terms_from_stream(rc)
    i2, i4 = nt.check_in2(terms), nt.check_in4(terms)
    record_property("I-N2", i2.status)
    record_property("I-N4", i4.status)
    record_property("keys", len(rc.state) + len(rc.retired))
    assert i2.status == nt.PASS, i2
    assert i4.status == nt.PASS, i4
    for kt, p in list(rc.state.items()):
        assert nt.check_in1(p["net"], kt).status == nt.PASS
    (kt,) = [k for k in rc.state if k[2] == h.pid]
    assert rc.state[kt]["net"] == s.expected()                       # I-N6 values, exactly
    if "bigrams" in caps:
        assert bg.check_ib2_drained(rc).status == bg.PASS
    assert own_fds() == before
