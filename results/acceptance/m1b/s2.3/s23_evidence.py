"""S2.3 evidence (run as root): build info, read method, and the exact state of
an idle helper under each forced loss path. Writes JSON to argv[1]."""
import json, os, sys
REPO = "/mnt/c/Users/mypc/Desktop/vit/5th sem/os/os project/os project"
sys.path[:0] = [REPO, os.path.join(REPO, "tests")]
os.chdir(REPO)
from conftest import Helper, HELPER_BIN
from processpulse import bpf_collector as bc
import test_bigrams_bpf as T

def show(c, pid):
    p, t = T.state(c, pid)
    return {"counts": {k: v for k, v in p["counts"].items() if v}, "pairs_lost": p["pairs_lost"],
            "pairs": {f"{a}->{b}": n for (a, b), n in sorted(t.items())}}

out = {}
c = bc.BpfCollector(capabilities=("counts", "bigrams")).start()
try:
    info = c.build_info()
    out["build_info"] = {k: info[k] for k in ("capabilities", "compilations", "open_tracepoints",
                                              "vocabulary", "max_procs", "max_threads", "max_pairs", "maps")}
    h = Helper([HELPER_BIN]); h.do("openat", 1); h.do("open", 2); h.do("openat", 3)
    out["no_loss_helper"] = show(c, h.pid)
    r = c.read_bigrams()
    out["read"] = {k: r[k] for k in ("method", "entries", "zero_entries", "orphan_entries", "read_ns")}
    out["health"] = c.bigram_health()
    h.exit()
finally:
    c.close()

s = bc.BpfCollector(capabilities=("counts", "bigrams"), max_procs=256, max_threads=256, max_pairs=256).start()
try:
    for name, mapname, mk, leaf in (("row1_counts_full", "counts", T._dummy_count_key, lambda t: t.Leaf()),
                                    ("row2_thread_full", "threads", T._dummy_thread_key, T._dummy_thread_leaf),
                                    ("row3_bigram_full", "bigrams", T._dummy_pair_key, lambda t: t.Leaf(1))):
        before = s._health_all()
        tbl = s.b[mapname]
        d = T.fill(tbl, mk, leaf)
        h = Helper([HELPER_BIN]); h.do("openat", 2)
        during = s._health_all()
        T.drain_keys(tbl, d)
        h.do("open", 1)
        out[name] = {"dummies_to_fill": len(d), "after": show(s, h.pid),
                     "health_delta_while_full": {k: during[k] - before[k] for k in
                         ("counts_map_full", "thread_map_full", "bigram_map_full", "bigram_dropped", "pre_arm_events") }}
        h.exit()
finally:
    s.close()
json.dump(out, open(sys.argv[1], "w"), indent=2)
print(json.dumps(out, indent=2))
