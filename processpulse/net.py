"""Network capability (M1b S3.1/S3.2): decoding and accounting checkers.

Stdlib only (never imports BCC), so it also runs in the Python 3.12 ML
environment. Contract: docs/m1b-s3-network-plan.md (decisions N1-N10) and
docs/telemetry-v2.md §9. S3.2 covers connect() and accept()/accept4(); byte
and send/receive counters are S3.3.

Raw map entries. netc (bpf/net.bpf.c) is keyed by (process, class code) and
holds, in this order: entry[connect, accept, accept4], connect_ok,
connect_pending, connect_refused, connect_err, accept_ok, accept_err,
dest[loopback, private, link_local, special, public, unknown]. entry[] is
counted only in the "unknown" entry (the class is not known at entry, plan
§4); dest[] only in IP classes.

Decoded per-process object (bpf_proc.net):
    {"classes": {class: {result: n, ..., "dest": {dest: n}}},   # sparse classes
     "entry_observed": {"connect": n, "accept": n, "accept4": n}}
A class that recorded nothing is absent (capability ok: absent = 0 observed).
"dest" is present only in IP classes.

Checkers return bigrams.Result (PASS / FAIL / NOT_APPLICABLE). Accounting
terms ("terms") are built by BpfCollector.drain() (collector side) or by
terms_from_stream() (an emitted, reconstructed stream).
"""

from .bigrams import FAIL, NOT_APPLICABLE, PASS, Result
from .vocab import (NET_CLASSES, NET_DEST_CLASSES, NET_HOOK_FIELDS, NET_IP_CLASSES, NET_RESULTS,
                    NET_SYSCALLS)

U64 = 1 << 64
RAW_FIELDS = (tuple(f"entry_{s}" for s in NET_SYSCALLS) + NET_RESULTS
              + tuple(f"dest_{d}" for d in NET_DEST_CLASSES))
CONNECT_RESULTS = NET_RESULTS[:4]
ACCEPT_RESULTS = NET_RESULTS[4:]
# Userspace terms kept per syscall next to the BPF hook counters.
HOOK_EXTRA = ("purged_entry", "purged_results", "purged_stash", "stash_live")
HOOK_KEYS = NET_HOOK_FIELDS + HOOK_EXTRA


class NetDecodeError(ValueError):
    pass


def _is_count(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < U64


def decode_entries(entries):
    """One process's raw entries [(class_code, values)] -> its net object.

    values is the RAW_FIELDS tuple. Raises NetDecodeError for an unknown class
    code, a duplicate class, entry counts outside the "unknown" entry, or
    destination counts outside an IP class (all impossible for net.bpf.c)."""
    out = {"classes": {}, "entry_observed": dict.fromkeys(NET_SYSCALLS, 0)}
    seen = set()
    for code, values in entries:
        if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code < len(NET_CLASSES):
            raise NetDecodeError(f"unknown net class code {code!r}")
        if code in seen:
            raise NetDecodeError(f"duplicate net class {NET_CLASSES[code]}")
        seen.add(code)
        if len(values) != len(RAW_FIELDS) or not all(_is_count(v) for v in values):
            raise NetDecodeError(f"malformed net values {values!r}")
        cls = NET_CLASSES[code]
        raw = dict(zip(RAW_FIELDS, values))
        entries_ = {s: raw[f"entry_{s}"] for s in NET_SYSCALLS}
        if cls == "unknown":
            out["entry_observed"] = entries_
        elif any(entries_.values()):
            raise NetDecodeError(f"entry counts in class {cls}")
        dest = {d: raw[f"dest_{d}"] for d in NET_DEST_CLASSES}
        if cls not in NET_IP_CLASSES and any(dest.values()):
            raise NetDecodeError(f"destination counts in non-IP class {cls}")
        counters = {r: raw[r] for r in NET_RESULTS}
        if any(counters.values()) or any(dest.values()):
            if cls in NET_IP_CLASSES:
                counters["dest"] = dest
            out["classes"][cls] = counters
    out["classes"] = {c: out["classes"][c] for c in NET_CLASSES if c in out["classes"]}
    return out


def empty_net():
    return {"classes": {}, "entry_observed": dict.fromkeys(NET_SYSCALLS, 0)}


def merge(a, b):
    """The sum of two net objects (sparse, canonical class order)."""
    out = empty_net()
    for sc in NET_SYSCALLS:
        out["entry_observed"][sc] = a["entry_observed"][sc] + b["entry_observed"][sc]
    for cls in NET_CLASSES:
        x, y = a["classes"].get(cls), b["classes"].get(cls)
        if x is None and y is None:
            continue
        x = x or {}
        y = y or {}
        c = {r: x.get(r, 0) + y.get(r, 0) for r in NET_RESULTS}
        if cls in NET_IP_CLASSES:
            c["dest"] = {d: x.get("dest", {}).get(d, 0) + y.get("dest", {}).get(d, 0)
                         for d in NET_DEST_CLASSES}
        out["classes"][cls] = c
    return out


def sums(net):
    """(entry_observed per syscall, connect results, accept results) of one object."""
    entries = dict(net["entry_observed"])
    connect = sum(c[r] for c in net["classes"].values() for r in CONNECT_RESULTS)
    accept = sum(c[r] for c in net["classes"].values() for r in ACCEPT_RESULTS)
    return entries, connect, accept


def totals(nets):
    """totals.net of the emitted state: {entries, results}, mod 2^64."""
    e = r = 0
    for n in nets:
        if n is None:
            continue
        entries, connect, accept = sums(n)
        e += sum(entries.values())
        r += connect + accept
    return {"entries": e % U64, "results": r % U64}


# --- invariants -------------------------------------------------------------------

def check_in1(net, key=None):
    """I-N1, class exclusivity: every recorded event is in exactly one class.
    Checks that every class name is known; that local IPC, other and unknown
    classes carry no destination (so local IPC never counts as IP traffic); and
    that every matched connect exit on an IP socket is in exactly one
    destination class (sum of dest = sum of connect results, per IP class)."""
    if net is None:
        return Result("I-N1", NOT_APPLICABLE, key, "net capability unavailable")
    for cls, c in net["classes"].items():
        if cls not in NET_CLASSES:
            return Result("I-N1", FAIL, key, f"unknown class {cls!r}")
        if cls in NET_IP_CLASSES:
            if set(c.get("dest", {})) != set(NET_DEST_CLASSES):
                return Result("I-N1", FAIL, key, f"{cls}: destination classes incomplete")
            if sum(c["dest"].values()) != sum(c[r] for r in CONNECT_RESULTS):
                return Result("I-N1", FAIL, key, f"{cls}: destinations != connect results",
                              {"dest": c["dest"]})
        elif "dest" in c:
            return Result("I-N1", FAIL, key, f"non-IP class {cls} carries destinations")
    return Result("I-N1", PASS, key)


def check_in2(terms):
    """I-N2, event conservation per hook (plan §5): for every attached hook,
    events seen = events recorded (live + reclaimed keys) + unresolved +
    self-excluded + dropped + purged. S3.2's hooks are the connect/accept
    syscall entries and exits (the socket hooks come in S3.3); an exit that
    finds no stashed entry is counted in exit_without_entry, and accept and
    accept4 exits are pooled because their results are pooled. Only exact on a
    drained read (terms["drained"])."""
    if terms is None or not terms.get("drained"):
        return Result("I-N2", NOT_APPLICABLE, None, "no drained read or snapshot")
    if terms.get("orphan_entries"):
        return Result("I-N2", FAIL, None, f"{terms['orphan_entries']} net entries without a "
                                          "counts entry belong to no term")
    h, rec = terms["hooks"], terms["recorded"]
    bad, detail = [], {}
    for sc in NET_SYSCALLS:
        x = h[sc]
        lhs = x["seen_enter"]
        rhs = (rec["entry"][sc] + x["unresolved_enter"] + x["excluded_enter"]
               + x["dropped_enter"] + x["purged_entry"])
        detail[f"enter_{sc}"] = [lhs, rhs]
        if lhs != rhs:
            bad.append(f"enter_{sc}")

    def exit_side(scs, recorded):
        lhs = sum(h[s]["seen_exit"] for s in scs)
        rhs = recorded + sum(h[s]["unresolved_exit"] + h[s]["excluded_exit"] + h[s]["dropped_exit"]
                             + h[s]["exit_without_entry"] + h[s]["purged_results"] for s in scs)
        return lhs, rhs
    for name, scs, recorded in (("exit_connect", ("connect",), rec["connect_results"]),
                                ("exit_accept", ("accept", "accept4"), rec["accept_results"])):
        lhs, rhs = exit_side(scs, recorded)
        detail[name] = [lhs, rhs]
        if lhs != rhs:
            bad.append(name)
    return Result("I-N2", FAIL if bad else PASS, None,
                  f"conservation broken: {bad}" if bad else "", detail)


def check_in3(terms=None):
    """I-N3, byte conservation: needs the byte counters of S3.3."""
    return Result("I-N3", NOT_APPLICABLE, None, "no byte counters before S3.3")


def check_in4(terms):
    """I-N4, stash balance per stashed syscall (plan §5): entries that reached
    the stash = matched exits + stash_full + stash_overwrite + stash_orphaned +
    entries purged with their process + entries left at the drain. The purge
    term is the stash part of the purge accounting (P-PURGE). Drained only."""
    if terms is None or not terms.get("drained"):
        return Result("I-N4", NOT_APPLICABLE, None, "no drained read or snapshot")
    bad, detail = [], {}
    for sc in NET_SYSCALLS:
        x = terms["hooks"][sc]
        lhs = x["stash_entries"]
        rhs = (x["matched"] + x["stash_full"] + x["stash_overwrite"] + x["stash_orphaned"]
               + x["purged_stash"] + x["stash_live"])
        detail[sc] = [lhs, rhs]
        if lhs != rhs:
            bad.append(sc)
    return Result("I-N4", FAIL if bad else PASS, None,
                  f"stash balance broken: {bad}" if bad else "", detail)


def check_in5(net=None, key=None):
    """I-N5, partial-send bounds: needs the sendto counters of S3.3."""
    return Result("I-N5", NOT_APPLICABLE, key, "no sendto counters before S3.3")


def check_in6(net, expected, key=None, losses=None):
    """I-N6, scripted ground truth: the process's net object equals the one the
    script implies, exactly. losses: the increases of the hook loss counters
    over the script's window; any rise makes the check NOT_APPLICABLE."""
    if net is None:
        return Result("I-N6", NOT_APPLICABLE, key, "net capability unavailable")
    if losses is None:
        return Result("I-N6", NOT_APPLICABLE, key, "loss counters not supplied")
    rose = {k: v for k, v in losses.items() if v}
    if rose:
        return Result("I-N6", NOT_APPLICABLE, key, f"losses during the window: {rose}")
    ok = net == expected
    return Result("I-N6", PASS if ok else FAIL, key, "" if ok else "differs from the script",
                  {} if ok else {"observed": net, "expected": expected})


# Losses that can affect a resolvable process's values. unresolved_* are events
# of tasks outside the distro pid namespace and can never belong to one.
LOSS_FIELDS = ("dropped_enter", "dropped_exit", "stash_full", "stash_overwrite",
               "stash_orphaned", "exit_without_entry")


def loss_window(before, after):
    """Increases of the per-hook loss counters (and net_map_full) between two
    net_health() readings."""
    out = {f"{sc}.{f}": after["hooks"][sc][f] - before["hooks"][sc][f]
           for sc in NET_SYSCALLS for f in LOSS_FIELDS}
    out["net_map_full"] = after["net_map_full"] - before["net_map_full"]
    if any(v < 0 for v in out.values()):
        raise ValueError(f"loss counters decreased: {out}")
    return out


def expected_net(script):
    """The net object of one process from a scripted list of
    ("connect", class, dest, result) and ("accept"|"accept4", class, result)
    steps, every one observed (entry and matched exit). Results are the
    NET_RESULTS names."""
    out = empty_net()
    for step in script:
        op = step[0]
        if op not in NET_SYSCALLS:
            raise ValueError(f"unknown step {step!r}")
        out["entry_observed"][op] += 1
        cls = step[1]
        if cls not in NET_CLASSES:
            raise ValueError(f"unknown class in {step!r}")
        c = out["classes"].setdefault(cls, dict.fromkeys(NET_RESULTS, 0))
        if cls in NET_IP_CLASSES:
            c.setdefault("dest", dict.fromkeys(NET_DEST_CLASSES, 0))
        if op == "connect":
            dest, result = step[2], step[3]
            if result not in CONNECT_RESULTS:
                raise ValueError(f"bad connect result in {step!r}")
            if cls in NET_IP_CLASSES:
                if dest not in NET_DEST_CLASSES:
                    raise ValueError(f"bad destination in {step!r}")
                c["dest"][dest] += 1
            elif dest is not None:
                raise ValueError(f"destination for a non-IP class in {step!r}")
        else:
            result = step[2]
            if result not in ACCEPT_RESULTS:
                raise ValueError(f"bad accept result in {step!r}")
        c[result] += 1
    out["classes"] = {c: out["classes"][c] for c in NET_CLASSES if c in out["classes"]}
    return out


# --- terms from an emitted stream ------------------------------------------------------

def terms_from_stream(rc):
    """I-N2/I-N4 terms of a Reconstructor whose drained snapshot was applied:
    recorded = live keys of the drained state + keys reclaimed as exited (their
    last emitted values); hook, purge and stash terms from the drained end
    record's net_health. Keys removed as self_excluded count only through the
    purge terms. None when a precondition is unmet."""
    view = rc.last
    if view is None or view.status != "ok" or not view.drained or not rc.valid:
        return None
    if not rc.epoch_intact:
        return None
    end = rc.last_ok_end
    nh = end.get("net_health") if end else None
    if nh is None:
        return None
    if any(r["reason"] == "vanished" for r in rc.retired.values()):
        return None
    nets = [p.get("net") for p in rc.state.values()]
    nets += [r["proc"].get("net") for r in rc.retired.values() if r["reason"] == "exited"]
    if any(n is None for n in nets):
        return None
    rec = {"entry": dict.fromkeys(NET_SYSCALLS, 0), "connect_results": 0, "accept_results": 0}
    for n in nets:
        entries, connect, accept = sums(n)
        for sc in NET_SYSCALLS:
            rec["entry"][sc] += entries[sc]
        rec["connect_results"] += connect
        rec["accept_results"] += accept
    return {"drained": True, "recorded": rec, "hooks": nh["hooks"],
            "net_map_full": nh["net_map_full"]}
