"""Syscall bigrams: decoding, invariant checkers and a scripted oracle (M1b S2.2).

Stdlib only; never imports BCC and needs no kernel access, so it also runs in
the Python 3.12 ML environment. Contract: docs/telemetry-v2.md §8.5-§8.6
(S2 design report; R-LOSS and I-B1..I-B5 approved as A8).

Codes. A pair (a, b) is stored in the BPF map as two codes: 0..|V|-1 are the
vocabulary syscalls in order, |V|+0..|V|+3 the markers START_NEW,
START_ATTACH, START_LOST, EXEC. Only a may be a marker (I-B5).

Results. Every checker returns a Result whose status is PASS, FAIL, or
NOT_APPLICABLE when a precondition does not hold. NOT_APPLICABLE is neither a
pass nor a failure. The per-process exact invariants hold only for a
quiescent process, and the caller must say why the process is quiescent:

    "drained"           values of the drained snapshot (probes detached,
                        maps read stably);
    "reclaimed_exited"  the last emitted values of a key reclaimed as exited
                        (two-phase reclaim: unchanged since its exit report);
    "asserted"          the caller knows the process was idle across the read
                        (a scripted helper blocked outside the vocabulary).

A live process (quiescence None) is NOT_APPLICABLE: its counts and pairs are
read one after the other while events continue, so equality is not claimed.
Pairs absent from a table count as 0; the producer leaves zero entries out
(they can be read between map insertion and increment), so an absent pair is
never evidence of loss. Loss is visible only in pairs_lost and the health
counters.
"""

from dataclasses import dataclass, field

from .snapshots import BIGRAM_MARKERS
from .vocab import VOCABULARY

PASS, FAIL, NOT_APPLICABLE = "PASS", "FAIL", "NOT_APPLICABLE"
QUIESCENCE = ("drained", "reclaimed_exited", "asserted")
U64_MAX = (1 << 64) - 1

SYSCALLS = VOCABULARY.syscalls
NAMES = SYSCALLS + BIGRAM_MARKERS                     # code -> name
CODES = {n: i for i, n in enumerate(NAMES)}
MARKER_CODES = {m: CODES[m] for m in BIGRAM_MARKERS}


class DecodeError(ValueError):
    pass


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# --- decoding ---------------------------------------------------------------------

def name_of(code):
    """Name of a pair-element code; raises DecodeError for anything else."""
    if not _is_int(code) or not 0 <= code < len(NAMES):
        raise DecodeError(f"unknown pair-element code {code!r}")
    return NAMES[code]


def code_of(name):
    if not isinstance(name, str) or name not in CODES:
        raise DecodeError(f"unknown pair-element name {name!r}")
    return CODES[name]


def decode_pair(a, b):
    """(a, b) codes -> names. b must be a vocabulary syscall (I-B5)."""
    first = name_of(a)
    second = name_of(b)
    if second not in SYSCALLS:
        raise DecodeError(f"I-B5: marker {second} as the second element of a pair")
    return first, second


def decode_entries(entries):
    """One process's raw map entries [(a_code, b_code, n)] -> ({(a, b): n}, zero_entries).

    Entries with n = 0 are dropped and counted: a map entry can be read after
    its insertion and before its first increment. They are not loss.
    """
    table, seen, zeros = {}, set(), 0
    for e in entries:
        if not isinstance(e, (tuple, list)) or len(e) != 3:
            raise DecodeError(f"malformed entry {e!r}")
        a, b, n = e
        pair = decode_pair(a, b)
        if not _is_int(n) or not 0 <= n <= U64_MAX:
            raise DecodeError(f"malformed count {n!r} for {pair}")
        if pair in seen:
            raise DecodeError(f"duplicate entry {pair}")
        seen.add(pair)
        if n == 0:
            zeros += 1
        else:
            table[pair] = n
    return table, zeros


# --- results and shared checks ---------------------------------------------------

@dataclass(frozen=True)
class Result:
    invariant: str
    status: str
    key: object = None
    reason: str = ""
    detail: dict = field(default_factory=dict)


def _table_problem(table):
    for (a, b), n in table.items():
        if a not in CODES or b not in SYSCALLS:
            return f"table breaks I-B5 or the vocabulary: ({a!r}, {b!r})"
        if not _is_int(n) or n < 0:
            return f"table has a malformed count {n!r} for ({a}, {b})"
    return None


def _pre(name, proc, table, quiescence, key, zero_loss=False):
    """The Result for an unmet precondition or a malformed table, else None."""
    if quiescence is not None and quiescence not in QUIESCENCE:
        raise ValueError(f"quiescence must be one of {QUIESCENCE} or None, not {quiescence!r}")
    problem = _table_problem(table)
    if problem:
        return Result(name, FAIL, key, problem)
    if quiescence is None:
        return Result(name, NOT_APPLICABLE, key,
                      "process not proven quiescent: a live snapshot is not atomic")
    if proc.get("pairs_lost") is None:
        return Result(name, NOT_APPLICABLE, key, "bigram capability unavailable (pairs_lost null)")
    if zero_loss and proc["pairs_lost"] != 0:
        return Result(name, NOT_APPLICABLE, key, f"pairs_lost = {proc['pairs_lost']} > 0")
    return None


def _incoming(table):
    out = dict.fromkeys(SYSCALLS, 0)
    for (_a, b), n in table.items():
        out[b] += n
    return out


def _outgoing(table):
    out = dict.fromkeys(NAMES, 0)
    for (a, _b), n in table.items():
        out[a] += n
    return out


# --- invariants -------------------------------------------------------------------

def check_ib5(table, key=None):
    """I-B5 (unconditional): names come from the vocabulary; markers only first."""
    problem = _table_problem(table)
    return Result("I-B5", FAIL if problem else PASS, key, problem or "")


def check_ib1(proc, table, quiescence=None, key=None):
    """I-B1: for each s in V, sum_x B(x, s) = C'[s]. Quiescent and pairs_lost = 0."""
    pre = _pre("I-B1", proc, table, quiescence, key, zero_loss=True)
    if pre:
        return pre
    inc = _incoming(table)
    bad = {s: [inc[s], proc["counts"][s]] for s in SYSCALLS if inc[s] != proc["counts"][s]}
    return Result("I-B1", FAIL if bad else PASS, key, "incoming pairs != counts" if bad else "",
                  {"mismatch": bad} if bad else {})


def check_ib1_prime(proc, table, quiescence=None, key=None):
    """I-B1': sum B + pairs_lost = sum_s C'[s]. Quiescent; holds with losses."""
    pre = _pre("I-B1'", proc, table, quiescence, key)
    if pre:
        return pre
    pairs, counts = sum(table.values()), sum(proc["counts"][s] for s in SYSCALLS)
    ok = pairs + proc["pairs_lost"] == counts
    return Result("I-B1'", PASS if ok else FAIL, key, "" if ok else "pairs + pairs_lost != counts",
                  {"pairs": pairs, "pairs_lost": proc["pairs_lost"], "counts": counts})


def check_ib3_prime(proc, table, quiescence=None, key=None):
    """I-B3': for x in V, sum_s B(x, s) <= C'[x]. Quiescent; holds with losses."""
    pre = _pre("I-B3'", proc, table, quiescence, key)
    if pre:
        return pre
    out = _outgoing(table)
    bad = {x: [out[x], proc["counts"][x]] for x in SYSCALLS if out[x] > proc["counts"][x]}
    return Result("I-B3'", FAIL if bad else PASS, key, "row sum > count" if bad else "",
                  {"exceeds": bad} if bad else {})


GLOBAL_LOSS_FIELDS = ("counts_map_full", "thread_map_full", "bigram_map_full", "pre_arm_events")


def loss_window(before, after):
    """Increases of the global loss counters between two readings (mappings that
    hold GLOBAL_LOSS_FIELDS, e.g. BpfCollector.global_losses())."""
    out = {f: after[f] - before[f] for f in GLOBAL_LOSS_FIELDS}
    if any(v < 0 for v in out.values()):
        raise ValueError(f"loss counters decreased: {out} (different epochs?)")
    return out


def epoch_losses(rc):
    """The global loss counters of a Reconstructor's current epoch, from its last
    applied end record: they are cumulative since the epoch's BPF load, so they
    are already epoch-relative. None without bigram health. A window that starts
    after arming (loss_window) is the tighter choice for a process spawned later:
    pre_arm_events of the epoch then never apply to it."""
    end = rc.last_ok_end
    if end is None or end.get("bigram_health") is None:
        return None
    h = end["bigram_health"]
    return {"counts_map_full": end["loss"]["counts_map_full"],
            "thread_map_full": h["thread_map_full"], "bigram_map_full": h["bigram_map_full"],
            "pre_arm_events": h["pre_arm_events"]}


def _global_losses_pre(name, losses, key):
    """Exact I-B3/I-B4 need zero losses (plan v3 D13). R-LOSS row 1 and a
    thread-map-full event leave no trace in the process's own pairs_lost (row 1
    by contract; START_LOST is given to every thread that started before the
    last slot-map-full event), so the global counters must not have risen over
    the window the claim covers."""
    if losses is None:
        return Result(name, NOT_APPLICABLE, key,
                      "global loss counters not supplied: zero losses cannot be established")
    if not hasattr(losses, "get") or any(f not in losses for f in GLOBAL_LOSS_FIELDS):
        raise ValueError(f"losses must map every one of {GLOBAL_LOSS_FIELDS}")
    if any(not _is_int(losses[f]) or losses[f] < 0 for f in GLOBAL_LOSS_FIELDS):
        raise ValueError(f"loss counter increases must be non-negative integers: {losses}")
    rose = {f: losses[f] for f in GLOBAL_LOSS_FIELDS if losses[f]}
    if rose:
        return Result(name, NOT_APPLICABLE, key, f"global losses during the window: {rose}")
    return None


def check_ib3_exact(proc, table, oracle, quiescence=None, key=None, losses=None):
    """I-B3 exact: for x in V, C'[x] - sum_s B(x, s) = number of thread segments
    whose last observed call is x. Quiescent, pairs_lost = 0, scripted ground
    truth, and no global loss over the window (losses: increases of
    GLOBAL_LOSS_FIELDS, see loss_window / epoch_losses)."""
    if oracle is None:
        return Result("I-B3", NOT_APPLICABLE, key, "no scripted ground truth")
    pre = (_pre("I-B3", proc, table, quiescence, key, zero_loss=True)
           or _global_losses_pre("I-B3", losses, key))
    if pre:
        return pre
    out = _outgoing(table)
    rest = {x: proc["counts"][x] - out[x] for x in SYSCALLS}
    bad = {x: [rest[x], oracle.segment_ends[x]] for x in SYSCALLS
           if rest[x] != oracle.segment_ends[x]}
    return Result("I-B3", FAIL if bad else PASS, key,
                  "segment ends differ from the ground truth" if bad else "",
                  {"mismatch": bad} if bad else {"ends": rest})


def check_ib4_exact(proc, table, oracle, quiescence=None, key=None, losses=None):
    """I-B4 exact: for each marker m, sum_s B(m, s) = number of non-empty thread
    segments starting with m (START_LOST: 0). Quiescent, pairs_lost = 0, ground
    truth, and no global loss over the window (as check_ib3_exact)."""
    if oracle is None:
        return Result("I-B4", NOT_APPLICABLE, key, "no scripted ground truth")
    pre = (_pre("I-B4", proc, table, quiescence, key, zero_loss=True)
           or _global_losses_pre("I-B4", losses, key))
    if pre:
        return pre
    out = _outgoing(table)
    starts = {m: out[m] for m in BIGRAM_MARKERS}
    bad = {m: [starts[m], oracle.segment_starts[m]] for m in BIGRAM_MARKERS
           if starts[m] != oracle.segment_starts[m]}
    return Result("I-B4", FAIL if bad else PASS, key,
                  "segment starts differ from the ground truth" if bad else "",
                  {"mismatch": bad} if bad else {"starts": starts})


def check_ib2_drained(rc):
    """I-B2 on the drained snapshot of a Reconstructor (processpulse.snapshots):

        sum C' + purged_counts = sum B + sum pairs_lost + purged_pairs + purged_pairs_lost

    over the live keys of the drained state and the keys reclaimed as exited
    in this epoch (their last emitted values). Keys removed as self_excluded
    are counted only through the purged_* totals, which hold what their
    entries contained when purged. Preconditions: a drained snapshot was
    applied, the state is valid, the whole epoch was observed from seq 0
    without invalidation, the capability is ok and no entry vanished.
    """
    terms = _ib2_terms("I-B2", rc)
    if isinstance(terms, Result):
        return terms
    lhs = terms["counts"] + terms["purged_counts"]
    rhs = (terms["pairs"] + terms["pairs_lost"] + terms["purged_pairs"]
           + terms["purged_pairs_lost"])
    detail = dict(terms, lhs=lhs, rhs=rhs)
    return Result("I-B2", PASS if lhs == rhs else FAIL, None,
                  "" if lhs == rhs else "global conservation broken", detail)


def check_ib2_drain_read(drain):
    """I-B2 on the collector's own drained read (BpfCollector.drain(), S2.5):

        live C' + reclaimed C' + purged_counts
            = live B + live pairs_lost + reclaimed B + reclaimed pairs_lost
              + purged_pairs + purged_pairs_lost

    The equation of check_ib2_drained, with the live terms taken from the
    stable read of the maps (every key with a counts entry) instead of an
    emitted stream, and the reclaimed terms from the collector's reclaim
    totals (the values of each key reclaimed as exited, unchanged since its
    exit report). Each key is in exactly one term: reclaim and purge delete
    the entries they account for. Preconditions: drained (detached, barrier,
    two equal reads) and the bigram capability selected. A pair entry
    without a counts entry belongs to no term, so it is a FAIL.
    """
    name = "I-B2-drain"
    if not drain or not drain.get("drained"):
        return Result(name, NOT_APPLICABLE, None, "no drained read (drain not run or not stable)")
    acc = drain.get("accounting")
    if acc is None:
        return Result(name, NOT_APPLICABLE, None, "bigram capability not selected")
    if acc["orphan_entries"]:
        return Result(name, FAIL, None,
                      f"{acc['orphan_entries']} pair entries without a counts entry "
                      f"({acc['orphan_pairs']} pairs) belong to no I-B2 term")
    rec, pur = acc["reclaimed"], acc["purged"]
    lhs = acc["counts"] + rec["counts"] + pur["counts"]
    rhs = (acc["pairs"] + acc["pairs_lost"] + rec["pairs"] + rec["pairs_lost"]
           + pur["pairs"] + pur["pairs_lost"])
    detail = {"lhs": lhs, "rhs": rhs, "keys_live": acc["keys"], "live_counts": acc["counts"],
              "live_pairs": acc["pairs"], "live_pairs_lost": acc["pairs_lost"],
              "reclaimed": dict(rec), "purged": dict(pur)}
    return Result(name, PASS if lhs == rhs else FAIL, None,
                  "" if lhs == rhs else "global conservation broken", detail)


def check_ib2_ground_truth(rc, observed_entries):
    """I-B2 against independent ground truth (the v2 §4 form of I-B2):

        sum C' + purged_counts + counts_map_full = observed entries
            = sum B + sum pairs_lost + purged_pairs + purged_pairs_lost + counts_map_full

    observed_entries is the number of tracked-syscall entries the scripted
    workload made after arming in every tracked process, counted by the
    script itself (never from the collector's own counters). counts_map_full
    holds the R-LOSS row 1 events (no counts entry: count and pair both lost).
    Unlike check_ib2_drained, this detects a process that is missing or
    counted twice even when its own values balance. Same preconditions as
    check_ib2_drained; only meaningful when observed_entries is truly known
    (a run whose only tracked processes are scripted helpers).
    """
    if not _is_int(observed_entries) or observed_entries < 0:
        raise ValueError(f"observed_entries must be a non-negative integer, not {observed_entries!r}")
    terms = _ib2_terms("I-B2-GT", rc)
    if isinstance(terms, Result):
        return terms
    l_c = rc.last_ok_end["loss"]["counts_map_full"]
    counts_side = terms["counts"] + terms["purged_counts"] + l_c
    pairs_side = (terms["pairs"] + terms["pairs_lost"] + terms["purged_pairs"]
                  + terms["purged_pairs_lost"] + l_c)
    ok = counts_side == observed_entries == pairs_side
    detail = dict(terms, counts_map_full=l_c, counts_side=counts_side, pairs_side=pairs_side,
                  observed_entries=observed_entries)
    return Result("I-B2-GT", PASS if ok else FAIL, None,
                  "" if ok else "totals differ from the ground truth", detail)


def check_ib2_ground_truth_scope(processes, observed_entries, quiescence, losses, purged=None):
    """The ground-truth form of I-B2 over a closed scope of scripted processes:

        sum C' + purged_counts = observed entries
            = sum B + sum pairs_lost + purged_pairs + purged_pairs_lost

    processes: [(proc, table)] for every process of the scope that still has
    an entry (live or exited, all quiescent); purged: the increases of the
    collector's purge totals caused by the scope's purged processes (None:
    none were purged); observed_entries: the tracked-syscall entries the
    scope's processes made while the program was attached, counted by the
    script, never by the collector. R-LOSS row 1 events cannot be attributed
    to a scope, so counts_map_full must not have risen (losses); thread-map,
    bigram-map and pre-arm losses are in pairs_lost and allowed.

    This is check_ib2_ground_truth restricted to a scope whose final values are
    known without the drained snapshot (S2.5); the whole-epoch form still
    needs the drain.
    """
    name = "I-B2-GT-scope"
    if not _is_int(observed_entries) or observed_entries < 0:
        raise ValueError(f"observed_entries must be a non-negative integer, not {observed_entries!r}")
    if quiescence is not None and quiescence not in QUIESCENCE:
        raise ValueError(f"quiescence must be one of {QUIESCENCE} or None, not {quiescence!r}")
    if quiescence is None:
        return Result(name, NOT_APPLICABLE, None, "scope not proven quiescent")
    if losses is None:
        return Result(name, NOT_APPLICABLE, None, "global loss counters not supplied")
    if losses.get("counts_map_full"):
        return Result(name, NOT_APPLICABLE, None,
                      f"counts_map_full rose by {losses['counts_map_full']}: row-1 losses "
                      "cannot be attributed to the scope")
    pur = {"counts": 0, "pairs": 0, "pairs_lost": 0}
    if purged is not None:
        pur.update({k: purged[k] for k in pur})
    counts = pairs = lost = 0
    for p, t in processes:
        if p.get("pairs_lost") is None:
            return Result(name, NOT_APPLICABLE, None, "bigram capability unavailable")
        problem = _table_problem(t)
        if problem:
            return Result(name, FAIL, None, problem)
        counts += sum(p["counts"][s] for s in SYSCALLS)
        pairs += sum(t.values())
        lost += p["pairs_lost"]
    counts_side = counts + pur["counts"]
    pairs_side = pairs + lost + pur["pairs"] + pur["pairs_lost"]
    ok = counts_side == observed_entries == pairs_side
    return Result(name, PASS if ok else FAIL, None, "" if ok else "totals differ from the ground truth",
                  {"counts_side": counts_side, "pairs_side": pairs_side,
                   "observed_entries": observed_entries, "processes": len(processes),
                   "purged": pur, "pairs_lost": lost})


def _ib2_terms(name, rc):
    """The I-B2 sums of a drained Reconstructor, or the Result of an unmet precondition."""
    view = rc.last
    if view is None or view.status != "ok" or not view.drained:
        return Result(name, NOT_APPLICABLE, None, "no drained snapshot applied")
    if not rc.valid:
        return Result(name, NOT_APPLICABLE, None, "reconstructed state is invalid")
    if not rc.epoch_intact:
        return Result(name, NOT_APPLICABLE, None,
                      "the epoch was not observed whole from seq 0 without invalidation")
    end = rc.last_ok_end
    health = end.get("bigram_health") if end else None
    if health is None:
        return Result(name, NOT_APPLICABLE, None, "bigram capability unavailable or not selected")
    vanished = sum(1 for r in rc.retired.values() if r["reason"] == "vanished")
    if vanished or end["loss"]["vanished_entries"]:
        return Result(name, NOT_APPLICABLE, None,
                      "vanished entries: their final values are unknown")
    rows = [(kt, p, rc.pairs.get(kt)) for kt, p in rc.state.items()]
    reclaimed = [(kt, r["proc"], r["pairs"]) for kt, r in rc.retired.items()
                 if r["reason"] == "exited"]
    counts = pairs = lost = 0
    for kt, p, t in rows + reclaimed:
        if p.get("pairs_lost") is None or t is None:
            return Result(name, NOT_APPLICABLE, None, f"key {kt} has no bigram values")
        problem = _table_problem(t)
        if problem:
            return Result(name, FAIL, kt, problem)
        counts += sum(p["counts"][s] for s in SYSCALLS)
        pairs += sum(t.values())
        lost += p["pairs_lost"]
    return {"counts": counts, "purged_counts": health["purged_counts"], "pairs": pairs,
            "pairs_lost": lost, "purged_pairs": health["purged_pairs"],
            "purged_pairs_lost": health["purged_pairs_lost"],
            "keys_live": len(rows), "keys_reclaimed_exited": len(reclaimed)}


def check_quiescent_reports(rc):
    """I-B5, I-B1', I-B3' and I-B1 for every process whose values are final:
    keys reclaimed as exited in this epoch and, after a drained snapshot with a
    valid state, every live key. Live processes before the drain are skipped."""
    subjects = []
    for kt, r in rc.retired.items():
        if r["reason"] != "exited":
            continue                   # self_excluded: in I-B2 via purged_*; vanished: unknown
        basis = "reclaimed_exited" if r["proc"].get("exited") else None
        subjects.append((kt, r["proc"], r["pairs"] or {}, basis,
                         None if basis else "reclaimed as exited but its last record is not "
                                            "marked exited; final values not proven"))
    if rc.valid and rc.last is not None and rc.last.drained:
        subjects += [(kt, p, rc.pairs.get(kt, {}), "drained", None) for kt, p in rc.state.items()]
    out = []
    for kt, p, t, basis, why in subjects:
        out.append(check_ib5(t, kt))
        for check in (check_ib1_prime, check_ib3_prime, check_ib1):
            r = check(p, t, basis, kt)
            if why and r.status == NOT_APPLICABLE:
                r = Result(r.invariant, NOT_APPLICABLE, kt, why)
            out.append(r)
    return out


# --- scripted oracle ----------------------------------------------------------------

@dataclass(frozen=True)
class Oracle:
    pairs: dict                  # {(a, b): n} expected pair table
    counts: dict                 # {s: n} expected counts for every s in V
    segment_starts: dict         # marker -> non-empty segments starting with it
    segment_ends: dict           # s -> non-empty segments whose last call is s


def expected_pairs(script):
    """Expected pair table of one process from a scripted, loss-free lifecycle.

    Steps (thread ids are labels, never kernel TIDs):
        ("thread", t, "attach")  t existed before arming (START_ATTACH)
        ("thread", t, "new")     t started after arming (START_NEW)
        ("call", t, s)           t made an observed call s in V
        ("exec", t)              successful exec by t: every other thread ends,
                                 t continues with prev = EXEC
        ("exit", t)              t exits
    A segment runs from its marker to exit, exec or the end of the script.
    Rules: a thread id is declared before use; a reused id is a new thread
    ("new"); nothing can be "attach" after an exec. Losses are not modelled:
    an oracle is only ground truth for a run with pairs_lost = 0.
    """
    if not isinstance(script, (list, tuple)):
        raise ValueError("script must be a list of steps")
    pairs, counts = {}, dict.fromkeys(SYSCALLS, 0)
    starts, ends = dict.fromkeys(BIGRAM_MARKERS, 0), dict.fromkeys(SYSCALLS, 0)
    live, seen, execd = {}, set(), False   # t -> [marker, prev or None]

    def close(t):
        marker, prev = live.pop(t)
        if prev is not None:
            starts[marker] += 1
            ends[prev] += 1

    for step in script:
        if not isinstance(step, (list, tuple)) or len(step) not in (2, 3):
            raise ValueError(f"malformed step {step!r}")
        op, t = step[0], step[1]
        if op == "thread":
            kind = step[2] if len(step) == 3 else None
            if kind not in ("attach", "new"):
                raise ValueError(f"thread kind must be attach or new: {step!r}")
            if t in live:
                raise ValueError(f"thread {t!r} declared while live")
            if kind == "attach" and (t in seen or execd):
                raise ValueError(f"thread {t!r} cannot have existed before arming")
            live[t] = ["START_ATTACH" if kind == "attach" else "START_NEW", None]
            seen.add(t)
        elif op in ("call", "exec", "exit"):
            if t not in live:
                raise ValueError(f"step on a thread that is not live: {step!r}")
            if op == "call":
                s = step[2] if len(step) == 3 else None
                if s not in SYSCALLS:
                    raise ValueError(f"call outside the vocabulary: {step!r}")
                st = live[t]
                a = st[1] if st[1] is not None else st[0]
                pairs[(a, s)] = pairs.get((a, s), 0) + 1
                counts[s] += 1
                st[1] = s
            elif op == "exec":
                for other in [o for o in live if o != t]:
                    close(other)
                close(t)
                live[t] = ["EXEC", None]
                execd = True
            else:
                close(t)
        else:
            raise ValueError(f"unknown step {step!r}")
    for t in list(live):
        close(t)
    return Oracle(pairs, counts, starts, ends)
