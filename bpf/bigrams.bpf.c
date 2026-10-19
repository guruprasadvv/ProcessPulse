/*
 * bigrams.bpf.c — capability "bigrams" (M1b S2.3): per-process counts of
 * pairs (a, b) of consecutive observed tracked calls of one thread, where b
 * is the observed call and a the thread's previous observed call or a
 * segment-start marker. Contract: docs/telemetry-v2.md §8, S2 design (R-LOSS,
 * I-B1..I-B5, approved as A8).
 *
 * Compiled after common.h and before syscall_counter.bpf.c, which calls the
 * hooks below; requires the "counts" capability (U9). Adds no tracepoint.
 * Compile-time constants: NSYSCALLS (vocabulary size), MAX_PAIRS (capacity
 * of the bigram map).
 *
 * Codes: 0..NSYSCALLS-1 are the vocabulary syscalls (processpulse/vocab.py);
 * the markers follow. A marker is only ever written into a slot's prev, and
 * a pair is always (prev, observed call), so a marker is never the second
 * element (I-B5).
 *
 * R-LOSS, for each observed entry s of process K:
 *   row 1  no counts entry for K and none can be created: count and pair
 *          lost (H_COUNTS_FULL, H_BIGRAM_DROPPED); next prev START_LOST
 *   row 2  counted, no thread slot: pair lost (pairs_lost_K,
 *          H_BIGRAM_DROPPED; H_THREAD_FULL in thread_touch); the time is
 *          kept so the thread's next slot starts at START_LOST
 *   row 3  counted, slot ok, bigram map full: pair lost (pairs_lost_K,
 *          H_BIGRAM_FULL, H_BIGRAM_DROPPED); prev := s
 *   ok     counted, pair recorded; prev := s
 * Before arming (U2a) every entry is counted and its pair lost
 * (pairs_lost_K, H_PRE_ARM, H_BIGRAM_DROPPED); prev is not changed.
 */

#define M_START_NEW    (NSYSCALLS + 0)   /* thread started after arming */
#define M_START_ATTACH (NSYSCALLS + 1)   /* thread existed before arming */
#define M_START_LOST   (NSYSCALLS + 2)   /* a pair of this thread may have been lost */
#define M_EXEC         (NSYSCALLS + 3)   /* first call after a successful exec */

struct bkey {
    struct pkey proc;
    u16 a;                 /* previous call code or marker */
    u16 b;                 /* observed call code (< NSYSCALLS) */
    u32 pad;
};

struct bstate {
    u64 armed_boot_ns;           /* CLOCK_BOOTTIME read by userspace when arming */
    u64 last_thread_full_ns;     /* bpf_ktime_get_boot_ns() of the last slot-map-full event */
    u32 armed;
    u32 pad;
};

BPF_HASH(bigrams, struct bkey, u64, MAX_PAIRS);
BPF_ARRAY(bglobal, struct bstate, 1);

static __always_inline struct bstate *bglobal_get(void)
{
    int zero = 0;

    return bglobal.lookup(&zero);
}

/* The marker a new slot starts with (thread start times are boot-clock ns). */
static __always_inline u16 start_marker(u64 thread_start_ns)
{
    struct bstate *st = bglobal_get();

    if (st == NULL)
        return M_START_LOST;
    if (st->last_thread_full_ns != 0 && thread_start_ns < st->last_thread_full_ns)
        return M_START_LOST;
    if (st->armed && thread_start_ns >= st->armed_boot_ns)
        return M_START_NEW;
    return M_START_ATTACH;
}

/* After thread_touch(): classify a new slot, or note a full slot map (row 2). */
static __always_inline void bigram_on_slot(struct tslot *slot, int created)
{
    if (slot == NULL) {
        struct bstate *st = bglobal_get();
        if (st)
            st->last_thread_full_ns = bpf_ktime_get_boot_ns();
        return;
    }
    if (created)
        slot->prev = start_marker(slot->thread_start_ns);
}

/* Row 1: the entry was not counted, so its pair is lost too (not in pairs_lost). */
static __always_inline void bigram_count_lost(struct tslot *slot)
{
    hinc(H_BIGRAM_DROPPED);
    if (slot)
        slot->prev = M_START_LOST;
}

/* A counted entry sc of process k (rows 2, 3, ok and pre-arm). */
static __always_inline void bigram_on_entry(const struct pkey *k, struct tslot *slot, int sc,
                                            u64 *pairs_lost)
{
    struct bstate *st = bglobal_get();
    struct bkey bk = {};
    u64 zero = 0;
    u64 *n;

    if (st == NULL || !st->armed) {
        hinc(H_PRE_ARM);
        hinc(H_BIGRAM_DROPPED);
        __sync_fetch_and_add(pairs_lost, 1);
        return;
    }
    if (slot == NULL) {
        hinc(H_BIGRAM_DROPPED);
        __sync_fetch_and_add(pairs_lost, 1);
        return;
    }
    bk.proc = *k;
    bk.a = slot->prev;
    bk.b = (u16)sc;
    n = bigrams.lookup_or_try_init(&bk, &zero);
    if (n == NULL) {
        hinc(H_BIGRAM_FULL);
        hinc(H_BIGRAM_DROPPED);
        __sync_fetch_and_add(pairs_lost, 1);
    } else {
        __sync_fetch_and_add(n, 1);
    }
    slot->prev = (u16)sc;
}

/* sched_process_exec of process k, after the old TID's slot was dropped: the
 * exec'ing thread (now holding the leader's TID) continues with EXEC. Before
 * arming the slot keeps its start marker. */
static __always_inline void bigram_on_exec(const struct pkey *k)
{
    int created = 0;
    struct tslot *slot = thread_touch(k, &created);
    struct bstate *st = bglobal_get();

    bigram_on_slot(slot, created);
    if (slot && st && st->armed)
        slot->prev = M_EXEC;
}
