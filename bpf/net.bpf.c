/*
 * net.bpf.c — capability "net" (M1b S3.1/S3.2): connect() and accept()/accept4()
 * tracking per process, in a sparse (process, class) map netc. Contract:
 * docs/m1b-s3-network-plan.md (N1–N10) and docs/bpf-collector.md "Network".
 *
 * Compiled after common.h and syscall_counter.bpf.c (a network event creates
 * the process's counts and info entries, so a network-only process is
 * reported, N3) and before core.bpf.c (the thread-exit hook). Requires the
 * "counts" capability. Compile-time constants: MAX_NET (net map), MAX_NET_STASH
 * (per-thread stash).
 *
 * Hooks (tracepoints only, N2): syscalls:sys_{enter,exit}_{connect,accept,accept4}.
 * The tracepoints carry fd / sockaddr pointer / addrlen at entry and ret at
 * exit, but not the socket's family or protocol. The class is therefore read
 * from the socket object behind the fd (task->files fdtable -> file -> socket
 * -> sock), a kernel-memory read inside the tracepoint like resolve(); a fd
 * that is not a socket or cannot be read gives class "unknown".
 *
 * Privacy: a connect()'s destination address is read from user memory into a
 * local variable only to compute a coarse destination class (ND_*); ports are
 * never read; only class codes are stored.
 *
 * R-NLOSS, for every hook invocation (counters in nhealth, per syscall):
 *   1. seen_*            first, before any lookup;
 *   2. unresolved_*      identity unresolved: stop, never attributed;
 *   3. excluded_*        our own collectors: stop;
 *   4. dropped_* + net_map_full  counts/info/net entry cannot be created: stop;
 *   entry: stash_entries, then stash_full (no slot), stash_overwrite (an
 *          entry of the same thread was still there), stash_orphaned (an
 *          entry of a dead thread with the same TID was still there);
 *   exit:  exit_without_entry (no matching entry), else matched, then the
 *          result is recorded (or dropped, rule 4).
 * Thread exit deletes the thread's entry (stash_orphaned).
 */

/* BCC 0.35's bundled uapi linux/bpf.h predates struct bpf_task_work, which the
 * 6.18 kernel's internal linux/bpf.h (pulled in by net/sock.h) takes the size
 * of in an inline helper. The definition below is copied from the running
 * kernel's uapi header (tag linux-msft-wsl-6.18.33.2, include/uapi/linux/bpf.h);
 * this program never uses the type. */
struct bpf_task_work {
    __u64 __opaque;
} __attribute__((aligned(8)));

#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>

/* Classes: processpulse/vocab.py NET_CLASSES (same order). */
#define NC_INET4_TCP   0
#define NC_INET4_UDP   1
#define NC_INET4_OTHER 2
#define NC_INET6_TCP   3
#define NC_INET6_UDP   4
#define NC_INET6_OTHER 5
#define NC_LOCAL_IPC   6
#define NC_OTHER       7
#define NC_UNKNOWN     8
#define NC_IP_LAST     NC_INET6_OTHER

/* Destination classes: vocab.py NET_DEST_CLASSES. */
#define ND_LOOPBACK   0
#define ND_PRIVATE    1
#define ND_LINK_LOCAL 2
#define ND_SPECIAL    3
#define ND_PUBLIC     4
#define ND_UNKNOWN    5
#define NDEST         6
#define ND_NONE       0xffff          /* not counted: no IP socket, or not a connect */

/* Stashed syscalls: vocab.py NET_SYSCALLS. */
#define NS_CONNECT 0
#define NS_ACCEPT  1
#define NS_ACCEPT4 2
#define NSC        3

/* nhealth fields per syscall: vocab.py NET_HOOK_FIELDS. */
#define NH_SEEN_ENTER          0
#define NH_SEEN_EXIT           1
#define NH_UNRESOLVED_ENTER    2
#define NH_UNRESOLVED_EXIT     3
#define NH_EXCLUDED_ENTER      4
#define NH_EXCLUDED_EXIT       5
#define NH_DROPPED_ENTER       6
#define NH_DROPPED_EXIT        7
#define NH_STASH_ENTRIES       8
#define NH_MATCHED             9
#define NH_STASH_FULL         10
#define NH_STASH_OVERWRITE    11
#define NH_STASH_ORPHANED     12
#define NH_EXIT_WITHOUT_ENTRY 13
#define NHF                   14
#define NH_MAP_FULL     (NSC * NHF)   /* a counts/info/net entry could not be created */
#define NNHEALTH        (NSC * NHF + 1)

#define S_IFMT_   00170000
#define S_IFSOCK_ 0140000

struct nkey {
    struct pkey proc;
    u16 cls;
    u16 pad1;
    u32 pad2;
};

/* Cumulative per (process, class). entry[] is used only in the NC_UNKNOWN
 * entry (the class is not known when it is counted, plan §4). */
struct ncnt {
    u64 entry[NSC];
    u64 connect_ok;
    u64 connect_pending;
    u64 connect_refused;
    u64 connect_err;
    u64 accept_ok;            /* accept and accept4 */
    u64 accept_err;
    u64 dest[NDEST];          /* matched connect exits by destination class (IP classes) */
};

struct nstash {
    u64 thread_start_ns;      /* detects a reused host TID */
    struct pkey proc;
    u16 sc;
    u16 cls;
    u16 dest;
    u16 pad;
};

BPF_HASH(netc, struct nkey, struct ncnt, MAX_NET);
BPF_HASH(net_stash, u32, struct nstash, MAX_NET_STASH);
BPF_ARRAY(nhealth, u64, NNHEALTH);

static __always_inline void nhinc(u32 sc, u32 field)
{
    int i = sc * NHF + field;
    u64 *v;

    if (sc >= NSC)
        return;
    v = nhealth.lookup(&i);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline void nh_map_full(void)
{
    int i = NH_MAP_FULL;
    u64 *v = nhealth.lookup(&i);

    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline u16 net_class(u16 family, u16 protocol)
{
    if (family == AF_INET)
        return protocol == IPPROTO_TCP ? NC_INET4_TCP :
               protocol == IPPROTO_UDP ? NC_INET4_UDP : NC_INET4_OTHER;
    if (family == AF_INET6)
        return protocol == IPPROTO_TCP ? NC_INET6_TCP :
               protocol == IPPROTO_UDP ? NC_INET6_UDP : NC_INET6_OTHER;
    if (family == AF_UNIX || family == AF_NETLINK || family == AF_VSOCK)
        return NC_LOCAL_IPC;
    return NC_OTHER;
}

/* The class of the socket behind fd in the current task, or NC_UNKNOWN when fd
 * is not an open socket or a read fails (programs run under rcu_read_lock()). */
static __always_inline u16 net_class_of_fd(int fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **fds = NULL;
    struct file *f = NULL;
    struct inode *ino = NULL;
    struct socket *sock = NULL;
    struct sock *sk = NULL;
    unsigned int max_fds = 0;
    umode_t mode = 0;
    u16 family = 0, protocol = 0;

    if (fd < 0)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&files, sizeof(files), &task->files) || files == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt) || fdt == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&max_fds, sizeof(max_fds), &fdt->max_fds) || (u32)fd >= max_fds)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&fds, sizeof(fds), &fdt->fd) || fds == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || f == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&ino, sizeof(ino), &f->f_inode) || ino == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&mode, sizeof(mode), &ino->i_mode) || (mode & S_IFMT_) != S_IFSOCK_)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&sock, sizeof(sock), &f->private_data) || sock == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) || sk == NULL)
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family))
        return NC_UNKNOWN;
    if (bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol))
        return NC_UNKNOWN;
    return net_class(family, protocol);
}

/* Coarse class of an IPv4 address in host byte order. */
static __always_inline u16 dest4(u32 h)
{
    u32 top = h >> 24;

    if (top == 127)
        return ND_LOOPBACK;
    if (top == 10 || (h & 0xfff00000) == 0xac100000 || (h & 0xffff0000) == 0xc0a80000)
        return ND_PRIVATE;
    if ((h & 0xffff0000) == 0xa9fe0000)
        return ND_LINK_LOCAL;
    if (top == 0 || (h >> 28) == 0xe || (h >> 28) == 0xf)
        return ND_SPECIAL;
    return ND_PUBLIC;
}

/* Coarse class of an IPv6 address (network byte order bytes). */
static __always_inline u16 dest6(const u8 *a)
{
    u32 w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    u32 v4 = 0;

    w0 = ((u32)a[0] << 24) | ((u32)a[1] << 16) | ((u32)a[2] << 8) | a[3];
    w1 = ((u32)a[4] << 24) | ((u32)a[5] << 16) | ((u32)a[6] << 8) | a[7];
    w2 = ((u32)a[8] << 24) | ((u32)a[9] << 16) | ((u32)a[10] << 8) | a[11];
    w3 = ((u32)a[12] << 24) | ((u32)a[13] << 16) | ((u32)a[14] << 8) | a[15];
    if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1)
        return ND_LOOPBACK;                       /* ::1 */
    if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0)
        return ND_SPECIAL;                        /* :: */
    if (w0 == 0 && w1 == 0 && w2 == 0x0000ffff) {
        v4 = w3;                                  /* ::ffff:a.b.c.d */
        return dest4(v4);
    }
    if (a[0] == 0xff)
        return ND_SPECIAL;                        /* multicast */
    if ((a[0] & 0xfe) == 0xfc)
        return ND_PRIVATE;                        /* fc00::/7 */
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
        return ND_LINK_LOCAL;                     /* fe80::/10 */
    return ND_PUBLIC;
}

/* Destination class of a connect() sockaddr in user memory. Only the family
 * and the address bytes are read, never the port. */
static __always_inline u16 net_dest(const void *ua, int addrlen)
{
    u16 fam = 0;
    u32 a4 = 0;
    u8 a6[16] = {};

    if (ua == NULL || addrlen < 2 || bpf_probe_read_user(&fam, sizeof(fam), ua))
        return ND_UNKNOWN;
    if (fam == AF_INET) {
        if (addrlen < 8 || bpf_probe_read_user(&a4, sizeof(a4), ua + 4))
            return ND_UNKNOWN;
        return dest4(__builtin_bswap32(a4));
    }
    if (fam == AF_INET6) {
        if (addrlen < 24 || bpf_probe_read_user(a6, sizeof(a6), ua + 8))
            return ND_UNKNOWN;
        return dest6(a6);
    }
    return ND_UNKNOWN;
}

/* Ensures k has its counts and info entries (N3), then returns its net entry
 * for cls, or NULL when an entry cannot be created (R-NLOSS rule 4). */
static __always_inline struct ncnt *net_entry(struct pkey *k, u16 cls, u32 level, u32 cpid)
{
    struct pcounts czero = {};
    struct ncnt nzero = {};
    struct nkey nk = {};
    struct pinfo *pi;

    if (counts.lookup_or_try_init(k, &czero) == NULL)
        return NULL;
    pi = info.lookup(k);
    if (pi == NULL) {
        struct pinfo ni = {};
        ni.cgroup_id = bpf_get_current_cgroup_id();
        ni.last_ktime = bpf_ktime_get_ns();
        ni.host_tgid = bpf_get_current_pid_tgid() >> 32;
        ni.level = level;
        ni.container_pid = cpid;
        bpf_get_current_comm(&ni.comm, sizeof(ni.comm));
        if (info.insert(k, &ni) != 0 && info.lookup(k) == NULL)
            return NULL;
    }
    nk.proc = *k;
    nk.cls = cls;
    return netc.lookup_or_try_init(&nk, &nzero);
}

static __always_inline u64 cur_thread_start(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 start = 0;

    bpf_probe_read_kernel(&start, sizeof(start), &task->start_boottime);
    return start;
}

static __always_inline int net_enter(u32 sc, int fd, const void *ua, int addrlen)
{
    struct pkey k = {};
    struct nstash s = {};
    struct nstash *old;
    struct ncnt *n;
    u32 level = 0, cpid = 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();

    nhinc(sc, NH_SEEN_ENTER);
    if (resolve(&k, &level, &cpid) != 0) {
        nhinc(sc, NH_UNRESOLVED_ENTER);
        return 0;
    }
    if (excluded.lookup(&k.tgid)) {
        nhinc(sc, NH_EXCLUDED_ENTER);
        return 0;
    }
    n = net_entry(&k, NC_UNKNOWN, level, cpid);
    if (n == NULL) {
        nhinc(sc, NH_DROPPED_ENTER);
        nh_map_full();
        return 0;
    }
    if (sc == NS_CONNECT)
        __sync_fetch_and_add(&n->entry[NS_CONNECT], 1);
    else if (sc == NS_ACCEPT)
        __sync_fetch_and_add(&n->entry[NS_ACCEPT], 1);
    else
        __sync_fetch_and_add(&n->entry[NS_ACCEPT4], 1);

    nhinc(sc, NH_STASH_ENTRIES);
    s.thread_start_ns = cur_thread_start();
    s.proc = k;
    s.sc = (u16)sc;
    s.cls = net_class_of_fd(fd);
    s.dest = (sc == NS_CONNECT && s.cls <= NC_IP_LAST) ? net_dest(ua, addrlen) : ND_NONE;
    old = net_stash.lookup(&tid);
    if (old) {
        /* the previous entry of this TID never saw its exit */
        if (old->thread_start_ns == s.thread_start_ns)
            nhinc(old->sc, NH_STASH_OVERWRITE);
        else
            nhinc(old->sc, NH_STASH_ORPHANED);
    }
    if (net_stash.update(&tid, &s) != 0)
        nhinc(sc, NH_STASH_FULL);
    return 0;
}

static __always_inline int net_exit(u32 sc, long ret)
{
    struct pkey k = {};
    struct nstash st = {};
    struct nstash *s;
    struct ncnt *n;
    u32 level = 0, cpid = 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();

    nhinc(sc, NH_SEEN_EXIT);
    if (resolve(&k, &level, &cpid) != 0) {
        nhinc(sc, NH_UNRESOLVED_EXIT);
        return 0;
    }
    if (excluded.lookup(&k.tgid)) {
        nhinc(sc, NH_EXCLUDED_EXIT);    /* its stash entry, if any, is purged by exclude() */
        return 0;
    }
    s = net_stash.lookup(&tid);
    if (s == NULL) {
        nhinc(sc, NH_EXIT_WITHOUT_ENTRY);
        return 0;
    }
    st = *s;
    if (net_stash.delete(&tid) != 0) {   /* deleted meanwhile (thread exit or purge) */
        nhinc(sc, NH_EXIT_WITHOUT_ENTRY);
        return 0;
    }
    if (st.thread_start_ns != cur_thread_start() || st.sc != sc) {
        nhinc(st.sc, NH_STASH_ORPHANED);
        nhinc(sc, NH_EXIT_WITHOUT_ENTRY);
        return 0;
    }
    nhinc(sc, NH_MATCHED);
    n = net_entry(&k, st.cls, level, cpid);
    if (n == NULL) {
        nhinc(sc, NH_DROPPED_EXIT);
        nh_map_full();
        return 0;
    }
    if (sc == NS_CONNECT) {
        if (ret == 0)
            __sync_fetch_and_add(&n->connect_ok, 1);
        else if (ret == -EINPROGRESS)
            __sync_fetch_and_add(&n->connect_pending, 1);
        else if (ret == -ECONNREFUSED)
            __sync_fetch_and_add(&n->connect_refused, 1);
        else
            __sync_fetch_and_add(&n->connect_err, 1);
        if (st.dest < NDEST)
            __sync_fetch_and_add(&n->dest[st.dest], 1);
    } else if (ret >= 0) {
        __sync_fetch_and_add(&n->accept_ok, 1);
    } else {
        __sync_fetch_and_add(&n->accept_err, 1);
    }
    return 0;
}

/* sched_process_exit for every thread (core.bpf.c): its stash entry, if any,
 * will never see an exit. */
static __always_inline void net_thread_exit(void)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct nstash *s = net_stash.lookup(&tid);
    u32 sc;

    if (s == NULL)
        return;
    sc = s->sc;
    if (net_stash.delete(&tid) == 0)
        nhinc(sc, NH_STASH_ORPHANED);
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    return net_enter(NS_CONNECT, (int)args->fd, (const void *)args->uservaddr, (int)args->addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect)
{
    return net_exit(NS_CONNECT, args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept)
{
    return net_enter(NS_ACCEPT, (int)args->fd, NULL, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
    return net_exit(NS_ACCEPT, args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4)
{
    return net_enter(NS_ACCEPT4, (int)args->fd, NULL, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
{
    return net_exit(NS_ACCEPT4, args->ret);
}
