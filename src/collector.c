/*
 * collector.c — ProcessPulse-C /proc resource collector.
 *
 * Two output modes:
 *
 *   ./collector
 *       M0 legacy snapshot: one {"pid","comm","utime","stime"} object per
 *       process, then exit. Kept for backward compatibility.
 *
 *   ./collector --v1 [--interval-ms N] [--count K]
 *       Resource schema v1 (processpulse/schemas/telemetry.v1.json): repeated
 *       samples, each framed as sample_begin, one proc record per process,
 *       sample_end. K = 0 (default) samples until SIGTERM/SIGINT, stdout
 *       closure, or parent death.
 *
 * stdout carries telemetry only; diagnostics go to stderr.
 * Exit codes: 0 ok, 1 cannot open /proc, 2 usage error, 3 stdout write failed.
 *
 * Build: make   (see Makefile; C11, POSIX.1-2008, Linux)
 */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include "procfs.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SCHEMA_VERSION  1
#define FILE_BUF_SIZE   8192
#define CGROUP_PATH_MAX 4096
/* "/proc/" + a d_name of up to 255 bytes + "/cgroup" + NUL. */
#define PATH_BUF_SIZE   (6 + 255 + 8 + 1)

static volatile sig_atomic_t g_stop;

static int parse_long_arg(const char *s, long min, long max, long *out);

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/*
 * Returns 1 if 'name' is a non-empty string of ASCII decimal digits.
 * Used to filter /proc directory entries: only numeric entries are PID dirs.
 */
static int is_numeric(const char *name)
{
    if (name == NULL || *name == '\0')
        return 0;
    for (const char *p = name; *p != '\0'; ++p) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

static unsigned long long now_ns(clockid_t clk)
{
    struct timespec ts;
    clock_gettime(clk, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/*
 * Reads a whole procfs file into buf (NUL-terminated). Reading the whole file
 * — not one line — matters because comm may contain '\n' (M0 defect D1).
 * Returns the byte count, or -1 with errno set (ENOBUFS if it did not fit).
 */
static long read_file(const char *path, char *buf, size_t size)
{
    size_t len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t n = read(fd, buf + len, size - 1 - len);
        if (n < 0) {
            int e = errno;
            if (e == EINTR)
                continue;
            close(fd);
            errno = e;
            return -1;
        }
        if (n == 0)
            break;
        len += (size_t)n;
        if (len == size - 1) {
            close(fd);
            errno = ENOBUFS;
            return -1;
        }
    }
    close(fd);
    buf[len] = '\0';
    return (long)len;
}

/* Maps an errno from a procfs read to a schema error code. */
static const char *err_code(int e)
{
    switch (e) {
    case EACCES:
    case EPERM:
        return "EACCES";
    case ENOENT:
        return "ENOENT";
    case ESRCH:
        return "ESRCH";
    default:
        return "EIO";
    }
}

static int process_vanished(int e)
{
    return e == ENOENT || e == ESRCH;
}

typedef struct {
    unsigned long long pids_seen, emitted, gone, denied, parse_errors, read_errors;
    unsigned long long io_denied, fd_denied;
} sample_stats;

/* --- M0 legacy snapshot -------------------------------------------------- */

static int run_legacy(void)
{
    DIR *proc_dir = opendir("/proc");
    struct dirent *entry;
    int emitted = 0;
    char buf[FILE_BUF_SIZE];

    if (proc_dir == NULL) {
        fprintf(stderr, "collector: cannot open /proc: %s\n", strerror(errno));
        return 1;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        char path[PATH_BUF_SIZE];
        char escaped[PP_JSON_ESCAPED_MAX(PP_COMM_MAX)];
        pp_stat st;
        long len;

        if (!is_numeric(entry->d_name))
            continue;
        snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        len = read_file(path, buf, sizeof(buf));
        if (len < 0) {
            /* ENOENT/ESRCH: exited since readdir (TOCTOU). EACCES: not ours. */
            if (!process_vanished(errno) && errno != EACCES)
                fprintf(stderr, "collector: read %s: %s\n", path, strerror(errno));
            continue;
        }
        if (pp_parse_stat(buf, (size_t)len, &st) != 0) {
            fprintf(stderr, "collector: parse error for %s\n", path);
            continue;
        }
        pp_json_escape(st.comm, st.comm_len, escaped, sizeof(escaped));
        printf("{\"pid\":%d,\"comm\":\"%s\",\"utime\":%llu,\"stime\":%llu}\n",
               st.pid, escaped, st.utime, st.stime);
        ++emitted;
    }
    closedir(proc_dir);

    if (emitted == 0)
        fprintf(stderr, "collector: warning: no processes emitted from /proc\n");
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "collector: stdout write failed: %s\n", strerror(errno));
        return 3;
    }
    return 0;
}

/* --- schema v1 ----------------------------------------------------------- */

static void emit_err_field(const char *name, const char *code)
{
    if (code)
        printf(",\"%s\":\"%s\"", name, code);
    else
        printf(",\"%s\":null", name);
}

static void emit_proc(unsigned long long seq, const char *pid_s, const pp_stat *st,
                      char *buf, sample_stats *ss)
{
    char path[PATH_BUF_SIZE];
    char escaped[PP_JSON_ESCAPED_MAX(PP_COMM_MAX)];
    char cg_raw[CGROUP_PATH_MAX];
    char cg_esc[PP_JSON_ESCAPED_MAX(CGROUP_PATH_MAX)];
    const char *status_err = NULL, *io_err = NULL, *fd_err = NULL, *cg_err = NULL;
    int partial = 0, comm_valid;
    pp_status status;
    pp_io io;
    long long fd_count = -1;
    long len;

    memset(&status, 0, sizeof(status));

    snprintf(path, sizeof(path), "/proc/%s/status", pid_s);
    len = read_file(path, buf, FILE_BUF_SIZE);
    if (len < 0) {
        status_err = err_code(errno);
        partial |= process_vanished(errno);
    } else if (pp_parse_status(buf, (size_t)len, &status) != 0) {
        status_err = "EPARSE";
    }

    snprintf(path, sizeof(path), "/proc/%s/io", pid_s);
    len = read_file(path, buf, FILE_BUF_SIZE);
    if (len < 0) {
        io_err = err_code(errno);
        partial |= process_vanished(errno);
        if (errno == EACCES || errno == EPERM)
            ++ss->io_denied;
    } else if (pp_parse_io(buf, (size_t)len, &io) != 0) {
        io_err = "EPARSE";
    }

    snprintf(path, sizeof(path), "/proc/%s/fd", pid_s);
    {
        DIR *d = opendir(path);
        if (d == NULL) {
            fd_err = err_code(errno);
            partial |= process_vanished(errno);
            if (errno == EACCES || errno == EPERM)
                ++ss->fd_denied;
        } else {
            struct dirent *e;
            fd_count = 0;
            errno = 0;
            while ((e = readdir(d)) != NULL) {
                if (e->d_name[0] != '.')
                    ++fd_count;
            }
            if (errno != 0) {
                fd_err = err_code(errno);
                partial |= process_vanished(errno);
                fd_count = -1;
            }
            closedir(d);
        }
    }

    snprintf(path, sizeof(path), "/proc/%s/cgroup", pid_s);
    len = read_file(path, buf, FILE_BUF_SIZE);
    if (len < 0) {
        cg_err = err_code(errno);
        partial |= process_vanished(errno);
    } else if (pp_parse_cgroup_v2(buf, (size_t)len, cg_raw, sizeof(cg_raw)) != 0) {
        cg_err = "UNSUPPORTED";   /* no cgroup v2 line */
    } else {
        pp_json_escape(cg_raw, strlen(cg_raw), cg_esc, sizeof(cg_esc));
    }

    comm_valid = pp_json_escape(st->comm, st->comm_len, escaped, sizeof(escaped));

    printf("{\"type\":\"proc\",\"v\":%d,\"seq\":%llu,\"t_mono_ns\":%llu,"
           "\"pid\":%d,\"comm\":\"%s\",\"comm_utf8_valid\":%s,\"comm_truncated\":%s,"
           "\"state\":\"%c\",\"ppid\":%d,\"starttime_ticks\":%llu,"
           "\"utime\":%llu,\"stime\":%llu,\"num_threads\":%lld",
           SCHEMA_VERSION, seq, now_ns(CLOCK_MONOTONIC), st->pid, escaped,
           comm_valid ? "true" : "false", st->comm_truncated ? "true" : "false",
           isalpha((unsigned char)st->state) ? st->state : '?', st->ppid,
           st->starttime, st->utime, st->stime, st->num_threads);

    if (status_err == NULL && status.has_rss) {
        printf(",\"rss_kb\":%llu,\"rss_err\":null", status.rss_kb);
    } else {
        printf(",\"rss_kb\":null");
        emit_err_field("rss_err", status_err ? status_err : "UNSUPPORTED");
    }
    if (status_err == NULL && status.has_uid) {
        printf(",\"uid_real\":%llu,\"uid_eff\":%llu,\"uid_err\":null",
               status.uid_real, status.uid_eff);
    } else {
        printf(",\"uid_real\":null,\"uid_eff\":null");
        emit_err_field("uid_err", status_err ? status_err : "UNSUPPORTED");
    }
    if (status_err == NULL && status.has_ctxsw) {
        printf(",\"vol_ctxsw\":%llu,\"nonvol_ctxsw\":%llu,\"ctxsw_err\":null",
               status.vol_ctxsw, status.nonvol_ctxsw);
    } else {
        printf(",\"vol_ctxsw\":null,\"nonvol_ctxsw\":null");
        emit_err_field("ctxsw_err", status_err ? status_err : "UNSUPPORTED");
    }
    if (io_err == NULL) {
        printf(",\"io\":{\"rchar\":%llu,\"wchar\":%llu,\"syscr\":%llu,\"syscw\":%llu,"
               "\"read_bytes\":%llu,\"write_bytes\":%llu,\"cancelled_write_bytes\":%llu}",
               io.rchar, io.wchar, io.syscr, io.syscw, io.read_bytes, io.write_bytes,
               io.cancelled_write_bytes);
    } else {
        printf(",\"io\":null");
    }
    emit_err_field("io_err", io_err);
    if (fd_err == NULL)
        printf(",\"fd_count\":%lld", fd_count);
    else
        printf(",\"fd_count\":null");
    emit_err_field("fd_err", fd_err);
    if (cg_err == NULL)
        printf(",\"cgroup\":\"%s\"", cg_esc);
    else
        printf(",\"cgroup\":null");
    emit_err_field("cgroup_err", cg_err);
    printf(",\"partial\":%s}\n", partial ? "true" : "false");
}

static void read_boot_id(char *dst, size_t size)
{
    char buf[64];
    long len = read_file("/proc/sys/kernel/random/boot_id", buf, sizeof(buf));
    size_t n = 0;

    if (len > 0) {
        while (n < (size_t)len && n + 1 < size && buf[n] != '\n' &&
               (isxdigit((unsigned char)buf[n]) || buf[n] == '-')) {
            dst[n] = buf[n];
            ++n;
        }
    }
    dst[n] = '\0';
}

static int sample_once(unsigned long long seq, unsigned long long late_ns,
                       const char *boot_id, unsigned long long pidns_ino, char *buf)
{
    unsigned long long t0 = now_ns(CLOCK_MONOTONIC);
    sample_stats ss;
    const char *readdir_err = NULL;
    struct dirent *entry;
    DIR *proc_dir;

    memset(&ss, 0, sizeof(ss));
    printf("{\"type\":\"sample_begin\",\"v\":%d,\"seq\":%llu,\"t_mono_ns\":%llu,"
           "\"t_wall_ns\":%llu,\"clk_tck\":%ld,\"page_size\":%ld,\"boot_id\":\"%s\","
           "\"pidns_ino\":%llu,\"euid\":%lu,\"collector_pid\":%ld}\n",
           SCHEMA_VERSION, seq, t0, now_ns(CLOCK_REALTIME), sysconf(_SC_CLK_TCK),
           sysconf(_SC_PAGESIZE), boot_id, pidns_ino, (unsigned long)geteuid(),
           (long)getpid());

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        fprintf(stderr, "collector: cannot open /proc: %s\n", strerror(errno));
        return -1;
    }
    for (;;) {
        char path[PATH_BUF_SIZE];
        pp_stat st;
        long len;

        errno = 0;
        entry = readdir(proc_dir);
        if (entry == NULL) {
            if (errno != 0)
                readdir_err = err_code(errno);
            break;
        }
        if (!is_numeric(entry->d_name))
            continue;
        ++ss.pids_seen;
        snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        len = read_file(path, buf, FILE_BUF_SIZE);
        if (len < 0) {
            if (process_vanished(errno))
                ++ss.gone;
            else if (errno == EACCES || errno == EPERM)
                ++ss.denied;
            else
                ++ss.read_errors;
            continue;
        }
        if (pp_parse_stat(buf, (size_t)len, &st) != 0) {
            ++ss.parse_errors;
            fprintf(stderr, "collector: parse error for %s\n", path);
            continue;
        }
        emit_proc(seq, entry->d_name, &st, buf, &ss);
        ++ss.emitted;
    }
    closedir(proc_dir);

    {
        unsigned long long t1 = now_ns(CLOCK_MONOTONIC);
        printf("{\"type\":\"sample_end\",\"v\":%d,\"seq\":%llu,\"t_mono_ns\":%llu,"
               "\"dur_ns\":%llu,\"pids_seen\":%llu,\"emitted\":%llu,\"gone\":%llu,"
               "\"denied\":%llu,\"parse_errors\":%llu,\"read_errors\":%llu,"
               "\"io_denied\":%llu,\"fd_denied\":%llu,\"late_ns\":%llu",
               SCHEMA_VERSION, seq, t1, t1 - t0, ss.pids_seen, ss.emitted, ss.gone,
               ss.denied, ss.parse_errors, ss.read_errors, ss.io_denied, ss.fd_denied,
               late_ns);
        emit_err_field("readdir_err", readdir_err);
        printf("}\n");
    }
    return 0;
}

static int run_v1(long interval_ms, unsigned long long count)
{
    char boot_id[48];
    char *buf = malloc(FILE_BUF_SIZE);
    unsigned long long pidns_ino = 0;
    unsigned long long interval_ns = (unsigned long long)interval_ms * 1000000ULL;
    struct timespec deadline;
    struct stat sb;
    pid_t parent = getppid();
    int rc = 0;

    if (buf == NULL) {
        fprintf(stderr, "collector: out of memory\n");
        return 1;
    }

    /* Telemetry must reach the supervisor promptly: flush once per sample. */
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    /*
     * Stop when the supervisor dies. PDEATHSIG only covers deaths after this
     * call, so also stop if the parent is already not the expected supervisor:
     * PPC_SUPERVISOR_PID (set by processpulse) closes the race where the
     * supervisor died before we got here and getppid() is already the reaper.
     */
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    {
        const char *sup = getenv("PPC_SUPERVISOR_PID");
        long expected;
        if (sup != NULL && parse_long_arg(sup, 1, 2147483647L, &expected) == 0)
            parent = (pid_t)expected;
    }
    if (getppid() != parent)
        g_stop = 1;

    read_boot_id(boot_id, sizeof(boot_id));
    if (stat("/proc/self/ns/pid", &sb) == 0)
        pidns_ino = (unsigned long long)sb.st_ino;

    clock_gettime(CLOCK_MONOTONIC, &deadline);
    for (unsigned long long seq = 0; !g_stop && (count == 0 || seq < count); ++seq) {
        unsigned long long scheduled = (unsigned long long)deadline.tv_sec * 1000000000ULL +
                                       (unsigned long long)deadline.tv_nsec;
        unsigned long long start = now_ns(CLOCK_MONOTONIC);
        unsigned long long late = start > scheduled ? start - scheduled : 0;

        if (sample_once(seq, late, boot_id, pidns_ino, buf) != 0) {
            rc = 1;
            break;
        }
        if (fflush(stdout) != 0 || ferror(stdout)) {
            /* Usually EPIPE: the supervisor closed our stdout. */
            fprintf(stderr, "collector: stdout write failed: %s\n", strerror(errno));
            rc = 3;
            break;
        }
        if (count != 0 && seq + 1 >= count)
            break;

        /* Absolute deadlines avoid drift; never burst to catch up. */
        scheduled += interval_ns;
        {
            unsigned long long now = now_ns(CLOCK_MONOTONIC);
            if (scheduled < now)
                scheduled = now;
        }
        deadline.tv_sec = (time_t)(scheduled / 1000000000ULL);
        deadline.tv_nsec = (long)(scheduled % 1000000000ULL);
        while (!g_stop &&
               clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL) == EINTR)
            ;
    }
    free(buf);
    return rc;
}

static int parse_long_arg(const char *s, long min, long max, long *out)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: collector                      M0 snapshot (legacy schema)\n"
            "       collector --v1 [--interval-ms N] [--count K]\n"
            "                 schema v1 samples; N in [10, 3600000] (default 1000),\n"
            "                 K samples (default 0 = until signalled)\n");
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    long interval_ms = 1000, count = 0;
    int v1 = 0;

    if (argc == 1)
        return run_legacy();

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--v1") == 0) {
            v1 = 1;
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            if (parse_long_arg(argv[++i], 10, 3600000, &interval_ms) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            if (parse_long_arg(argv[++i], 0, 1000000000L, &count) != 0) {
                usage();
                return 2;
            }
        } else {
            usage();
            return 2;
        }
    }
    if (!v1) {
        usage();
        return 2;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    /* Report a closed stdout as a write error (exit 3) instead of dying silently. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    return run_v1(interval_ms, (unsigned long long)count);
}
