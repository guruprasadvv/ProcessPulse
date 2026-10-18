/*
 * test_procfs.c — unit tests for src/procfs.c and src/jsonl.c.
 *
 * No external framework: CHECK() records failures and main() returns
 * non-zero if any check failed. Build and run with `make test-c`.
 */

#include "../../src/jsonl.h"
#include "../../src/procfs.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++checks;                                                            \
        if (!(cond)) {                                                       \
            ++failures;                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

/* String literal and its length (without the terminating NUL). */
#define LIT(s) (s), (sizeof(s) - 1)

/* A realistic 52-field stat line with placeholders for the tested fields. */
static size_t make_stat(char *buf, size_t size, const char *pid, const char *comm,
                        size_t comm_len, const char *utime, const char *stime)
{
    int n = snprintf(buf, size, "%s (", pid);
    size_t len = (size_t)n;
    memcpy(buf + len, comm, comm_len);
    len += comm_len;
    n = snprintf(buf + len, size - len,
                 ") S 1 42 42 0 -1 4194560 120 0 0 0 %s %s 0 0 20 0 3 0 98765 "
                 "1048576 512 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 "
                 "0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                 utime, stime);
    return len + (size_t)n;
}

static void test_stat_basic(void)
{
    char buf[1024];
    pp_stat st;
    size_t len = make_stat(buf, sizeof(buf), "1234", "nginx", 5, "71", "24");

    CHECK(pp_parse_stat(buf, len, &st) == 0);
    CHECK(st.pid == 1234);
    CHECK(strcmp(st.comm, "nginx") == 0);
    CHECK(st.state == 'S');
    CHECK(st.ppid == 1);
    CHECK(st.utime == 71);
    CHECK(st.stime == 24);
    CHECK(st.num_threads == 3);
    CHECK(st.starttime == 98765);
    CHECK(st.comm_truncated == 0);
}

static void test_stat_tricky_comm(void)
{
    static const char *const names[] = {
        "my cool proc", "proc(1)", "bad (name) here", "(a)(b)(c)", "a) R 1 (b", "",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char buf[1024];
        pp_stat st;
        size_t len = make_stat(buf, sizeof(buf), "77", names[i], strlen(names[i]), "5", "6");
        CHECK(pp_parse_stat(buf, len, &st) == 0);
        CHECK(strcmp(st.comm, names[i]) == 0);
        CHECK(st.utime == 5 && st.stime == 6);
    }
}

/* D1 regression: a comm containing '\n' must not break parsing. */
static void test_stat_newline_in_comm(void)
{
    char buf[1024];
    pp_stat st;
    size_t len = make_stat(buf, sizeof(buf), "581", "evil\nhidden", 11, "3", "4");

    CHECK(pp_parse_stat(buf, len, &st) == 0);
    CHECK(st.comm_len == 11);
    CHECK(memcmp(st.comm, "evil\nhidden", 11) == 0);
    CHECK(st.utime == 3 && st.stime == 4);
}

/* D5: 64-byte kworker-style names are kept; longer input is truncated and flagged. */
static void test_stat_long_comm(void)
{
    char name[80];
    char buf[1024];
    pp_stat st;
    size_t len;

    memset(name, 'k', sizeof(name));
    len = make_stat(buf, sizeof(buf), "9", name, 64, "1", "1");
    CHECK(pp_parse_stat(buf, len, &st) == 0);
    CHECK(st.comm_len == 64 && st.comm_truncated == 0);

    len = make_stat(buf, sizeof(buf), "9", name, 70, "1", "1");
    CHECK(pp_parse_stat(buf, len, &st) == 0);
    CHECK(st.comm_len == 64 && st.comm_truncated == 1);
}

/* D3 regression and PID strictness. */
static void test_stat_malformed(void)
{
    char buf[1024];
    pp_stat st;
    size_t len;

    len = make_stat(buf, sizeof(buf), "1", "x", 1, "-1", "0");
    CHECK(pp_parse_stat(buf, len, &st) == -1);          /* negative utime */

    len = make_stat(buf, sizeof(buf), "12abc", "x", 1, "1", "1");
    CHECK(pp_parse_stat(buf, len, &st) == -1);          /* garbage pid */

    len = make_stat(buf, sizeof(buf), "0", "x", 1, "1", "1");
    CHECK(pp_parse_stat(buf, len, &st) == -1);          /* pid 0 */

    len = make_stat(buf, sizeof(buf), "1", "x", 1, "abc", "1");
    CHECK(pp_parse_stat(buf, len, &st) == -1);          /* non-numeric utime */

    CHECK(pp_parse_stat("", 0, &st) == -1);
    CHECK(pp_parse_stat(LIT("1 init S 0 0"), &st) == -1);          /* no parens */
    CHECK(pp_parse_stat(LIT("1 (init S 0 0"), &st) == -1);         /* no close */
    CHECK(pp_parse_stat(LIT("1 (init) S 0 0"), &st) == -1);        /* too few fields */
    CHECK(pp_parse_stat(LIT("1 (x) S 1 2 3 4 5 6 7 8 9 10 11 99999999999999999999999 "
                            "1 1 1 1 1 1 1 1"), &st) == -1);       /* overflow */
}

static const char STATUS_FULL[] =
    "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t341\nNgid:\t0\n"
    "Pid:\t341\nPPid:\t340\nTracerPid:\t0\nUid:\t1000\t1001\t1000\t1000\n"
    "Gid:\t1000\t1000\t1000\t1000\nVmPeak:\t    9000 kB\nVmRSS:\t    5120 kB\n"
    "Threads:\t1\nvoluntary_ctxt_switches:\t150\nnonvoluntary_ctxt_switches:\t7\n";

static const char STATUS_KTHREAD[] =
    "Name:\tkthreadd\nState:\tS (sleeping)\nTgid:\t2\nPid:\t2\nPPid:\t0\n"
    "Uid:\t0\t0\t0\t0\nThreads:\t1\nvoluntary_ctxt_switches:\t10\n"
    "nonvoluntary_ctxt_switches:\t0\n";

static void test_status(void)
{
    pp_status s;

    CHECK(pp_parse_status(STATUS_FULL, sizeof(STATUS_FULL) - 1, &s) == 0);
    CHECK(s.has_uid && s.uid_real == 1000 && s.uid_eff == 1001);
    CHECK(s.has_rss && s.rss_kb == 5120);
    CHECK(s.has_ctxsw && s.vol_ctxsw == 150 && s.nonvol_ctxsw == 7);

    CHECK(pp_parse_status(STATUS_KTHREAD, sizeof(STATUS_KTHREAD) - 1, &s) == 0);
    CHECK(s.has_rss == 0);                 /* absent, not zero */
    CHECK(s.has_ctxsw && s.vol_ctxsw == 10);

    CHECK(pp_parse_status(LIT("garbage\n"), &s) == -1);
    CHECK(pp_parse_status(LIT("Pid:\t1\nUid:\t-1\t0\t0\t0\n"), &s) == -1);
}

static void test_io(void)
{
    static const char io[] =
        "rchar: 20169\nwchar: 7\nsyscr: 25\nsyscw: 1\nread_bytes: 4096\n"
        "write_bytes: 0\ncancelled_write_bytes: 0\n";
    pp_io v;

    CHECK(pp_parse_io(io, sizeof(io) - 1, &v) == 0);
    CHECK(v.rchar == 20169 && v.wchar == 7 && v.syscr == 25 && v.syscw == 1);
    CHECK(v.read_bytes == 4096 && v.write_bytes == 0 && v.cancelled_write_bytes == 0);
    CHECK(pp_parse_io(LIT("rchar: 1\n"), &v) == -1);
}

static void test_cgroup(void)
{
    static const char docker[] =
        "0::/system.slice/docker-6b4a3410c12506aacecee2f5c69b7eed8e29b4c7c33e9dc505e039aa73dbec8c.scope\n";
    static const char hybrid[] = "12:cpu:/x\n0::/init.scope\n";
    char path[256];
    char tiny[4];

    CHECK(pp_parse_cgroup_v2(docker, sizeof(docker) - 1, path, sizeof(path)) == 0);
    CHECK(strncmp(path, "/system.slice/docker-6b4a", 25) == 0);
    CHECK(pp_parse_cgroup_v2(hybrid, sizeof(hybrid) - 1, path, sizeof(path)) == 0);
    CHECK(strcmp(path, "/init.scope") == 0);
    CHECK(pp_parse_cgroup_v2(LIT("12:cpu:/x\n"), path, sizeof(path)) == -1);
    CHECK(pp_parse_cgroup_v2(docker, sizeof(docker) - 1, tiny, sizeof(tiny)) == -1);
}

static void test_json_escape(void)
{
    char out[PP_JSON_ESCAPED_MAX(32)];

    CHECK(pp_json_escape("plain", 5, out, sizeof(out)) == 1 && strcmp(out, "plain") == 0);
    CHECK(pp_json_escape("a\"b\\c", 5, out, sizeof(out)) == 1 && strcmp(out, "a\\\"b\\\\c") == 0);
    CHECK(pp_json_escape("x\ny\x01", 4, out, sizeof(out)) == 1 &&
          strcmp(out, "x\\u000ay\\u0001") == 0);
    /* Valid UTF-8 (é, €, 😀) passes through unchanged. */
    CHECK(pp_json_escape("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9, out, sizeof(out)) == 1 &&
          strcmp(out, "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80") == 0);
    /* D2 regression: invalid bytes become U+FFFD and are reported. */
    CHECK(pp_json_escape("bad\xff\xfename", 9, out, sizeof(out)) == 0 &&
          strcmp(out, "bad\xef\xbf\xbd\xef\xbf\xbdname") == 0);
    CHECK(pp_json_escape("\xc0\xaf", 2, out, sizeof(out)) == 0);           /* overlong */
    CHECK(pp_json_escape("\xed\xa0\x80", 3, out, sizeof(out)) == 0);       /* surrogate */
    CHECK(pp_json_escape("\xf4\x90\x80\x80", 4, out, sizeof(out)) == 0);   /* > U+10FFFF */
    CHECK(pp_json_escape("\xe2\x82", 2, out, sizeof(out)) == 0);           /* truncated */
    /* Embedded NUL is a control character, not a terminator. */
    CHECK(pp_json_escape("a\0b", 3, out, sizeof(out)) == 1 && strcmp(out, "a\\u0000b") == 0);
}

int main(void)
{
    test_stat_basic();
    test_stat_tricky_comm();
    test_stat_newline_in_comm();
    test_stat_long_comm();
    test_stat_malformed();
    test_status();
    test_io();
    test_cgroup();
    test_json_escape();

    printf("test_procfs: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
