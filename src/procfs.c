/*
 * procfs.c — pure parsers for procfs files. See procfs.h.
 */

#include "procfs.h"

#include <limits.h>
#include <string.h>

int pp_parse_u64(const char *s, size_t n, unsigned long long *out)
{
    unsigned long long v = 0;

    if (n == 0)
        return -1;
    for (size_t i = 0; i < n; ++i) {
        unsigned d;
        if (s[i] < '0' || s[i] > '9')
            return -1;
        d = (unsigned)(s[i] - '0');
        if (v > (ULLONG_MAX - d) / 10)
            return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

/* Strict signed decimal parse (optional leading '-'). */
static int parse_i64(const char *s, size_t n, long long *out)
{
    unsigned long long mag;
    int neg = (n > 0 && s[0] == '-');

    if (pp_parse_u64(s + neg, n - (size_t)neg, &mag) != 0)
        return -1;
    if (neg) {
        if (mag > (unsigned long long)LLONG_MAX + 1ULL)
            return -1;
        *out = (mag == (unsigned long long)LLONG_MAX + 1ULL) ? LLONG_MIN : -(long long)mag;
    } else {
        if (mag > (unsigned long long)LLONG_MAX)
            return -1;
        *out = (long long)mag;
    }
    return 0;
}

/* Last occurrence of c in [buf, buf+len), or NULL. */
static const char *last_byte(const char *buf, size_t len, char c)
{
    for (size_t i = len; i > 0; --i) {
        if (buf[i - 1] == c)
            return buf + i - 1;
    }
    return NULL;
}

/*
 * /proc/<pid>/stat: "pid (comm) state ppid ... utime stime ... num_threads
 * itrealvalue starttime ...".
 *
 * comm may contain spaces, parentheses and even newlines, so the closing
 * delimiter is the LAST ')' in the whole buffer: every field after comm is
 * numeric (or the single state letter) and cannot contain ')'.
 */
int pp_parse_stat(const char *buf, size_t len, pp_stat *out)
{
    const char *end = buf + len;
    const char *p = buf;
    const char *open, *close;
    unsigned long long pid;
    size_t comm_len;

    /* Field 1: pid, strictly digits followed by " (". */
    while (p < end && *p >= '0' && *p <= '9')
        ++p;
    if (p == buf || end - p < 2 || p[0] != ' ' || p[1] != '(')
        return -1;
    if (pp_parse_u64(buf, (size_t)(p - buf), &pid) != 0 || pid == 0 || pid > INT_MAX)
        return -1;
    out->pid = (int)pid;

    /* Field 2: comm, between the first '(' and the last ')'. */
    open = p + 1;
    close = last_byte(buf, len, ')');
    if (close == NULL || close < open)
        return -1;
    comm_len = (size_t)(close - open - 1);
    out->comm_truncated = comm_len > PP_COMM_MAX;
    if (comm_len > PP_COMM_MAX)
        comm_len = PP_COMM_MAX;
    memcpy(out->comm, open + 1, comm_len);
    out->comm[comm_len] = '\0';
    out->comm_len = comm_len;

    /* Fields 3..: space-separated tokens after ") ". */
    p = close + 1;
    for (int field = 3; field <= 22; ++field) {
        const char *tok;
        size_t n;

        if (p >= end || *p != ' ')
            return -1;
        ++p;
        tok = p;
        while (p < end && *p != ' ' && *p != '\n')
            ++p;
        n = (size_t)(p - tok);
        if (n == 0)
            return -1;

        switch (field) {
        case 3:
            if (n != 1)
                return -1;
            out->state = tok[0];
            break;
        case 4: {
            long long v;
            if (parse_i64(tok, n, &v) != 0 || v < 0 || v > INT_MAX)
                return -1;
            out->ppid = (int)v;
            break;
        }
        case 14:
            if (pp_parse_u64(tok, n, &out->utime) != 0)
                return -1;
            break;
        case 15:
            if (pp_parse_u64(tok, n, &out->stime) != 0)
                return -1;
            break;
        case 20:
            if (parse_i64(tok, n, &out->num_threads) != 0 || out->num_threads < 0)
                return -1;
            break;
        case 22:
            if (pp_parse_u64(tok, n, &out->starttime) != 0)
                return -1;
            break;
        default: {
            /* Skipped fields must still be well-formed signed integers. */
            long long ignored;
            if (parse_i64(tok, n, &ignored) != 0)
                return -1;
            break;
        }
        }
    }
    return 0;
}

/*
 * Finds "key:" at the start of a line and returns a pointer just past the
 * colon, with *line_end set to the end of that line.
 */
static const char *find_key(const char *buf, size_t len, const char *key,
                            const char **line_end)
{
    size_t klen = strlen(key);
    const char *end = buf + len;
    const char *line = buf;

    while (line < end) {
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        const char *le = nl ? nl : end;

        if ((size_t)(le - line) > klen && memcmp(line, key, klen) == 0 && line[klen] == ':') {
            *line_end = le;
            return line + klen + 1;
        }
        line = nl ? nl + 1 : end;
    }
    return NULL;
}

/* Parses up to max whitespace-separated unsigned values from [p, le). */
static int parse_u64_list(const char *p, const char *le, unsigned long long *vals, int max)
{
    int count = 0;

    while (p < le && count < max) {
        const char *tok;
        while (p < le && (*p == ' ' || *p == '\t'))
            ++p;
        tok = p;
        while (p < le && *p != ' ' && *p != '\t')
            ++p;
        if (p == tok)
            break;
        if (pp_parse_u64(tok, (size_t)(p - tok), &vals[count]) != 0)
            return -1;
        ++count;
    }
    return count;
}

int pp_parse_status(const char *buf, size_t len, pp_status *out)
{
    const char *v, *le;
    unsigned long long vals[4];

    memset(out, 0, sizeof(*out));

    /* Every task has Name/Pid; their absence means this is not a status file. */
    if (find_key(buf, len, "Pid", &le) == NULL)
        return -1;

    if ((v = find_key(buf, len, "Uid", &le)) != NULL) {
        if (parse_u64_list(v, le, vals, 4) != 4)
            return -1;
        out->has_uid = 1;
        out->uid_real = vals[0];
        out->uid_eff = vals[1];
    }

    if ((v = find_key(buf, len, "VmRSS", &le)) != NULL) {
        /* "VmRSS:\t    2420 kB" */
        const char *kb = le;
        if (le - v >= 3 && memcmp(le - 3, " kB", 3) == 0)
            kb = le - 3;
        if (parse_u64_list(v, kb, vals, 1) != 1)
            return -1;
        out->has_rss = 1;
        out->rss_kb = vals[0];
    }

    {
        const char *v2, *le2;
        v = find_key(buf, len, "voluntary_ctxt_switches", &le);
        v2 = find_key(buf, len, "nonvoluntary_ctxt_switches", &le2);
        if (v != NULL && v2 != NULL) {
            if (parse_u64_list(v, le, &out->vol_ctxsw, 1) != 1 ||
                parse_u64_list(v2, le2, &out->nonvol_ctxsw, 1) != 1)
                return -1;
            out->has_ctxsw = 1;
        }
    }
    return 0;
}

int pp_parse_io(const char *buf, size_t len, pp_io *out)
{
    static const char *const keys[7] = {
        "rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes",
        "cancelled_write_bytes",
    };
    unsigned long long *const dst[7] = {
        &out->rchar, &out->wchar, &out->syscr, &out->syscw, &out->read_bytes,
        &out->write_bytes, &out->cancelled_write_bytes,
    };

    for (int i = 0; i < 7; ++i) {
        const char *le;
        const char *v = find_key(buf, len, keys[i], &le);
        if (v == NULL || parse_u64_list(v, le, dst[i], 1) != 1)
            return -1;
    }
    return 0;
}

int pp_parse_cgroup_v2(const char *buf, size_t len, char *dst, size_t dst_size)
{
    const char *end = buf + len;
    const char *line = buf;

    while (line < end) {
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        const char *le = nl ? nl : end;

        if (le - line >= 3 && memcmp(line, "0::", 3) == 0) {
            size_t n = (size_t)(le - line - 3);
            if (n == 0 || n >= dst_size)
                return -1;
            memcpy(dst, line + 3, n);
            dst[n] = '\0';
            return 0;
        }
        line = nl ? nl + 1 : end;
    }
    return -1;
}
