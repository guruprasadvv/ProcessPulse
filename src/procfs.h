/*
 * procfs.h — pure parsers for /proc/<pid>/{stat,status,io,cgroup}.
 *
 * Every parser takes the complete file content as a byte buffer (which may
 * contain embedded newlines, e.g. inside comm) and performs no I/O, so each
 * one can be unit-tested on fixtures (tests/c/test_procfs.c).
 */
#ifndef PROCFS_H
#define PROCFS_H

#include <stddef.h>

/*
 * The kernel prints at most 64 bytes of task name in /proc/<pid>/stat
 * (fs/proc/array.c uses a 64-byte buffer so workqueue workers can show
 * "kworker/u8:2-events_unbound"). Ordinary tasks are limited to 15 bytes.
 */
#define PP_COMM_MAX 64

typedef struct {
    int                pid;                    /* field 1 */
    char               comm[PP_COMM_MAX + 1];  /* field 2, raw bytes, NUL-terminated */
    size_t             comm_len;               /* bytes stored (comm may hold any byte but NUL) */
    int                comm_truncated;         /* 1 if the name exceeded PP_COMM_MAX */
    char               state;                  /* field 3 */
    int                ppid;                   /* field 4 */
    unsigned long long utime;                  /* field 14, clock ticks */
    unsigned long long stime;                  /* field 15, clock ticks */
    long long          num_threads;            /* field 20 */
    unsigned long long starttime;              /* field 22, clock ticks since boot */
} pp_stat;

/* Returns 0 on success, -1 if the content is malformed. */
int pp_parse_stat(const char *buf, size_t len, pp_stat *out);

typedef struct {
    int                has_uid;
    unsigned long long uid_real, uid_eff;
    int                has_rss;          /* VmRSS is absent for kernel threads and zombies */
    unsigned long long rss_kb;
    int                has_ctxsw;
    unsigned long long vol_ctxsw, nonvol_ctxsw;
} pp_status;

/* Returns 0 on success (fields may still be absent), -1 if malformed. */
int pp_parse_status(const char *buf, size_t len, pp_status *out);

typedef struct {
    unsigned long long rchar, wchar, syscr, syscw, read_bytes, write_bytes,
                       cancelled_write_bytes;
} pp_io;

/* Returns 0 when all seven counters were found, -1 otherwise. */
int pp_parse_io(const char *buf, size_t len, pp_io *out);

/*
 * Extracts the cgroup v2 path from the "0::<path>" line into dst.
 * Returns 0 on success, -1 if there is no v2 line or dst is too small.
 */
int pp_parse_cgroup_v2(const char *buf, size_t len, char *dst, size_t dst_size);

/*
 * Strict unsigned decimal parse of [s, s+n): digits only, no sign, no
 * whitespace, no overflow. Returns 0 on success.
 */
int pp_parse_u64(const char *s, size_t n, unsigned long long *out);

#endif /* PROCFS_H */
