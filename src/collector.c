/*
 * collector.c — ProcessPulse-C M0
 *
 * Enumerates all running processes via /proc, reads /proc/<pid>/stat,
 * and emits one JSON object per process to stdout.
 *
 * Build: gcc -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L \
 *             -o collector src/collector.c
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>

/* /proc/<pid>/stat lines can be very long on 64-bit systems (52 fields). */
#define STAT_LINE_MAX   4096

/*
 * Kernel constant TASK_COMM_LEN is 16 (15 usable chars + null terminator).
 * We allocate double for safety against future kernel changes or truncated reads.
 */
#define COMM_MAX        32

/*
 * "/proc/4194304/stat" is the longest possible path: 20 chars.
 * 64 bytes is sufficient.
 */
#define PATH_BUF_SIZE   64

/* Parsed fields from /proc/<pid>/stat. */
typedef struct {
    int           pid;
    char          comm[COMM_MAX];
    unsigned long utime;  /* user-mode CPU ticks (field 14) */
    unsigned long stime;  /* kernel-mode CPU ticks (field 15) */
} ProcStat;

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

/*
 * Writes a JSON-safe version of 'src' into 'dst' (including null terminator).
 * Escapes backslash, double-quote, and ASCII control characters (< 0x20).
 * Silently truncates if dst_size is insufficient.
 */
static void json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t out = 0;

    for (const char *s = src; *s != '\0'; ++s) {
        unsigned char c = (unsigned char)*s;

        if (c == '"' || c == '\\') {
            /* Two-character escape: \" or \\ */
            if (out + 2 >= dst_size)
                break;
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c < 0x20) {
            /* Six-character unicode escape: \uXXXX */
            if (out + 6 >= dst_size)
                break;
            int n = snprintf(dst + out, dst_size - out, "\\u%04x", (unsigned int)c);
            if (n > 0)
                out += (size_t)n;
        } else {
            if (out + 1 >= dst_size)
                break;
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

/*
 * Parses a /proc/<pid>/stat line into *rec.
 * Returns 0 on success, -1 if the line is malformed.
 *
 * Parsing strategy — the comm field is tricky:
 *
 *   /proc/<pid>/stat format (man 5 proc, fields 1-15):
 *     pid (comm) state ppid pgrp session tty_nr tpgid flags
 *     minflt cminflt majflt cmajflt utime stime
 *
 *   The comm field is the process name wrapped in parentheses.
 *   It can contain spaces and parentheses (set via prctl PR_SET_NAME).
 *   A naive whitespace-split fails for multi-word comms.
 *   A naive strchr(')') fails when comm contains ')'.
 *
 *   Correct approach: find the LAST ')' in the line with strrchr().
 *   All fields after comm are integers — they never contain ')'.
 *   Therefore the last ')' in the line is always the closing delimiter
 *   of the comm field.
 *
 *   After the last ')', we skip fields 3–13 using sscanf's assignment-
 *   suppression operator (%*) and then store fields 14 (utime) and 15 (stime).
 *
 * Field numbering (1-indexed, from kernel documentation):
 *   3   state     char
 *   4   ppid      int
 *   5   pgrp      int
 *   6   session   int
 *   7   tty_nr    int
 *   8   tpgid     int
 *   9   flags     unsigned int
 *  10   minflt    unsigned long
 *  11   cminflt   unsigned long
 *  12   majflt    unsigned long
 *  13   cmajflt   unsigned long
 *  14   utime     unsigned long  ← stored
 *  15   stime     unsigned long  ← stored
 */
static int parse_proc_stat(const char *line, ProcStat *rec)
{
    /* --- Field 1: pid --- */
    char *endptr;
    long pid_long = strtol(line, &endptr, 10);
    if (endptr == line || pid_long <= 0)
        return -1;
    rec->pid = (int)pid_long;

    /* --- Field 2: comm --- */
    const char *open_paren  = strchr(line, '(');
    const char *close_paren = strrchr(line, ')');  /* last ')' in the line */

    if (open_paren == NULL || close_paren == NULL || close_paren <= open_paren)
        return -1;

    size_t comm_len = (size_t)(close_paren - open_paren - 1);
    if (comm_len >= COMM_MAX)
        comm_len = COMM_MAX - 1;  /* truncate; kernel already limits to 15 chars */
    memcpy(rec->comm, open_paren + 1, comm_len);
    rec->comm[comm_len] = '\0';

    /* --- Fields 3–15: parse from the char after the last ')' --- */
    /*
     * sscanf format after close_paren:
     *   " %*s"  — field  3: state (skip as token)
     *   " %*s"  — field  4: ppid
     *   " %*s"  — field  5: pgrp
     *   " %*s"  — field  6: session
     *   " %*s"  — field  7: tty_nr
     *   " %*s"  — field  8: tpgid
     *   " %*s"  — field  9: flags
     *   " %*s"  — field 10: minflt
     *   " %*s"  — field 11: cminflt
     *   " %*s"  — field 12: majflt
     *   " %*s"  — field 13: cmajflt
     *   " %lu"  — field 14: utime  (stored)
     *   " %lu"  — field 15: stime  (stored)
     *
     * We use %*s (skip one whitespace-delimited token) for all skipped fields.
     * This avoids a GCC -Wformat warning triggered by combining assignment
     * suppression (%*) with length modifiers (l, u) in some GCC versions.
     * All skipped fields are simple integer tokens with no embedded spaces,
     * so %*s is semantically correct here.
     *
     * sscanf returns the count of successfully *stored* conversions (2 here).
     */
    unsigned long utime = 0;
    unsigned long stime = 0;

    int n = sscanf(close_paren + 1,
                   " %*s"   /* field  3: state  */
                   " %*s"   /* field  4: ppid   */
                   " %*s"   /* field  5: pgrp   */
                   " %*s"   /* field  6: session */
                   " %*s"   /* field  7: tty_nr */
                   " %*s"   /* field  8: tpgid  */
                   " %*s"   /* field  9: flags  */
                   " %*s"   /* field 10: minflt */
                   " %*s"   /* field 11: cminflt */
                   " %*s"   /* field 12: majflt */
                   " %*s"   /* field 13: cmajflt */
                   " %lu"   /* field 14: utime  */
                   " %lu",  /* field 15: stime  */
                   &utime, &stime);

    if (n != 2)
        return -1;

    rec->utime = utime;
    rec->stime = stime;
    return 0;
}

/*
 * Opens /proc/<pid>/stat, reads the single stat line, and fills *rec.
 * Returns 0 on success.
 * Returns -1 silently if the file cannot be opened (process likely exited
 * between directory enumeration and this read — a normal TOCTOU race).
 * Prints to stderr and returns -1 for unexpected I/O errors.
 */
static int read_proc_stat(int pid, ProcStat *rec)
{
    char path[PATH_BUF_SIZE];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        /*
         * ENOENT: process exited between readdir() and fopen(). Expected.
         * EACCES: we lack permission to read this process. Skip silently.
         * Any other error: log it, it is unexpected.
         */
        if (errno != ENOENT && errno != EACCES)
            fprintf(stderr, "collector: open %s: %s\n", path, strerror(errno));
        return -1;
    }

    char line[STAT_LINE_MAX];
    int result = -1;

    if (fgets(line, sizeof(line), f) != NULL) {
        /* Strip trailing newline if present. */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        result = parse_proc_stat(line, rec);
        if (result != 0)
            fprintf(stderr, "collector: parse error for %s\n", path);
    }

    fclose(f);
    return result;
}

/*
 * Emits one JSON object to stdout, terminated by '\n'.
 *
 * Schema:
 *   {
 *     "pid":   <integer>  — process ID (always > 0)
 *     "comm":  <string>   — process name from /proc/<pid>/stat field 2
 *                           (up to 15 chars; set by process via prctl)
 *     "utime": <integer>  — user-mode CPU time in clock ticks (field 14)
 *                           divide by sysconf(_SC_CLK_TCK) for seconds
 *     "stime": <integer>  — kernel-mode CPU time in clock ticks (field 15)
 *                           divide by sysconf(_SC_CLK_TCK) for seconds
 *   }
 */
static void emit_json(const ProcStat *rec)
{
    /* Worst case: each byte in comm becomes a 6-char \uXXXX sequence. */
    char escaped[COMM_MAX * 6 + 1];
    json_escape(rec->comm, escaped, sizeof(escaped));

    printf("{\"pid\":%d,\"comm\":\"%s\",\"utime\":%lu,\"stime\":%lu}\n",
           rec->pid, escaped, rec->utime, rec->stime);
}

int main(void)
{
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        fprintf(stderr, "collector: cannot open /proc: %s\n", strerror(errno));
        return 1;
    }

    struct dirent *entry;
    int emitted = 0;

    /*
     * readdir() is not guaranteed to be thread-safe but this is a single-
     * threaded program. Entries are returned in filesystem order, not PID
     * order — that is acceptable for a snapshot collector.
     */
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!is_numeric(entry->d_name))
            continue;

        int pid = (int)strtol(entry->d_name, NULL, 10);
        ProcStat rec;
        memset(&rec, 0, sizeof(rec));

        if (read_proc_stat(pid, &rec) != 0)
            continue;  /* process exited or unreadable; skip silently */

        emit_json(&rec);
        ++emitted;
    }

    closedir(proc_dir);

    if (emitted == 0) {
        /* Should never happen on a running Linux system. */
        fprintf(stderr, "collector: warning: no processes emitted from /proc\n");
    }

    return 0;
}
