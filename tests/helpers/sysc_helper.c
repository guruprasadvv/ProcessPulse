/*
 * sysc_helper.c — deterministic syscall generator for eBPF count tests and
 * DIT-1. Built static so it runs inside a busybox container.
 *
 * Protocol (one line each way):
 *   helper -> "READY pid=<getpid> ppid=<getppid>"
 *   parent -> "<cmd> <n>"   cmd: getpid | open | openat | execve | clone
 *   helper -> "DONE <cmd> <n> errors=<calls that did not fail as expected>"
 *   parent -> "exit"        helper exits 0 (EOF on stdin does the same)
 *
 * Every call is a raw syscall(2) so that libc caching or wrappers cannot
 * change the number of kernel entries:
 *   open/openat/execve target a path that does not exist, so each call is
 *   exactly one syscall entry that fails with ENOENT;
 *   clone is a fork-like raw clone whose child immediately exit_groups.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MISSING_PATH "/nonexistent-processpulse/dit"

static long run(const char *cmd, long n)
{
    long errors = 0;
    char *const argv[] = { (char *)MISSING_PATH, NULL };
    char *const envp[] = { NULL };

    for (long i = 0; i < n; ++i) {
        if (strcmp(cmd, "getpid") == 0) {
            syscall(SYS_getpid);
        } else if (strcmp(cmd, "open") == 0) {
            if (syscall(SYS_open, MISSING_PATH, O_RDONLY) != -1 || errno != ENOENT)
                ++errors;
        } else if (strcmp(cmd, "openat") == 0) {
            if (syscall(SYS_openat, AT_FDCWD, MISSING_PATH, O_RDONLY) != -1 || errno != ENOENT)
                ++errors;
        } else if (strcmp(cmd, "execve") == 0) {
            if (syscall(SYS_execve, MISSING_PATH, argv, envp) != -1 || errno != ENOENT)
                ++errors;
        } else if (strcmp(cmd, "clone") == 0) {
            long child = syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
            if (child == 0)
                syscall(SYS_exit_group, 0);
            if (child < 0 || waitpid((pid_t)child, NULL, 0) != (pid_t)child)
                ++errors;
        } else {
            return -1;
        }
    }
    return errors;
}

int main(void)
{
    char line[128];

    printf("READY pid=%ld ppid=%ld\n", (long)syscall(SYS_getpid), (long)getppid());
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char cmd[32];
        long n = 0, errors;

        if (strncmp(line, "exit", 4) == 0)
            break;
        if (sscanf(line, "%31s %ld", cmd, &n) != 2 || n < 0) {
            printf("ERROR bad command\n");
            fflush(stdout);
            continue;
        }
        errors = run(cmd, n);
        if (errors < 0)
            printf("ERROR unknown command %s\n", cmd);
        else
            printf("DONE %s %ld errors=%ld\n", cmd, n, errors);
        fflush(stdout);
    }
    return 0;
}
