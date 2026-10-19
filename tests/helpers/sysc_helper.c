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
 * Thread and exec commands (M1b S1; F4/F9 tests):
 *   tspawn <n>  start n threads; each issues one openat, then waits.
 *               Reply adds "tids=<t1,t2,...>" (kernel thread ids).
 *   tjoin <n>   release the waiting threads and join them.
 *   exec 0      execve(argv[1]) from the main thread (argv[1] is passed on, so
 *               the new image can exec again); the new image prints READY.
 *   texec 0     a new thread issues one openat, replies "... tid=<tid>", then
 *               execve(argv[1]) from that (non-leader) thread.
 *   rename 0    prctl(PR_SET_NAME, "ppc_renamed") without exec.
 *
 * Every counted call is a raw syscall(2) so that libc caching or wrappers
 * cannot change the number of kernel entries:
 *   open/openat/execve target a path that does not exist, so each call is
 *   exactly one syscall entry that fails with ENOENT;
 *   clone is a fork-like raw clone whose child immediately exit_groups.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define MISSING_PATH "/nonexistent-processpulse/dit"
#define MAX_THREADS 64

extern char **environ;

static const char *exec_target;          /* argv[1], for exec / texec */

static pthread_t threads[MAX_THREADS];
static long tids[MAX_THREADS];
static long nthreads;
static pthread_barrier_t started;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int released;

static long missing_openat(void)
{
    return (syscall(SYS_openat, AT_FDCWD, MISSING_PATH, O_RDONLY) != -1 || errno != ENOENT) ? 1 : 0;
}

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
            errors += missing_openat();
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

static void exec_self(void)
{
    char *const argv[] = { (char *)exec_target, (char *)exec_target, NULL };

    execve(exec_target, argv, environ);
    printf("EXECFAIL errno=%d\n", errno);
    fflush(stdout);
    _exit(3);
}

static void *waiting_thread(void *arg)
{
    long i = (long)arg;

    tids[i] = (long)gettid();
    if (missing_openat() != 0)
        tids[i] = -tids[i];             /* reported as an error by tspawn */
    pthread_barrier_wait(&started);
    pthread_mutex_lock(&mu);
    while (!released)
        pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    return NULL;
}

static void *exec_thread(void *arg)
{
    long errors = missing_openat();

    (void)arg;
    printf("DONE texec 0 errors=%ld tid=%ld\n", errors, (long)gettid());
    fflush(stdout);
    exec_self();
    return NULL;
}

static void tspawn(long n)
{
    long errors = 0;

    if (n < 1 || nthreads + n > MAX_THREADS) {
        printf("ERROR bad thread count\n");
        return;
    }
    pthread_barrier_init(&started, NULL, (unsigned)n + 1);
    for (long i = nthreads; i < nthreads + n; ++i)
        if (pthread_create(&threads[i], NULL, waiting_thread, (void *)i) != 0)
            ++errors;
    pthread_barrier_wait(&started);
    pthread_barrier_destroy(&started);
    printf("DONE tspawn %ld errors=%ld tids=", n, errors);
    for (long i = nthreads; i < nthreads + n; ++i) {
        if (tids[i] < 0)
            ++errors;
        printf("%s%ld", i > nthreads ? "," : "", tids[i] < 0 ? -tids[i] : tids[i]);
    }
    printf("\n");
    nthreads += n;
}

static void tjoin(long n)
{
    long errors = 0;

    pthread_mutex_lock(&mu);
    released = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    for (long i = 0; i < nthreads; ++i)
        if (pthread_join(threads[i], NULL) != 0)
            ++errors;
    nthreads = 0;
    released = 0;
    printf("DONE tjoin %ld errors=%ld\n", n, errors);
}

int main(int argc, char **argv)
{
    char line[128];

    exec_target = argc > 1 ? argv[1] : NULL;
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
        if (strcmp(cmd, "tspawn") == 0) {
            tspawn(n);
        } else if (strcmp(cmd, "tjoin") == 0) {
            tjoin(n);
        } else if (strcmp(cmd, "rename") == 0) {
            errors = prctl(PR_SET_NAME, "ppc_renamed", 0, 0, 0) != 0;
            printf("DONE rename %ld errors=%ld\n", n, errors);
        } else if ((strcmp(cmd, "exec") == 0 || strcmp(cmd, "texec") == 0) && exec_target == NULL) {
            printf("ERROR no exec target (argv[1])\n");
        } else if (strcmp(cmd, "exec") == 0) {
            printf("DONE exec %ld errors=0\n", n);
            fflush(stdout);
            exec_self();
        } else if (strcmp(cmd, "texec") == 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, exec_thread, NULL) != 0) {
                printf("ERROR pthread_create\n");
            } else {
                pthread_join(t, NULL);         /* never returns: the thread execs */
            }
        } else {
            errors = run(cmd, n);
            if (errors < 0)
                printf("ERROR unknown command %s\n", cmd);
            else
                printf("DONE %s %ld errors=%ld\n", cmd, n, errors);
        }
        fflush(stdout);
    }
    return 0;
}
