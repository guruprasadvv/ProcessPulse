/*
 * core.bpf.c — scheduler hooks of the unified BPF program, compiled after
 * common.h and the enabled capability sources (see common.h). Each hook runs
 * the shared per-thread bookkeeping and then dispatches to the capabilities
 * compiled in (PPC_CAP_<NAME>). A tracepoint can have only one probe per
 * program, which is why the dispatch lives here.
 */

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct pkey k = {};
    u32 level = 0, cpid = 0;

    thread_exit();                       /* every thread (F4) */
    if (!args->group_dead)
        return 0;
    if (resolve(&k, &level, &cpid) != 0)
        return 0;
    hinc(H_EXIT);
#ifdef PPC_CAP_COUNTS
    counts_on_exit(&k);
#endif
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct pkey k = {};
    u32 level = 0, cpid = 0;

    thread_exec((u32)args->old_pid);
    if (resolve(&k, &level, &cpid) != 0)
        return 0;
    if (excluded.lookup(&k.tgid))
        return 0;
#ifdef PPC_CAP_COUNTS
    counts_on_exec(&k);
#endif
    return 0;
}
