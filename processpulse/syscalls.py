"""BCC syscall collector (producer of syscall_snapshot records) — M1 interface.

Since M1b S1 the implementation is processpulse.bpf_collector.BpfCollector,
which compiles the unified, capability-flagged program (bpf/common.h +
bpf/syscall_counter.bpf.c + bpf/core.bpf.c). SyscallCollector is that
collector with the "counts" capability only, keeping the M1 constructor,
methods and schema-v1 snapshot record; the vocabulary is
processpulse.vocab.VOCABULARY (the M1 syscall set, unchanged).

Requires root and BCC (python3-bpfcc); see processpulse.preflight.
"""

from .bpf_collector import (HEALTH_FIELDS, V1_HEALTH_FIELDS, BpfCollector, CalibrationError,  # noqa: F401
                            calibrate, family_totals)
from .vocab import FAMILIES, SYSCALLS  # noqa: F401


class SyscallCollector(BpfCollector):
    def __init__(self, max_procs=16384, distro_inum_override=None, resolver=None,
                 track_removals=False):
        super().__init__(capabilities=("counts",), max_procs=max_procs,
                         distro_inum_override=distro_inum_override, resolver=resolver,
                         track_removals=track_removals)
