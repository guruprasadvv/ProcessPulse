"""Syscall vocabulary: the ordered set of syscalls the BPF collector counts.

The order is part of the definition: a syscall's position is its counter
index (SC_<i>) in the compiled BPF program and its column in snapshot
records. A vocabulary is serialised canonically (fixed key order, compact
JSON, ASCII) and identified by the SHA-256 of that serialisation, so any
change to the version, the syscalls, their order, or the families changes
the identifier. Stdlib only; usable from the Python 3.12 ML environment.
"""

import hashlib
import json
import re
from dataclasses import dataclass

_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class Vocabulary:
    version: int
    syscalls: tuple                  # ordered syscall names
    families: tuple                  # ordered ((family, (member, ...)), ...)

    def __post_init__(self):
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("vocabulary version must be a positive integer")
        if not self.syscalls:
            raise ValueError("vocabulary has no syscalls")
        if len(set(self.syscalls)) != len(self.syscalls):
            raise ValueError("duplicate syscall in vocabulary")
        names = [f for f, _ in self.families]
        if len(set(names)) != len(names):
            raise ValueError("duplicate family in vocabulary")
        seen = set()
        for name in list(self.syscalls) + names:
            if not _NAME.match(name):
                raise ValueError(f"invalid name {name!r}")
        for fam, members in self.families:
            for m in members:
                if m not in self.syscalls:
                    raise ValueError(f"family {fam!r} lists unknown syscall {m!r}")
                if m in seen:
                    raise ValueError(f"syscall {m!r} is in more than one family")
                seen.add(m)

    def canonical(self):
        """Deterministic serialisation the identifier is computed from."""
        doc = {"version": self.version, "syscalls": list(self.syscalls),
               "families": [[f, list(m)] for f, m in self.families]}
        return json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @property
    def sha256(self):
        return hashlib.sha256(self.canonical()).hexdigest()

    @property
    def id(self):
        return f"v{self.version}-{self.sha256[:12]}"

    def index(self, name):
        return self.syscalls.index(name)

    def family_map(self):
        return {f: tuple(m) for f, m in self.families}


# M1 vocabulary (the execve/open/clone families accepted in M1). Changing it
# changes VOCABULARY.id, and tests/test_vocab.py pins the current identifier.
VOCABULARY = Vocabulary(
    version=1,
    syscalls=("execve", "execveat", "open", "openat", "openat2", "clone", "clone3", "fork", "vfork"),
    families=(("execve", ("execve", "execveat")),
              ("open", ("open", "openat", "openat2")),
              ("clone", ("clone", "clone3", "fork", "vfork"))),
)

SYSCALLS = VOCABULARY.syscalls
FAMILIES = VOCABULARY.family_map()
