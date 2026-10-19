"""Syscall vocabulary: determinism, a pinned identifier, and sensitivity to every change."""

import subprocess
import sys

import pytest

from processpulse.vocab import FAMILIES, SYSCALLS, VOCABULARY, Vocabulary

PINNED_SHA256 = "3aba869d1752e0501719c1312df9d3d872674dfbc3b6420231afcfff6d4aaa34"
M1_SYSCALLS = ("execve", "execveat", "open", "openat", "openat2", "clone", "clone3", "fork", "vfork")


def test_m1_vocabulary_is_unchanged():
    assert SYSCALLS == M1_SYSCALLS
    assert FAMILIES == {"execve": ("execve", "execveat"), "open": ("open", "openat", "openat2"),
                        "clone": ("clone", "clone3", "fork", "vfork")}


def test_identifier_is_pinned():
    # A deliberate vocabulary change must update this constant (and bump the version).
    assert VOCABULARY.sha256 == PINNED_SHA256
    assert VOCABULARY.id == "v1-" + PINNED_SHA256[:12]


def test_serialisation_is_repeatable_in_process():
    assert len({VOCABULARY.canonical() for _ in range(5)}) == 1
    same = Vocabulary(VOCABULARY.version, tuple(VOCABULARY.syscalls), tuple(VOCABULARY.families))
    assert same.canonical() == VOCABULARY.canonical() and same.id == VOCABULARY.id


def test_serialisation_is_repeatable_across_processes():
    code = "from processpulse.vocab import VOCABULARY as V; print(V.sha256)"
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           check=True, env={"PYTHONHASHSEED": seed, "PYTHONPATH": "."}).stdout.strip()
            for seed in ("0", "1", "12345")}
    assert outs == {PINNED_SHA256}


def _variant(**kw):
    base = dict(version=VOCABULARY.version, syscalls=VOCABULARY.syscalls, families=VOCABULARY.families)
    base.update(kw)
    return Vocabulary(**base)


@pytest.mark.parametrize("change", [
    {"version": 2},
    {"syscalls": M1_SYSCALLS[1:] + M1_SYSCALLS[:1]},                    # order
    {"syscalls": M1_SYSCALLS + ("setuid",)},                            # addition
    {"syscalls": M1_SYSCALLS[:-1],
     "families": (("execve", ("execve", "execveat")), ("open", ("open", "openat", "openat2")),
                  ("clone", ("clone", "clone3", "fork")))},             # removal
    {"families": (("open", ("open", "openat", "openat2")), ("execve", ("execve", "execveat")),
                  ("clone", ("clone", "clone3", "fork", "vfork")))},     # family order
    {"families": (("exec", ("execve", "execveat")), ("open", ("open", "openat", "openat2")),
                  ("clone", ("clone", "clone3", "fork", "vfork")))},     # family name
    {"families": (("execve", ("execve",)), ("open", ("open", "openat", "openat2", "execveat")),
                  ("clone", ("clone", "clone3", "fork", "vfork")))},     # membership
])
def test_any_definition_change_changes_the_identifier(change):
    assert _variant(**change).sha256 != VOCABULARY.sha256


@pytest.mark.parametrize("bad", [
    {"syscalls": ("openat", "openat")},
    {"syscalls": ()},
    {"syscalls": ("Open",)},
    {"version": 0},
    {"families": (("x", ("nosuch",)),)},
    {"families": (("a", ("openat",)), ("b", ("openat",)))},
    {"families": (("a", ()), ("a", ()))},
])
def test_invalid_vocabularies_are_rejected(bad):
    with pytest.raises(ValueError):
        _variant(**bad)


def test_index_is_the_position():
    assert [VOCABULARY.index(s) for s in SYSCALLS] == list(range(len(SYSCALLS)))
