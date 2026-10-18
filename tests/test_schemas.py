"""Schema and validator tests: the stdlib validator must agree with the
reference `jsonschema` implementation on valid and invalid fixtures."""

import copy

import pytest

from processpulse.validate import RECORD_TYPES, Validator, load_schema

BOOT = "d8272aeb-2d00-4ca0-9e4a-11dab89ea8cc"

PROC = {
    "type": "proc", "v": 1, "seq": 0, "t_mono_ns": 123, "pid": 846, "comm": "sleep",
    "comm_utf8_valid": True, "comm_truncated": False, "state": "S", "ppid": 821,
    "starttime_ticks": 5000, "utime": 0, "stime": 1, "num_threads": 1,
    "rss_kb": 512, "rss_err": None, "uid_real": 0, "uid_eff": 0, "uid_err": None,
    "vol_ctxsw": 3, "nonvol_ctxsw": 0, "ctxsw_err": None,
    "io": None, "io_err": "EACCES", "fd_count": None, "fd_err": "EACCES",
    "cgroup": "/system.slice/docker-" + "a" * 64 + ".scope", "cgroup_err": None, "partial": False,
}

BEGIN = {"type": "sample_begin", "v": 1, "seq": 0, "t_mono_ns": 100, "t_wall_ns": 1, "clk_tck": 100,
         "page_size": 4096, "boot_id": BOOT, "pidns_ino": 4026532219, "euid": 1000,
         "collector_pid": 42}

END = {"type": "sample_end", "v": 1, "seq": 0, "t_mono_ns": 200, "dur_ns": 100, "pids_seen": 1,
       "emitted": 1, "gone": 0, "denied": 0, "parse_errors": 0, "read_errors": 0, "io_denied": 1,
       "fd_denied": 1, "late_ns": 0, "readdir_err": None}

COUNTS = {s: 0 for s in ("execve", "execveat", "open", "openat", "openat2", "clone", "clone3",
                         "fork", "vfork")}

SNAPSHOT = {
    "type": "syscall_snapshot", "v": 1, "seq": 0, "t_mono_ns": 300, "interval_ns": None,
    "resource_seq": 0,
    "probe": {"mode": "per_syscall_tracepoints", "syscalls": list(COUNTS), "attached_since_mono_ns": 1},
    "calibration": {"boot_id": BOOT, "distro_level": 2, "distro_pidns_ino": 4026532219},
    "procs": [{
        "key": {"boot_id": BOOT, "pidns_ino": 4026532219, "tgid": 846, "start_ticks": 5000},
        "host_tgid": 1200, "level": 3, "container_pid": 1, "comm": "sleep",
        "container": {"cgroup_id": 9999, "cgroup_path": "/system.slice/docker-" + "a" * 64 + ".scope",
                      "container_id": "a" * 64, "runtime": "docker", "attribution": "docker",
                      "stale": False},
        "counts": dict(COUNTS, openat=5), "exited": False,
    }],
    "health": {"map_entries": 1, "map_capacity": 16384, "counts_map_full": 0, "info_map_full": 0,
               "unresolved_events": 0, "self_excluded_events": 0, "exit_events": 0, "reclaimed": 0,
               "snapshot_ns": 10},
}

HEALTH = {
    "type": "health", "v": 1, "seq": 0, "t_mono_ns": 400,
    "resource": {"alive": True, "epoch": 0, "restarts": 0, "last_exit_code": None, "lines": 3,
                 "malformed_json": 0, "invalid_utf8": 0, "oversize_lines": 0, "partial_tail": 0,
                 "not_object": 0, "schema_errors": 0, "framing_errors": 0, "dropped_samples": 0,
                 "samples": 1},
    "syscall": {"available": False, "reason": "disabled (--no-bpf)"},
    "alignment_skew_ns": None,
}

VALID = [BEGIN, PROC, END, SNAPSHOT, HEALTH]


def _mut(rec, path, value=..., delete=False):
    r = copy.deepcopy(rec)
    node = r
    for k in path[:-1]:
        node = node[k]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return r


INVALID = [
    _mut(PROC, ["pid"], 0),                         # minimum
    _mut(PROC, ["utime"], -1),                      # negative counter (D3)
    _mut(PROC, ["comm"], delete=True),              # required
    _mut(PROC, ["extra"], 1),                       # additionalProperties
    _mut(PROC, ["io_err"], "EWHATEVER"),            # enum
    _mut(PROC, ["state"], '"'),                     # pattern
    _mut(PROC, ["utime"], True),                    # bool is not an integer
    _mut(BEGIN, ["boot_id"], "not-a-uuid"),
    _mut(BEGIN, ["v"], 2),                          # schema version
    _mut(SNAPSHOT, ["procs", 0, "counts", "openat"], -5),
    _mut(SNAPSHOT, ["procs", 0, "container", "attribution"], "k8s"),
    _mut(SNAPSHOT, ["probe", "mode"], "raw_syscalls"),
    _mut(HEALTH, ["resource", "alive"], None),
]

# Semantic (cross-field) violations that JSON Schema alone does not catch.
SEMANTIC_INVALID = [
    _mut(PROC, ["rss_err"], "EACCES"),              # value and error both set
    _mut(PROC, ["fd_err"], None),                   # value and error both null
    _mut(_mut(PROC, ["uid_eff"], None), ["uid_err"], None),
    _mut(SNAPSHOT, ["procs", 0, "container_pid"], None),
    _mut(SNAPSHOT, ["procs", 0, "key", "pidns_ino"], 1),
]


def test_schema_declares_every_record_type():
    schema = load_schema()
    assert set(RECORD_TYPES) <= set(schema["$defs"])
    assert len(schema["oneOf"]) == len(RECORD_TYPES)


@pytest.mark.parametrize("rec", VALID, ids=[r["type"] for r in VALID])
def test_valid_fixtures(rec):
    assert Validator().errors(rec) == []


@pytest.mark.parametrize("rec", INVALID)
def test_invalid_fixtures_rejected(rec):
    assert Validator().errors(rec)


@pytest.mark.parametrize("rec", SEMANTIC_INVALID)
def test_semantic_violations_rejected(rec):
    assert Validator().errors(rec)


def test_unknown_type_rejected():
    assert Validator().errors({"type": "nope", "v": 1})
    assert Validator().errors([1, 2])


def test_unsupported_keyword_is_refused():
    schema = load_schema()
    schema["$defs"]["proc"]["maxProperties"] = 3
    with pytest.raises(ValueError):
        Validator(schema)


def test_jsonschema_reference_agrees():
    jsonschema = pytest.importorskip("jsonschema")
    js = jsonschema.Draft202012Validator(load_schema())
    for rec in VALID:
        assert not list(js.iter_errors(rec)), rec["type"]
    for rec in INVALID:
        assert list(js.iter_errors(rec)), rec
