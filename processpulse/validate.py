"""Stdlib-only validation of telemetry records against schemas/telemetry.v{1,2}.json.

The JSON Schema files are the single source of truth. This module implements
the subset of JSON Schema keywords those files use, so the agent needs no
third-party dependency; tests cross-check it against the `jsonschema` package.
Records are dispatched on their "type" field to the matching $defs entry of
the schema version that defines that type (v1: resource/syscall/health
records; v2: the BPF snapshot protocol). The "v" field must then match.

semantic_errors() adds the cross-field rules a JSON Schema cannot express
compactly, e.g. "a null measurement must carry an error code".
v2_proc_semantic_errors() checks a bpf_proc against its snapshot's begin
record (calibration), which a single-record check cannot see.
"""

import json
import os
import re

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schemas", "telemetry.v1.json")
SCHEMA_V2_PATH = os.path.join(os.path.dirname(__file__), "schemas", "telemetry.v2.json")

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}

_SUPPORTED = {
    "$schema", "$id", "$ref", "$defs", "title", "description", "type", "required",
    "properties", "additionalProperties", "enum", "const", "minimum", "maximum", "pattern",
    "items", "oneOf",
}

RECORD_TYPES = ("sample_begin", "proc", "sample_end", "syscall_snapshot", "health")
RECORD_TYPES_V2 = ("bpf_snapshot_begin", "bpf_proc", "bpf_reclaimed", "bpf_snapshot_end")


def load_schema(path=SCHEMA_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class Validator:
    def __init__(self, schema=None, schema_v2=None):
        self.schema = schema if schema is not None else load_schema()
        self.schema_v2 = schema_v2 if schema_v2 is not None else load_schema(SCHEMA_V2_PATH)
        self._defs_by_type = {}
        for sch, types in ((self.schema, RECORD_TYPES), (self.schema_v2, RECORD_TYPES_V2)):
            self._check_keywords(sch)
            for t in types:
                self._defs_by_type[t] = sch["$defs"]
        self.defs = self.schema["$defs"]
        self._patterns = {}

    def _check_keywords(self, node):
        """Rejects schema keywords this validator would silently ignore."""
        if isinstance(node, dict):
            for k, v in node.items():
                # Under "properties" / "$defs" the keys are names, not keywords.
                if k in ("properties", "$defs"):
                    for sub in v.values():
                        self._check_keywords(sub)
                elif k not in _SUPPORTED:
                    raise ValueError(f"schema keyword {k!r} not supported by validate.py")
                elif isinstance(v, (dict, list)):
                    self._check_keywords(v)
        elif isinstance(node, list):
            for item in node:
                self._check_keywords(item)

    def errors(self, record):
        """Returns a list of human-readable errors (empty when valid)."""
        if not isinstance(record, dict):
            return ["record is not an object"]
        rtype = record.get("type")
        defs = self._defs_by_type.get(rtype)
        if defs is None:
            return [f"unknown record type {rtype!r}"]
        out = []
        self._validate(record, defs[rtype], rtype, out, defs)
        if not out:
            out.extend(semantic_errors(record))
        return out

    def _resolve(self, node, defs):
        while "$ref" in node:
            ref = node["$ref"]
            if not ref.startswith("#/$defs/"):
                raise ValueError(f"unsupported $ref {ref}")
            node = defs[ref[len("#/$defs/"):]]
        return node

    def _validate(self, value, node, path, out, defs):
        node = self._resolve(node, defs)
        if "type" in node:
            types = node["type"] if isinstance(node["type"], list) else [node["type"]]
            if not any(_TYPES[t](value) for t in types):
                out.append(f"{path}: expected {'/'.join(types)}, got {type(value).__name__}")
                return
        if "const" in node and value != node["const"]:
            out.append(f"{path}: expected {node['const']!r}, got {value!r}")
        if "enum" in node and value not in node["enum"]:
            out.append(f"{path}: {value!r} not in {node['enum']}")
        if "minimum" in node and _TYPES["number"](value) and value < node["minimum"]:
            out.append(f"{path}: {value} < minimum {node['minimum']}")
        if "maximum" in node and _TYPES["number"](value) and value > node["maximum"]:
            out.append(f"{path}: {value} > maximum {node['maximum']}")
        if "pattern" in node and isinstance(value, str):
            rx = self._patterns.setdefault(node["pattern"], re.compile(node["pattern"]))
            if not rx.search(value):
                out.append(f"{path}: {value!r} does not match {node['pattern']}")
        if isinstance(value, dict):
            for req in node.get("required", ()):
                if req not in value:
                    out.append(f"{path}: missing required field {req!r}")
            props = node.get("properties", {})
            for k, v in value.items():
                if k in props:
                    self._validate(v, props[k], f"{path}.{k}", out, defs)
                elif node.get("additionalProperties") is False:
                    out.append(f"{path}: unexpected field {k!r}")
        if isinstance(value, list) and "items" in node:
            for i, item in enumerate(value):
                self._validate(item, node["items"], f"{path}[{i}]", out, defs)


# (value field(s), error field) pairs for proc records: exactly one side is set.
_PROC_PAIRS = (
    (("rss_kb",), "rss_err"),
    (("uid_real", "uid_eff"), "uid_err"),
    (("vol_ctxsw", "nonvol_ctxsw"), "ctxsw_err"),
    (("io",), "io_err"),
    (("fd_count",), "fd_err"),
    (("cgroup",), "cgroup_err"),
)


def semantic_errors(record):
    out = []
    if record.get("type") == "proc":
        for fields, err in _PROC_PAIRS:
            present = [record[f] is not None for f in fields]
            if any(present) and not all(present):
                out.append(f"proc: {fields} must be all null or all set")
            if all(present) == (record[err] is not None):
                out.append(f"proc: exactly one of {fields} / {err} must be set")
    elif record.get("type") == "syscall_snapshot":
        for i, p in enumerate(record["procs"]):
            if (p["level"] > record["calibration"]["distro_level"]) != (p["container_pid"] is not None):
                out.append(f"procs[{i}]: container_pid must be set iff level > distro_level")
            if p["key"]["pidns_ino"] != record["calibration"]["distro_pidns_ino"]:
                out.append(f"procs[{i}]: key.pidns_ino differs from calibration")
    elif record.get("type") == "bpf_snapshot_end":
        if record["status"] == "ok":
            if record["reason"] is not None or record["read_err"] is not None:
                out.append("bpf_snapshot_end: status ok carries no reason / read_err")
            if record["loss"] is None or record["health"] is None:
                out.append("bpf_snapshot_end: status ok requires loss and health")
        else:
            if record["reason"] is None or record["read_err"] is None:
                out.append("bpf_snapshot_end: status failed requires reason and read_err")
            if record["loss"] is not None or record["health"] is not None:
                out.append("bpf_snapshot_end: status failed carries no loss / health")
            if record["procs_emitted"] or record["reclaimed_records"] or record["reclaimed_keys"]:
                out.append("bpf_snapshot_end: status failed carries no records")
    elif record.get("type") == "bpf_reclaimed":
        if not record["keys"]:
            out.append("bpf_reclaimed: keys must not be empty")
    return out


def v2_proc_semantic_errors(begin, proc):
    """Cross-record rules for a bpf_proc within the snapshot opened by begin."""
    cal = begin["calibration"]
    out = []
    if (proc["level"] > cal["distro_level"]) != (proc["container_pid"] is not None):
        out.append("bpf_proc: container_pid must be set iff level > distro_level")
    if proc["key"]["pidns_ino"] != cal["distro_pidns_ino"]:
        out.append("bpf_proc: key.pidns_ino differs from calibration")
    if proc["key"]["boot_id"] != cal["boot_id"]:
        out.append("bpf_proc: key.boot_id differs from calibration")
    return out
