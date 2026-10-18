"""Unit tests for processpulse.identity."""

import os

from processpulse.identity import (CgroupResolver, ProcessKey, container_identity, parse_container,
                                   start_ticks_from_ns)

CID = "6b4a3410c12506aacecee2f5c69b7eed8e29b4c7c33e9dc505e039aa73dbec8c"


def test_parse_docker_systemd_and_cgroupfs_paths():
    assert parse_container(f"/system.slice/docker-{CID}.scope") == ("docker", CID)
    assert parse_container(f"/docker/{CID}") == ("docker", CID)
    assert parse_container("/init.scope") == (None, None)
    assert parse_container("/user.slice/user-1000.slice/session-1.scope") == (None, None)
    assert parse_container(f"/system.slice/docker-{CID[:12]}.scope") == (None, None)  # short id
    assert parse_container(None) == (None, None)


def test_container_identity_attribution():
    assert container_identity(5, f"/system.slice/docker-{CID}.scope")["attribution"] == "docker"
    assert container_identity(5, "/init.scope")["attribution"] == "host"
    unknown = container_identity(5, None)
    assert unknown["attribution"] == "unknown" and unknown["container_id"] is None


def test_start_ticks_normalisation_matches_kernel_floor():
    assert start_ticks_from_ns(25_259_999_999, 100) == 2525
    assert start_ticks_from_ns(25_260_000_000, 100) == 2526
    assert start_ticks_from_ns(0, 100) == 0


def test_pid_reuse_yields_a_different_key():
    a = ProcessKey("b", 4026532219, 846, 5000)
    assert a != ProcessKey("b", 4026532219, 846, 5001)       # same pid, later start
    assert a != ProcessKey("c", 4026532219, 846, 5000)       # other boot
    assert a == ProcessKey("b", 4026532219, 846, 5000)


def test_resolver_maps_inode_and_flags_stale(tmp_path):
    scope = tmp_path / "system.slice" / f"docker-{CID}.scope"
    scope.mkdir(parents=True)
    ino = os.stat(scope).st_ino
    r = CgroupResolver(root=str(tmp_path), min_rescan_s=0)
    ident = r.identity(ino)
    assert ident["cgroup_path"] == f"/system.slice/docker-{CID}.scope"
    assert ident["container_id"] == CID and ident["stale"] is False

    scope.rmdir()                                  # container exited
    ident = r.identity(ino)
    assert ident["container_id"] == CID and ident["stale"] is True


def test_resolver_unknown_id_and_rescan_rate_limit(tmp_path):
    now = [0.0]
    r = CgroupResolver(root=str(tmp_path), min_rescan_s=1.0, clock=lambda: now[0])
    assert r.identity(123456789)["attribution"] == "unknown"
    assert r.identity(123456789)["attribution"] == "unknown"
    assert r.rescans == 1                          # second miss within 1 s: no rescan
    now[0] = 2.0
    r.identity(123456789)
    assert r.rescans == 2
