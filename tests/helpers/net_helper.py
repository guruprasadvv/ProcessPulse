"""Scripted network helper for the net-capability tests (M1b S3.2).

Protocol (one line each way), like sysc_helper:
    helper -> "READY pid=<pid> tid=<tid>"
    parent -> a command;  helper -> "DONE <ret> <errno>" (or "FD <fd>" for socket/listen)
Commands:
    socket <family> <type>               Python socket; replies "FD <fd>" (kept open)
    listen <family> <type> <addr>        bound, listening socket; "FD <fd> PORT <port>"
                                         (for AF_UNIX addr is a path; port 0)
    connect <fd> <family> <addr> <port> [addrlen]
                                         ONE raw connect(2); family: 2 (inet), 10 (inet6),
                                         1 (unix, addr = path), 0 (AF_UNSPEC)
    nonblock <fd>                        O_NONBLOCK on fd
    accept <fd> | accept4 <fd>           ONE raw accept(2) / accept4(2) (peer buffer NULL)
    open_null                            fd of /dev/null (not a socket); "FD <fd>"
    exec                                 execve() this helper again (new image prints READY)
    exit                                 exit 0
Every connect/accept is exactly one syscall, so the parent's tally is exact.
Only loopback TCP, UDP connect() (which sends no packet) and local sockets are
used by the tests: nothing leaves the host.
"""

import ctypes
import os
import socket
import struct
import sys
import threading

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
NR = {"connect": 42, "accept": 43, "accept4": 288}            # x86_64
KEEP = {}                                                    # fd -> socket object


def sockaddr(family, addr, port):
    if family == 2:
        return struct.pack("=H", 2) + struct.pack("!H", port) + socket.inet_pton(socket.AF_INET, addr) + b"\0" * 8
    if family == 10:
        return (struct.pack("=H", 10) + struct.pack("!H", port) + b"\0" * 4
                + socket.inet_pton(socket.AF_INET6, addr) + b"\0" * 4)
    if family == 1:
        return struct.pack("=H", 1) + addr.encode() + b"\0"
    if family == 0:
        return struct.pack("=H", 0) + b"\0" * 14
    return struct.pack("=H", family) + b"\0" * 14


def raw(nr, *args):
    ctypes.set_errno(0)
    ret = LIBC.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
    return ret, (ctypes.get_errno() if ret < 0 else 0)


def main():
    print(f"READY pid={os.getpid()} tid={threading.get_native_id()}", flush=True)
    for line in sys.stdin:
        w = line.split()
        if not w:
            continue
        cmd = w[0]
        if cmd == "exit":
            return 0
        if cmd == "socket":
            s = socket.socket(int(w[1]), int(w[2]))
            KEEP[s.fileno()] = s
            print(f"FD {s.fileno()}", flush=True)
        elif cmd == "listen":
            fam, typ = int(w[1]), int(w[2])
            s = socket.socket(fam, typ)
            if fam == socket.AF_UNIX:
                s.bind(w[3])
                port = 0
            else:
                s.bind((w[3], 0))
                port = s.getsockname()[1]
            if typ == socket.SOCK_STREAM:
                s.listen(16)
            KEEP[s.fileno()] = s
            print(f"FD {s.fileno()} PORT {port}", flush=True)
        elif cmd == "connect":
            fd, fam, addr, port = int(w[1]), int(w[2]), w[3], int(w[4])
            sa = sockaddr(fam, addr, port)
            alen = int(w[5]) if len(w) > 5 else len(sa)
            buf = ctypes.create_string_buffer(sa, max(len(sa), 128))
            ret, err = raw(NR["connect"], fd, ctypes.addressof(buf), alen)
            print(f"DONE {ret} {err}", flush=True)
        elif cmd == "nonblock":
            KEEP[int(w[1])].setblocking(False)
            print("DONE 0 0", flush=True)
        elif cmd in ("accept", "accept4"):
            args = (int(w[1]), 0, 0) + ((0,) if cmd == "accept4" else ())
            ret, err = raw(NR[cmd], *args)
            if ret >= 0:
                os.close(ret)
            print(f"DONE {ret} {err}", flush=True)
        elif cmd == "open_null":
            fd = os.open("/dev/null", os.O_RDONLY)
            print(f"FD {fd}", flush=True)
        elif cmd == "exec":
            sys.stdout.flush()
            os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])
        else:
            print(f"ERR unknown {cmd}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
