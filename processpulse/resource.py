"""Supervisor for the C resource collector (producer of resource samples).

Runs `collector --v1`, frames its stdout with JsonlFramer, validates every
record, assembles sample_begin/proc/sample_end into Sample objects and hands
them to the consumer through a bounded queue. Diagnostics (collector stderr,
malformed lines) never mix with telemetry.

Failure handling:
  * the child exiting unexpectedly is restarted with exponential backoff, up
    to max_restarts; each restart increments `epoch` (seq restarts at 0);
  * an incomplete sample (crash mid-sample, framing error) is discarded and
    counted, never forwarded;
  * when the consumer falls behind, the OLDEST complete sample is dropped and
    counted (bounded memory, visible loss).
"""

import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field

from .jsonl import JsonlFramer
from .validate import Validator

DEFAULT_BACKOFF_S = (1, 2, 4, 8, 16, 30)


@dataclass
class Sample:
    epoch: int
    seq: int
    begin: dict
    procs: list
    end: dict
    received_mono_ns: int


@dataclass
class _Stats:
    alive: bool = False
    epoch: int = 0
    restarts: int = 0
    last_exit_code: object = None
    schema_errors: int = 0
    framing_errors: int = 0
    dropped_samples: int = 0
    samples: int = 0
    errors: list = field(default_factory=list)


class ResourceCollector:
    def __init__(self, binary, interval_ms=1000, count=0, max_queue=64, max_restarts=5,
                 backoff_s=DEFAULT_BACKOFF_S, diag=None, extra_args=(), validator=None):
        # binary: a path, or an argv prefix such as [sys.executable, "fake.py"] (tests).
        prefix = list(binary) if isinstance(binary, (list, tuple)) else [binary]
        self.argv = prefix + ["--v1", "--interval-ms", str(interval_ms), "--count", str(count)]
        self.argv += list(extra_args)
        self.count = count
        self.max_restarts = max_restarts
        self.backoff_s = backoff_s
        self.diag = diag                     # writable text file or None
        self.validator = validator or Validator()
        self.framer = JsonlFramer(on_error=self._framer_error)
        self._q = queue.Queue(maxsize=max_queue)
        self._stats = _Stats()
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._proc = None
        self._thread = None
        self._cur = None                     # sample being assembled
        self.on_spawn = None                 # callback(pid) — e.g. BPF self-exclusion

    # --- public interface -------------------------------------------------

    def start(self):
        self._spawn()
        self._thread = threading.Thread(target=self._run, name="resource-collector", daemon=True)
        self._thread.start()

    def get(self, timeout=None):
        """Next complete Sample, or None on timeout / after the stream has ended."""
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def pid(self):
        p = self._proc
        return p.pid if p is not None else None

    @property
    def finished(self):
        return self._thread is not None and not self._thread.is_alive() and self._q.empty()

    def stop(self, timeout=5.0):
        self._stopping.set()
        p = self._proc
        if p is not None and p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def stats(self):
        with self._lock:
            s = self._stats
            out = {
                "alive": s.alive, "epoch": s.epoch, "restarts": s.restarts,
                "last_exit_code": s.last_exit_code, "schema_errors": s.schema_errors,
                "framing_errors": s.framing_errors, "dropped_samples": s.dropped_samples,
                "samples": s.samples,
            }
        out.update(self.framer.stats.as_dict())
        out.pop("records", None)
        return out

    # --- internals ----------------------------------------------------------

    def _log(self, msg):
        if self.diag is not None:
            self.diag.write(f"{time.monotonic_ns()} {msg}\n")
            self.diag.flush()

    def _framer_error(self, kind, raw):
        self._log(f"resource framer {kind}: {raw!r}")

    def _spawn(self):
        # PPC_SUPERVISOR_PID lets the collector detect that we died before it
        # could arm PR_SET_PDEATHSIG (see src/collector.c run_v1).
        env = dict(os.environ, PPC_SUPERVISOR_PID=str(os.getpid()))
        self._proc = subprocess.Popen(
            self.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, env=env)
        threading.Thread(target=self._drain_stderr, args=(self._proc,), daemon=True).start()
        with self._lock:
            self._stats.alive = True
        self._log(f"collector started pid={self._proc.pid} epoch={self._stats.epoch}")
        if self.on_spawn is not None:
            self.on_spawn(self._proc.pid)

    def _drain_stderr(self, proc):
        for line in proc.stderr:
            self._log("collector stderr: " + line.decode("utf-8", "replace").rstrip())

    def _run(self):
        while True:
            fd = self._proc.stdout.fileno()
            while True:
                data = os.read(fd, 65536)
                if not data:
                    break
                for rec in self.framer.feed(data):
                    self._handle(rec)
            self.framer.close()
            code = self._proc.wait()
            self._proc.stdout.close()
            with self._lock:
                self._stats.alive = False
                self._stats.last_exit_code = code
            if self._cur is not None:
                self._framing_error("stream ended inside a sample")
            self._log(f"collector exited code={code}")

            clean = code == 0 and self.count != 0
            if self._stopping.is_set() or clean:
                break
            with self._lock:
                if self._stats.restarts >= self.max_restarts:
                    self._log("collector restart limit reached")
                    break
                delay = self.backoff_s[min(self._stats.restarts, len(self.backoff_s) - 1)]
                self._stats.restarts += 1
                self._stats.epoch += 1
            if self._stopping.wait(delay):
                break
            self._spawn()

    def _framing_error(self, why):
        with self._lock:
            self._stats.framing_errors += 1
        self._log(f"resource framing error: {why}")
        self._cur = None

    def _handle(self, rec):
        errs = self.validator.errors(rec)
        if errs:
            with self._lock:
                self._stats.schema_errors += 1
            self._log(f"resource schema error: {errs[:3]}")
            if rec.get("type") in ("sample_begin", "sample_end"):
                self._cur = None
            return
        t = rec["type"]
        if t == "sample_begin":
            if self._cur is not None:
                self._framing_error("sample_begin before previous sample_end")
            self._cur = {"begin": rec, "procs": []}
        elif t == "proc":
            if self._cur is None or rec["seq"] != self._cur["begin"]["seq"]:
                self._framing_error("proc outside its sample")
                return
            self._cur["procs"].append(rec)
        elif t == "sample_end":
            cur = self._cur
            if cur is None or rec["seq"] != cur["begin"]["seq"]:
                self._framing_error("sample_end without matching sample_begin")
                return
            if rec["emitted"] != len(cur["procs"]):
                self._framing_error("sample_end.emitted differs from proc records received")
                return
            self._cur = None
            with self._lock:
                epoch = self._stats.epoch
            self._enqueue(Sample(epoch, rec["seq"], cur["begin"], cur["procs"], rec,
                                 time.monotonic_ns()))
        else:
            self._framing_error(f"unexpected record type {t}")

    def _enqueue(self, sample):
        while True:
            try:
                self._q.put_nowait(sample)
                break
            except queue.Full:
                try:
                    self._q.get_nowait()
                    with self._lock:
                        self._stats.dropped_samples += 1
                except queue.Empty:
                    pass
        with self._lock:
            self._stats.samples += 1
