"""Fault injectors. Each one creates a real latency spike through a
different mechanism, and each is cleanly start/stop.

Honest limits, up front:
- CPU throttling is simulated by duty cycling the server process
  with SIGSTOP/SIGCONT. A real cgroup cpu.max limit is enforced by
  the kernel scheduler and also shows up in cpu.stat nr_throttled;
  the simulation reproduces the visible symptom (the process is
  periodically not running despite having work) without needing
  write access to cgroupfs.
- Network faults go through a userspace TCP proxy. A proxy cannot
  drop packets the kernel has already accepted, so "loss" here means
  the proxy accepts a connection, reads the request, blackholes it
  for a bounded hold time, and then resets the connection without
  answering. From above TCP that is what loss looks like anyway: a
  stall, then a failure, then a retry on a fresh connection. The
  churn is real TCP behavior (new SYNs, TIME_WAIT growth), but it is
  not the same as tc/netem dropping packets on a wire, and on
  loopback it produces few if any kernel level retransmits, which
  the diagnoser has to cope with honestly.
"""

import os
import random
import signal
import socket
import struct
import threading
import time


def _busy_worker(stop_flag_path):
    """Busy loop process body. Pinned to the available CPUs so it
    competes for the same cores the server wants."""
    try:
        os.sched_setaffinity(0, set(range(len(os.sched_getaffinity(0)))))
    except (AttributeError, OSError):
        pass
    x = 0
    while not os.path.exists(stop_flag_path):
        for i in range(10000):
            x += i * i
    return x


class CpuSaturationInjector:
    """Spawn busy processes that saturate every CPU."""

    def __init__(self, workers=None):
        self.workers = workers or (len(os.sched_getaffinity(0)) + 1)
        self._procs = []
        self._flag = None

    def start(self):
        import multiprocessing
        import tempfile
        fd, self._flag = tempfile.mkstemp(prefix="netspike-stop-")
        os.close(fd)
        os.unlink(self._flag)  # workers run while the flag is absent
        ctx = multiprocessing.get_context("fork")
        for _ in range(self.workers):
            proc = ctx.Process(target=_busy_worker, args=(self._flag,),
                               daemon=True)
            proc.start()
            self._procs.append(proc)
        return self

    def stop(self):
        if self._flag:
            # Create the flag file: workers notice and exit.
            with open(self._flag, "w") as handle:
                handle.write("stop")
        for proc in self._procs:
            proc.join(timeout=2.0)
            if proc.is_alive():
                proc.terminate()
        self._procs = []
        if self._flag and os.path.exists(self._flag):
            os.unlink(self._flag)
        self._flag = None


class CpuThrottleInjector:
    """Duty cycle a pid with SIGSTOP / SIGCONT to mimic the visible
    effect of a cgroup CPU limit: runnable work, no CPU."""

    def __init__(self, pid, stop_fraction=0.75, period_s=0.12):
        self.pid = pid
        self.stop_fraction = stop_fraction
        self.period_s = period_s
        self._stop = threading.Event()
        self._thread = None

    def _run(self):
        stop_s = self.period_s * self.stop_fraction
        run_s = self.period_s - stop_s
        while not self._stop.is_set():
            try:
                os.kill(self.pid, signal.SIGSTOP)
            except (ProcessLookupError, PermissionError):
                return
            if self._stop.wait(stop_s):
                break
            try:
                os.kill(self.pid, signal.SIGCONT)
            except (ProcessLookupError, PermissionError):
                return
            self._stop.wait(run_s)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        # Never leave the target stopped.
        try:
            os.kill(self.pid, signal.SIGCONT)
        except (ProcessLookupError, PermissionError):
            pass


class TcpProxy:
    """Userspace TCP proxy with delay, jitter, and drop controls.

    One connection at a time per thread, one request/response round
    per connection, matching the echo server protocol. Stats are
    kept in self.stats: connections, forwarded, dropped, and the
    total artificial delay applied.
    """

    def __init__(self, target_port, host="127.0.0.1", delay_ms=0.0,
                 jitter_ms=0.0, drop_rate=0.0, drop_hold_ms=0.0,
                 seed=1234):
        self.target_port = target_port
        self.host = host
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.drop_rate = drop_rate
        self.drop_hold_ms = drop_hold_ms
        self._rng = random.Random(seed)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(128)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = None
        self.stats = {"connections": 0, "forwarded": 0, "dropped": 0,
                      "delay_ms_total": 0.0}
        self._lock = threading.Lock()

    def _bump(self, key, amount=1):
        with self._lock:
            self.stats[key] += amount

    def _read_line(self, sock):
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def _reset_close(self, conn):
        # SO_LINGER with a zero timeout: close sends a RST instead of
        # a FIN, which is what makes the peer stack react (and, for
        # data still in flight, retransmit) rather than shut down
        # politely.
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
        except OSError:
            pass
        conn.close()

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            self._bump("connections")
            data = self._read_line(conn)
            if not data:
                conn.close()
                return
            if self._rng.random() < self.drop_rate:
                self._bump("dropped")
                if self.drop_hold_ms > 0:
                    # Blackhole first, reset second: the client sits
                    # in a stall the way it would after real loss,
                    # instead of getting an instant reset.
                    time.sleep(self.drop_hold_ms / 1000.0)
                self._reset_close(conn)
                return
            with socket.create_connection((self.host, self.target_port),
                                          timeout=5.0) as upstream:
                upstream.settimeout(5.0)
                upstream.sendall(data)
                reply = self._read_line(upstream)
            delay_ms = self.delay_ms
            if self.jitter_ms:
                delay_ms += self._rng.uniform(0, self.jitter_ms)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
                self._bump("delay_ms_total", delay_ms)
            conn.sendall(reply)
            self._bump("forwarded")
            conn.close()
        except OSError:
            try:
                conn.close()
            except OSError:
                pass

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def stats_snapshot(self):
        with self._lock:
            return dict(self.stats)
