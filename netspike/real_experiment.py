"""Real-fault experiment: the same blind diagnosis as experiment.py,
but the faults are created by real kernel mechanisms instead of
simulations.

Differences from experiment.py:

- CPU throttling is a real cgroup v2 limit. The server process is
  placed in its own cgroup with cpu.max set to "20000 100000" (20%
  of one CPU) and runs a CPU-hungry request workload. The throttling
  evidence is the cgroup's own cpu.stat: nr_throttled and
  throttled_usec must actually rise, and the diagnoser reads them
  through the normal collectors path (the server pid resolves to
  that cgroup via /proc/<pid>/cgroup). No SIGSTOP anywhere.
- Network delay and loss are real tc/netem qdiscs on loopback:
  "delay 50ms 10ms" and "loss 15%". Server and client are both on
  loopback, so packets really traverse the kernel TCP stack, and
  under loss the kernel Tcp RetransSegs counter in /proc/net/snmp
  must actually rise. The qdisc is removed after every phase and
  from a finally block, even on failure.
- CPU saturation is unchanged: real busy processes on every core.

Each phase runs several independent trials; every trial is
diagnosed blind (the diagnoser sees only kernel counters and
latency summaries, never the phase name). Results are written as
JSON with per-trial detail plus per-phase medians and the key
kernel evidence for each phase.

Requires: Linux, root (or CAP_NET_ADMIN for tc, write access to
cgroupfs for the cgroup), iproute2. If a mechanism is unavailable
the phase is recorded as failed with the exact error, not faked.

Usage:
    python -m netspike.real_experiment [--out results-verda.json]
                                       [--trials 5] [--count 50]
"""

import argparse
import hashlib
import json
import multiprocessing
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time

from . import client, collectors, diagnose, inject
from .experiment import _free_port, _serve, _wait_connectable

CGROUP_NAME = "netspike-exp"
CGROUP_ROOT = "/sys/fs/cgroup"
CPU_MAX_THROTTLE = "20000 100000"  # 20% of one CPU per 100 ms period
TC_DELAY_SPEC = "delay 50ms 10ms"
TC_LOSS_SPEC = "loss 15%"


# ------------------------------------------------------- work server

class WorkServer:
    """Echo server that burns a fixed amount of CPU per request
    (pbkdf2 iterations). A cgroup CPU limit stretches the wall time
    of fixed work, which is exactly what throttling does to a real
    CPU-bound service. The plain EchoServer does almost no work per
    request, so a CPU limit would have nothing to bite on."""

    def __init__(self, host="127.0.0.1", port=0, work_iterations=20000):
        self.host = host
        self.work_iterations = work_iterations
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(128)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if data:
                hashlib.pbkdf2_hmac("sha256", data, b"netspike-work",
                                    self.work_iterations)
                conn.sendall(b"ok " + data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()


def _serve_work(port):
    server = WorkServer(port=port)
    server.serve_forever()


# ------------------------------------------------------------ cgroup

class CgroupCpu:
    """A single cgroup v2 directory with a cpu.max limit."""

    def __init__(self, name=CGROUP_NAME, root=CGROUP_ROOT):
        self.path = os.path.join(root, name)

    def create(self, cpu_max=CPU_MAX_THROTTLE):
        os.makedirs(self.path, exist_ok=True)
        with open(os.path.join(self.path, "cpu.max"), "w") as handle:
            handle.write(cpu_max)

    def add(self, pid):
        with open(os.path.join(self.path, "cgroup.procs"), "w") as handle:
            handle.write(str(pid))

    def cpu_stat(self):
        text = collectors._read_text(os.path.join(self.path, "cpu.stat"))
        return collectors.parse_cgroup_cpu_stat(text) if text else None

    def destroy(self):
        # Any live member would make rmdir fail; callers kill their
        # server first. Best effort: a leftover empty cgroup is
        # harmless, a wrong success claim is not, so report it.
        try:
            os.rmdir(self.path)
            return True
        except OSError:
            return False


# ---------------------------------------------------------------- tc

def tc_netem(spec):
    """Install a netem qdisc on loopback. Raises CalledProcessError
    with stderr captured when tc refuses."""
    return subprocess.run(
        ["tc", "qdisc", "add", "dev", "lo", "root", "netem"]
        + spec.split(),
        check=True, capture_output=True, text=True)


def tc_clear():
    """Remove the root qdisc on loopback. Failure is fine (there may
    be nothing to remove); this is cleanup, not a measurement."""
    subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"],
                   capture_output=True, text=True)


def tc_netem_with_retry(spec):
    """Try to install netem; on failure clear and retry once. Returns
    None on success, or the error text of the second failure."""
    error = None
    for _attempt in range(2):
        try:
            tc_netem(spec)
            return None
        except (subprocess.CalledProcessError, OSError) as exc:
            error = getattr(exc, "stderr", None) or str(exc)
            tc_clear()
            time.sleep(0.3)
    return error.strip() if error else "tc failed"


# ------------------------------------------------------------ trials

def _median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def measure_for(port, count, timeout_s=2.0, retries=0, min_window_s=0.0):
    """Measure like client.measure(), but keep repeating rounds of
    count requests until at least min_window_s has elapsed. The
    diagnoser thresholds in diagnose.py are stated for measurement
    windows of a few seconds; on a fast machine a single round of
    echo requests finishes in milliseconds and the cumulative
    counters (pressure, runqueue wait) never accumulate, so the
    saturation phase asks for a few-seconds window explicitly."""
    latencies = []
    attempts_total = 0
    started = time.perf_counter()
    while True:
        for _ in range(count):
            latency_ms, attempts = client.one_request(
                port, timeout_s=timeout_s, retries=retries)
            latencies.append(latency_ms)
            attempts_total += attempts
        if time.perf_counter() - started >= min_window_s:
            break
    summary = client.summarize(latencies)
    summary["attempts"] = attempts_total
    summary["retries"] = attempts_total - len(latencies)
    return summary


def run_trial(server_pid, port, count, timeout_s=2.0, retries=0,
              min_window_s=0.0):
    """One blind trial: snapshot, measure, snapshot, diff. Diagnosis
    happens later, against the baseline reference summary."""
    before = collectors.collect_all(pid=server_pid, sample_states=False)
    summary = measure_for(port, count, timeout_s=timeout_s,
                          retries=retries, min_window_s=min_window_s)
    after = collectors.collect_all(pid=server_pid, sample_states=True)
    features = diagnose.diff_snapshots(before, after)
    return {"latency": summary, "features": features}


def diagnose_trials(trials, reference, baseline_features=None):
    for trial in trials:
        diag = diagnose.diagnose(trial["features"], reference,
                                 trial["latency"],
                                 baseline_features=baseline_features)
        trial["diagnosis"] = diag["label"]
        trial["reasons"] = diag["reasons"]
    return trials


def median_features(trials):
    """Aggregate a set of trial feature dicts into one reference
    feature dict (median per key), for use as baseline_features.
    Baseline windows are short and their pressure totals are noisy,
    so a median across trials is the honest reference, not any
    single trial."""
    keys = ("window_s", "cpu_pressure_some_us", "schedstat_wait_ms",
            "schedstat_runtime_ms")
    return {key: _median([t["features"].get(key) for t in trials])
            for key in keys}


def aggregate(name, expected, trials, evidence_keys):
    entry = {
        "name": name,
        "expected": expected,
        "trials": len(trials),
        "diagnoses_correct": sum(
            1 for t in trials if t.get("diagnosis") == expected),
        "diagnoses": [t.get("diagnosis") for t in trials],
        "latency_median": {
            key: _median([t["latency"].get(key) for t in trials])
            for key in ("p50", "p95", "p99")
        },
        "evidence_median": {},
        "per_trial": trials,
    }
    for key in evidence_keys:
        entry["evidence_median"][key] = _median(
            [t["features"].get(key) for t in trials])
    # Derived evidence: runqueue wait ratio for the saturation phase.
    ratios = []
    for trial in trials:
        wait = trial["features"].get("schedstat_wait_ms") or 0
        runtime = trial["features"].get("schedstat_runtime_ms") or 0
        if runtime > 0:
            ratios.append(wait / runtime)
    if ratios:
        entry["evidence_median"]["schedstat_wait_ratio"] = _median(ratios)
    return entry


def _start_server(ctx, target, port):
    proc = ctx.Process(target=target, args=(port,), daemon=True)
    proc.start()
    if not _wait_connectable(port):
        proc.terminate()
        raise RuntimeError("server did not come up on port %d" % port)
    return proc


def run_real_experiment(trials=5, count=50, out_path="results-verda.json"):
    ctx = multiprocessing.get_context("fork")
    results = {
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "affinity_cpus": len(os.sched_getaffinity(0)),
        },
        "mechanisms": {
            "cgroup": "cgroup v2 cpu.max=%s in /sys/fs/cgroup/%s"
                      % (CPU_MAX_THROTTLE, CGROUP_NAME),
            "delay": "tc qdisc add dev lo root netem %s" % TC_DELAY_SPEC,
            "loss": "tc qdisc add dev lo root netem %s" % TC_LOSS_SPEC,
            "saturation": "busy processes on every core (inject.py)",
        },
        "phases": [],
        "errors": {},
    }
    phases = {}

    server_port = _free_port()
    server_proc = _start_server(ctx, _serve, server_port)
    server_pid = server_proc.pid
    cgroup = CgroupCpu()
    try:
        # ---- baseline: plain echo server, no fault, 5 trials.
        baseline_trials = []
        for _ in range(trials):
            baseline_trials.append(run_trial(server_pid, server_port,
                                             count))
            time.sleep(0.3)
        reference = {
            "p50": _median([t["latency"]["p50"] for t in baseline_trials]),
            "p95": _median([t["latency"]["p95"] for t in baseline_trials]),
            "p99": _median([t["latency"]["p99"] for t in baseline_trials]),
            "mean": _median([t["latency"]["mean"] for t in baseline_trials]),
            "count": count,
        }
        results["baseline_reference"] = reference
        baseline_features = median_features(baseline_trials)
        results["baseline_features"] = baseline_features
        diagnose_trials(baseline_trials, reference,
                        baseline_features=baseline_features)
        phases["baseline"] = aggregate(
            "baseline", "unknown", baseline_trials,
            ["tcp_retrans_delta", "cgroup_nr_throttled"])

        # ---- CPU saturation: busy processes, unchanged mechanism.
        sat_trials = []
        for _ in range(trials):
            injector = inject.CpuSaturationInjector()
            injector.start()
            try:
                sat_trials.append(run_trial(server_pid, server_port,
                                            count, min_window_s=2.5))
            finally:
                injector.stop()
            time.sleep(0.5)
        diagnose_trials(sat_trials, reference,
                        baseline_features=baseline_features)
        phases["cpu_saturation"] = aggregate(
            "cpu_saturation", "cpu_saturation", sat_trials,
            ["cpu_pressure_some_us", "schedstat_wait_ms",
             "schedstat_runtime_ms"])

        # ---- network delay: real tc/netem on loopback.
        delay_trials = []
        delay_error = None
        for _ in range(trials):
            tc_clear()
            delay_error = tc_netem_with_retry(TC_DELAY_SPEC)
            if delay_error:
                break
            try:
                delay_trials.append(run_trial(server_pid, server_port,
                                              count))
            finally:
                tc_clear()
            time.sleep(0.3)
        if delay_error:
            results["errors"]["network_delay"] = delay_error
            phases["network_delay"] = {
                "name": "network_delay", "expected": "network_delay",
                "trials": len(delay_trials), "failed": True,
                "error": delay_error,
                "per_trial": delay_trials,
            }
        else:
            diagnose_trials(delay_trials, reference,
                            baseline_features=baseline_features)
            phases["network_delay"] = aggregate(
                "network_delay", "network_delay", delay_trials,
                ["tcp_retrans_delta"])

        # ---- network loss: real tc/netem, kernel retransmits.
        loss_trials = []
        loss_error = None
        for _ in range(trials):
            tc_clear()
            loss_error = tc_netem_with_retry(TC_LOSS_SPEC)
            if loss_error:
                break
            try:
                loss_trials.append(run_trial(
                    server_pid, server_port, max(20, count - 10),
                    timeout_s=3.0, retries=0))
            finally:
                tc_clear()
            time.sleep(0.3)
        if loss_error:
            results["errors"]["network_retransmit"] = loss_error
            phases["network_retransmit"] = {
                "name": "network_retransmit",
                "expected": "network_retransmit",
                "trials": len(loss_trials), "failed": True,
                "error": loss_error,
                "per_trial": loss_trials,
            }
        else:
            diagnose_trials(loss_trials, reference,
                            baseline_features=baseline_features)
            phases["network_retransmit"] = aggregate(
                "network_retransmit", "network_retransmit", loss_trials,
                ["tcp_retrans_delta", "tcp_outsegs_delta"])

        # ---- CPU throttling: real cgroup v2 cpu.max limit.
        # Informational reference first: the CPU-hungry work server
        # with no limit, so the throttled numbers have a same-server
        # comparison (3 trials, not part of the scored phases).
        work_ref_trials = []
        for _ in range(3):
            work_port = _free_port()
            work_proc = _start_server(ctx, _serve_work, work_port)
            try:
                work_ref_trials.append(run_trial(work_proc.pid, work_port,
                                                 30))
            finally:
                work_proc.terminate()
                work_proc.join(timeout=3.0)
            time.sleep(0.3)
        results["work_server_unthrottled"] = {
            "trials": len(work_ref_trials),
            "latency_median": {
                key: _median([t["latency"].get(key)
                              for t in work_ref_trials])
                for key in ("p50", "p95", "p99")
            },
        }

        thr_trials = []
        thr_error = None
        for attempt in range(2):
            try:
                cgroup.create(CPU_MAX_THROTTLE)
                thr_error = None
                break
            except OSError as exc:
                thr_error = str(exc)
                time.sleep(0.3)
        if thr_error:
            results["errors"]["cpu_throttle"] = thr_error
            phases["cpu_throttle"] = {
                "name": "cpu_throttle", "expected": "cpu_throttle",
                "trials": 0, "failed": True, "error": thr_error,
                "per_trial": [],
            }
        else:
            try:
                for _ in range(trials):
                    work_port = _free_port()
                    work_proc = _start_server(ctx, _serve_work, work_port)
                    try:
                        cgroup.add(work_proc.pid)
                        time.sleep(0.2)
                        thr_trials.append(run_trial(
                            work_proc.pid, work_port,
                            max(20, count - 10)))
                    finally:
                        work_proc.terminate()
                        work_proc.join(timeout=3.0)
                    time.sleep(0.3)
            finally:
                cgroup.destroy()
            diagnose_trials(thr_trials, reference,
                            baseline_features=baseline_features)
            phases["cpu_throttle"] = aggregate(
                "cpu_throttle", "cpu_throttle", thr_trials,
                ["cgroup_nr_throttled", "cgroup_throttled_us"])
    finally:
        tc_clear()
        server_proc.terminate()
        server_proc.join(timeout=3.0)

    order = ["baseline", "cpu_saturation", "cpu_throttle",
             "network_delay", "network_retransmit"]
    results["phases"] = [phases[name] for name in order if name in phases]

    with open(out_path, "w") as handle:
        json.dump(results, handle, indent=2, default=str)

    print("machine: %s, %s cpus, python %s"
          % (results["machine"]["platform"],
             results["machine"]["cpu_count"],
             results["machine"]["python"]))
    for entry in results["phases"]:
        if entry.get("failed"):
            print("%-20s FAILED: %s" % (entry["name"], entry["error"]))
            continue
        lat = entry["latency_median"]
        print("%-20s p50 %8.2f  p95 %8.2f  p99 %8.2f  correct %d/%d"
              % (entry["name"], lat["p50"], lat["p95"], lat["p99"],
                 entry["diagnoses_correct"], entry["trials"]))
        print("  evidence medians: %s" % entry["evidence_median"])
    print("wrote %s" % out_path)
    return results


def run_saturation_supplement(trials=5, count=30,
                              out_path="results-verda.json"):
    """Supplementary saturation phase, appended to an existing
    results file. The primary cpu_saturation phase runs the busy
    process injector against the echo server, which does almost no
    work per request, so on a fast machine saturation barely moves
    its latency even while cpu pressure accumulates heavily. This
    phase keeps the same injector mechanism (busy processes, here
    2x cores + 1 of them) but points it at the CPU-hungry work
    server, where contention has something to bite on. Both phases
    stay in the results; neither replaces the other."""
    with open(out_path) as handle:
        results = json.load(handle)
    reference = results["baseline_reference"]
    baseline_features = results.get("baseline_features")
    ctx = multiprocessing.get_context("fork")
    workers = 2 * len(os.sched_getaffinity(0)) + 1
    sat_trials = []
    for _ in range(trials):
        work_port = _free_port()
        work_proc = _start_server(ctx, _serve_work, work_port)
        injector = inject.CpuSaturationInjector(workers=workers)
        injector.start()
        try:
            sat_trials.append(run_trial(work_proc.pid, work_port, count,
                                        min_window_s=2.5))
        finally:
            injector.stop()
            work_proc.terminate()
            work_proc.join(timeout=3.0)
        time.sleep(0.5)
    diagnose_trials(sat_trials, reference,
                    baseline_features=baseline_features)
    entry = aggregate("cpu_saturation_cpu_bound", "cpu_saturation",
                      sat_trials,
                      ["cpu_pressure_some_us", "schedstat_wait_ms",
                       "schedstat_runtime_ms"])
    entry["mechanism_note"] = (
        "busy processes x%d (2x cores + 1) against the CPU-hungry "
        "work server, min window 2.5 s; supplementary to the "
        "cpu_saturation phase, which uses the default injector "
        "against the echo server" % workers)
    results["phases"].append(entry)
    with open(out_path, "w") as handle:
        json.dump(results, handle, indent=2, default=str)
    lat = entry["latency_median"]
    print("cpu_saturation_cpu_bound p50 %.2f p95 %.2f p99 %.2f "
          "correct %d/%d" % (lat["p50"], lat["p95"], lat["p99"],
                             entry["diagnoses_correct"], entry["trials"]))
    print("  evidence medians: %s" % entry["evidence_median"])
    print("appended to %s" % out_path)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netspike.real_experiment")
    parser.add_argument("--out", default="results-verda.json")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--add-saturation-work", action="store_true",
                        help="append the supplementary saturation "
                             "phase to an existing results file")
    args = parser.parse_args(argv)
    if args.add_saturation_work:
        run_saturation_supplement(trials=args.trials, count=30,
                                  out_path=args.out)
        return 0
    run_real_experiment(trials=args.trials, count=args.count,
                        out_path=args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
