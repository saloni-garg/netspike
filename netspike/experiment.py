"""Run the full experiment: baseline, then each fault in sequence,
diagnosing each phase blind (the diagnoser never sees the fault
name, only kernel counters and latency summaries).

Usage:
    python -m netspike.experiment [--out results.json] [--count 50]

Writes a JSON results file and prints a small table.
"""

import argparse
import json
import multiprocessing
import os
import platform
import socket
import sys
import time

from . import client, collectors, diagnose, inject
from .server import EchoServer


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _serve(port):
    server = EchoServer(port=port)
    server.serve_forever()


def _wait_connectable(port, timeout_s=5.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port),
                                          timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class Phase:
    def __init__(self, name, expected):
        self.name = name
        self.expected = expected
        self.summary = None
        self.features = {}
        self.diagnosis = None
        self.reasons = []


def run_experiment(count=50, out_path="results.json"):
    server_port = _free_port()
    ctx = multiprocessing.get_context("fork")
    server_proc = ctx.Process(target=_serve, args=(server_port,),
                              daemon=True)
    server_proc.start()
    server_pid = server_proc.pid
    if not _wait_connectable(server_port):
        server_proc.terminate()
        raise RuntimeError("server did not come up")

    results = {
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "affinity_cpus": len(os.sched_getaffinity(0)),
        },
        "server_pid": server_pid,
        "phases": [],
    }

    def run_phase(name, expected, client_port, injector=None,
                  proxy=None, **client_kwargs):
        phase = Phase(name, expected)
        proxy_before = proxy.stats_snapshot() if proxy else None
        before = collectors.collect_all(pid=server_pid,
                                        sample_states=False)
        if injector is not None:
            injector.start()
        try:
            phase.summary = client.measure(client_port, **client_kwargs)
            # Snapshot while the fault is still active: the pid state
            # sample in particular only means something mid fault.
            after = collectors.collect_all(pid=server_pid,
                                           sample_states=True)
        finally:
            if injector is not None:
                injector.stop()
        proxy_after = proxy.stats_snapshot() if proxy else None
        phase.features = diagnose.diff_snapshots(
            before, after, proxy_before, proxy_after)
        return phase

    try:
        # Baseline: direct to the server, no fault.
        baseline = run_phase("baseline", "unknown", server_port,
                             count=count, timeout_s=2.0, retries=0)
        base_diag = diagnose.diagnose(baseline.features, baseline.summary,
                                      baseline.summary,
                                      baseline_features=baseline.features)
        baseline.diagnosis = base_diag["label"]
        baseline.reasons = base_diag["reasons"]
        results["baseline"] = {
            "latency": baseline.summary,
            "diagnosis": baseline.diagnosis,
        }
        results["phases"].append({
            "name": "baseline", "expected": "unknown",
            "latency": baseline.summary,
            "diagnosis": baseline.diagnosis,
            "reasons": baseline.reasons, "features": baseline.features,
        })
        time.sleep(1.0)

        faults = []

        # Fault 1: CPU saturation, busy processes on every core.
        sat = inject.CpuSaturationInjector()
        phase = run_phase("cpu_saturation", "cpu_saturation", server_port,
                          injector=sat, count=count, timeout_s=2.0,
                          retries=0)
        faults.append(phase)
        time.sleep(1.0)

        # Fault 2: CPU throttling simulation, SIGSTOP duty cycle.
        thr = inject.CpuThrottleInjector(server_pid, stop_fraction=0.75,
                                         period_s=0.12)
        phase = run_phase("cpu_throttle", "cpu_throttle", server_port,
                          injector=thr, count=count, timeout_s=2.0,
                          retries=0)
        faults.append(phase)
        time.sleep(1.0)

        # Fault 3: network delay through the proxy.
        delay_proxy = inject.TcpProxy(server_port, delay_ms=40.0,
                                      jitter_ms=10.0, drop_rate=0.0)
        delay_proxy.start()
        try:
            phase = run_phase("network_delay", "network_delay",
                              delay_proxy.port, proxy=delay_proxy,
                              count=max(20, count - 10), timeout_s=2.0,
                              retries=0)
        finally:
            delay_proxy.stop()
        faults.append(phase)
        time.sleep(1.0)

        # Fault 4: loss and churn through the proxy. Dropped requests
        # are reset, the client times out and retries on a fresh
        # connection, which is where the tail comes from.
        loss_proxy = inject.TcpProxy(server_port, delay_ms=0.0,
                                     jitter_ms=0.0, drop_rate=0.45,
                                     drop_hold_ms=250.0, seed=99)
        loss_proxy.start()
        try:
            phase = run_phase("network_retransmit", "network_retransmit",
                              loss_proxy.port, proxy=loss_proxy,
                              count=max(20, count - 10), timeout_s=0.35,
                              retries=1)
        finally:
            loss_proxy.stop()
        faults.append(phase)

        correct = 0
        for phase in faults:
            diag = diagnose.diagnose(phase.features, baseline.summary,
                                     phase.summary,
                                     baseline_features=baseline.features)
            phase.diagnosis = diag["label"]
            phase.reasons = diag["reasons"]
            ok = phase.diagnosis == phase.expected
            correct += 1 if ok else 0
            results["phases"].append({
                "name": phase.name, "expected": phase.expected,
                "latency": phase.summary, "diagnosis": phase.diagnosis,
                "correct": ok, "reasons": phase.reasons,
                "features": phase.features,
            })
        results["accuracy"] = {
            "correct": correct, "total": len(faults),
            "fraction": (correct / len(faults)) if faults else None,
        }
    finally:
        server_proc.terminate()
        server_proc.join(timeout=3.0)

    with open(out_path, "w") as handle:
        json.dump(results, handle, indent=2, default=str)

    print("machine: %s, %s cpus (affinity %s), python %s"
          % (results["machine"]["platform"],
             results["machine"]["cpu_count"],
             results["machine"]["affinity_cpus"],
             results["machine"]["python"]))
    print("%-20s %10s %10s  %s" % ("phase", "p50 ms", "p99 ms",
                                   "diagnosis"))
    for entry in results["phases"]:
        lat = entry["latency"]
        mark = ""
        if "correct" in entry:
            mark = " (correct)" if entry["correct"] else " (WRONG, " \
                   "expected %s)" % entry["expected"]
        print("%-20s %10.2f %10.2f  %s%s"
              % (entry["name"], lat["p50"], lat["p99"],
                 entry["diagnosis"], mark))
    acc = results["accuracy"]
    print("diagnosis accuracy: %d/%d faults"
          % (acc["correct"], acc["total"]))
    print("wrote %s" % out_path)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netspike.experiment")
    parser.add_argument("--out", default="results.json")
    parser.add_argument("--count", type=int, default=50)
    args = parser.parse_args(argv)
    run_experiment(count=args.count, out_path=args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
