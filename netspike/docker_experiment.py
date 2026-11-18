"""Multi-container experiment: the latency faults, in real
containers on a real bridge network.

Where experiment.py runs everything on one loopback and
real_experiment.py uses one host's cgroup and loopback qdisc, this
module runs the server and the client as separate Docker
containers on a user-defined bridge network, so traffic crosses a
veth pair and a bridge, and the counters are the containers' own:

- Server containers run from this project's image (see Dockerfile)
  with --cap-add NET_ADMIN, so tc works inside them.
- The CPU phase starts the server with a real container CPU limit
  (--cpus=0.25) and a CPU-hungry workload (server --work mode). The
  diagnosis evidence is the container's own cgroup cpu.stat, read
  with `docker exec ... cat /sys/fs/cgroup/cpu.stat`, which under
  Docker is the container's cgroup, not the host's.
- The network phases apply netem to the server container's eth0
  (`docker exec ... tc qdisc add dev eth0 root netem ...`): delay
  50ms, then loss 15%. Diagnosis uses the kernel TCP counters read
  from the server container's /proc/net/snmp plus the latency the
  client container measured.
- Snapshots inside the server container are shaped exactly like
  collectors.collect_all() output, so diagnose.diff_snapshots()
  and diagnose.diagnose() are reused unchanged, including the
  baseline_features the diagnoser's relative saturation rule
  needs (built from the baseline phase's in-container schedstat,
  pressure, and window).

Cleanup is unconditional: every container this module creates is
removed with `docker rm -f` and the network with
`docker network rm`, from a finally block.

When Docker is absent (no executable, or no reachable daemon) the
module degrades gracefully: it prints a clear message, writes a
results file that records available: false with the reason, and
exits 0. The command construction and the output parsers are pure
functions and are unit tested without a daemon.

Usage:
    python -m netspike.docker_experiment [--out results-docker.json]
                                         [--count 50]
Requires: Docker, and the image built from this repo's Dockerfile
(this module builds it: docker build -t netspike:latest .).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

from . import collectors, diagnose

IMAGE = "netspike:latest"
NETWORK = "netspike-net"
SERVER_NAME = "netspike-server"
LIMITED_SERVER_NAME = "netspike-server-limited"
SERVER_PORT = 8765
CPU_LIMIT = 0.25
TC_DELAY_SPEC = "delay 50ms 10ms"
TC_LOSS_SPEC = "loss 15%"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(cmd, timeout=120):
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout)


# ------------------------------------------------------- availability

def docker_available(runner=None, which=None):
    """Return (available, reason). Two distinct failure modes: no
    docker executable at all, and an executable with no reachable
    daemon -- the message says which, because the fix differs."""
    which = which or shutil.which
    if which("docker") is None:
        return False, "docker executable not found on PATH"
    runner = runner or _run
    try:
        proc = runner(["docker", "info"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "docker info failed: %s" % exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return False, "docker daemon not reachable: %s" % detail[:200]
    return True, "ok"


# ------------------------------------------------- command builders
# Pure functions returning argv lists. Nothing here executes, so the
# exact commands can be unit tested and shown to a reader.

def build_image_cmd(context=None):
    return ["docker", "build", "-t", IMAGE, context or PROJECT_ROOT]


def network_create_cmd():
    return ["docker", "network", "create", NETWORK]


def network_rm_cmd():
    return ["docker", "network", "rm", NETWORK]


def server_run_cmd(name=SERVER_NAME, cpus=None, work=False):
    cmd = ["docker", "run", "-d", "--name", name,
           "--network", NETWORK, "--cap-add", "NET_ADMIN"]
    if cpus:
        cmd += ["--cpus", str(cpus)]
    cmd += [IMAGE, "python", "-m", "netspike.server", str(SERVER_PORT)]
    if work:
        cmd.append("--work")
    return cmd


def client_measure_cmd(count=50, host=SERVER_NAME, timeout_s=2.0,
                       retries=0, min_window_s=0.0):
    cmd = ["docker", "run", "--rm", "--network", NETWORK, IMAGE,
           "python", "-m", "netspike.measure_cli",
           "--host", host, "--port", str(SERVER_PORT),
           "--count", str(count), "--timeout", str(timeout_s),
           "--retries", str(retries)]
    if min_window_s:
        cmd += ["--min-window", str(min_window_s)]
    return cmd


def exec_cmd(name, *args):
    return ["docker", "exec", name] + [str(a) for a in args]


def read_file_cmd(name, path):
    return exec_cmd(name, "cat", path)


def tc_add_cmd(name, spec):
    return exec_cmd(name, "tc", "qdisc", "add", "dev", "eth0",
                    "root", "netem", *spec.split())


def tc_del_cmd(name):
    return exec_cmd(name, "tc", "qdisc", "del", "dev", "eth0", "root")


def container_rm_cmd(name):
    return ["docker", "rm", "-f", name]


def wait_ready_cmd(name):
    """Probe the server from inside its own container."""
    return exec_cmd(name, "python", "-c",
                    "import socket; "
                    "socket.create_connection(('127.0.0.1', %d), 1)"
                    % SERVER_PORT)


# ------------------------------------------------------------ parsers

def parse_measure_output(text):
    """Extract the measure_cli JSON object from captured stdout.
    Container output can carry noise around the JSON line, so scan
    lines from the end and take the first that parses as an object
    with a summary. Raises ValueError when there is none."""
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict) and "summary" in parsed:
            return parsed
    raise ValueError("no measure_cli JSON found in output")


def _delta_dict(before, after):
    out = {}
    for key in set(before) | set(after):
        if key in before and key in after:
            out[key] = after[key] - before[key]
    return out


def cgroup_feature_delta(before_text, after_text):
    """Feature-dict entries from two cpu.stat texts (the container's
    own cgroup before and after a phase)."""
    before = collectors.parse_cgroup_cpu_stat(before_text or "")
    after = collectors.parse_cgroup_cpu_stat(after_text or "")
    delta = _delta_dict(before, after)
    features = {}
    if "throttled_usec" in delta:
        features["cgroup_throttled_us"] = delta["throttled_usec"]
    if "nr_throttled" in delta:
        features["cgroup_nr_throttled"] = delta["nr_throttled"]
    return features


def snmp_feature_delta(before_text, after_text):
    """Feature-dict entries from two /proc/net/snmp texts."""
    before = (collectors.parse_snmp(before_text or "") or {}).get("tcp") or {}
    after = (collectors.parse_snmp(after_text or "") or {}).get("tcp") or {}
    delta = _delta_dict(before, after)
    features = {}
    if "RetransSegs" in delta:
        features["tcp_retrans_delta"] = delta["RetransSegs"]
    if "OutSegs" in delta:
        features["tcp_outsegs_delta"] = delta["OutSegs"]
    return features


# ------------------------------------------------------- orchestration

def _checked(runner, cmd, timeout=120):
    proc = runner(cmd, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError("command failed (%s): %s"
                           % (" ".join(cmd),
                              (proc.stderr or proc.stdout or "").strip()))
    return proc


def _container_snapshot(runner, name, at_time):
    """A collect_all()-shaped snapshot of the server container, from
    docker exec cat of the same kernel files the host collectors
    read. The server is PID 1 in its container, so its schedstat is
    /proc/1/schedstat. Missing files simply stay out of the dict,
    and diff_snapshots treats them as unavailable, as on the host."""
    snapshot = {"time": at_time}

    def _read(path, parser):
        proc = runner(read_file_cmd(name, path), timeout=30)
        if proc.returncode != 0:
            return None
        return parser(proc.stdout)

    snapshot["pressure_cpu"] = _read("/proc/pressure/cpu",
                                     collectors.parse_pressure)
    snapshot["pressure_io"] = _read("/proc/pressure/io",
                                    collectors.parse_pressure)
    snmp = _read("/proc/net/snmp", collectors.parse_snmp)
    snapshot["snmp_tcp"] = (snmp or {}).get("tcp") if snmp else None
    snapshot["cgroup_cpu"] = _read("/sys/fs/cgroup/cpu.stat",
                                   collectors.parse_cgroup_cpu_stat)
    snapshot["schedstat"] = _read("/proc/1/schedstat",
                                  collectors.parse_schedstat)
    return snapshot


def _wait_ready(runner, name, tries=50):
    for _ in range(tries):
        proc = runner(wait_ready_cmd(name), timeout=10)
        if proc.returncode == 0:
            return True
        time.sleep(0.2)
    return False


def _measure_phase(runner, server_name, count, timeout_s=2.0,
                   retries=0, min_window_s=0.0, host=None):
    """Snapshot in-container, measure from the client container,
    snapshot again, diff. Returns (summary, features)."""
    before = _container_snapshot(runner, server_name, time.time())
    proc = _checked(runner, client_measure_cmd(
        count=count, host=host or server_name, timeout_s=timeout_s,
        retries=retries, min_window_s=min_window_s), timeout=600)
    measured = parse_measure_output(proc.stdout)
    after = _container_snapshot(runner, server_name, time.time())
    features = diagnose.diff_snapshots(before, after)
    return measured["summary"], features


def run_docker_experiment(out_path="results-docker.json", count=50,
                          runner=None, which=None):
    runner = runner or _run
    available, reason = docker_available(runner=runner, which=which)
    results = {"available": available, "image": IMAGE,
               "network": NETWORK, "phases": []}
    if not available:
        results["reason"] = reason
        with open(out_path, "w") as handle:
            json.dump(results, handle, indent=2, default=str)
        print("Docker is not available on this machine: %s" % reason)
        print("The multi-container experiment needs a Docker daemon; "
              "nothing was run. Wrote %s" % out_path)
        return results

    created = []
    network_created = False

    def start_server(name, cpus=None, work=False):
        _checked(runner, server_run_cmd(name=name, cpus=cpus,
                                        work=work), timeout=60)
        created.append(name)
        if not _wait_ready(runner, name):
            raise RuntimeError("server container %s did not come up"
                               % name)

    def stop_server(name):
        runner(container_rm_cmd(name), timeout=60)
        if name in created:
            created.remove(name)

    try:
        _checked(runner, build_image_cmd(), timeout=900)
        _checked(runner, network_create_cmd(), timeout=60)
        network_created = True

        phases = []

        # Baseline: CPU-hungry server, no limit. The baseline
        # features (in-container schedstat, pressure, window) are
        # what the relative saturation rule compares against.
        start_server(SERVER_NAME, work=True)
        base_summary, base_features = _measure_phase(
            runner, SERVER_NAME, count, min_window_s=2.5)
        base_diag = diagnose.diagnose(base_features, base_summary,
                                      base_summary,
                                      baseline_features=base_features)
        phases.append({"name": "baseline", "expected": "unknown",
                       "latency": base_summary,
                       "diagnosis": base_diag["label"],
                       "correct": base_diag["label"] == "unknown",
                       "reasons": base_diag["reasons"],
                       "features": base_features})
        stop_server(SERVER_NAME)

        # CPU limit: same workload, container started with
        # --cpus=0.25. Evidence: the container's own cpu.stat.
        start_server(LIMITED_SERVER_NAME, cpus=CPU_LIMIT, work=True)
        summary, features = _measure_phase(
            runner, LIMITED_SERVER_NAME, count, min_window_s=2.5)
        diag = diagnose.diagnose(features, base_summary, summary,
                                 baseline_features=base_features)
        phases.append({"name": "container_cpu_limit",
                       "expected": "cpu_throttle",
                       "mechanism": "docker run --cpus=%s, server "
                                    "--work workload" % CPU_LIMIT,
                       "latency": summary, "diagnosis": diag["label"],
                       "correct": diag["label"] == "cpu_throttle",
                       "reasons": diag["reasons"],
                       "features": features})
        stop_server(LIMITED_SERVER_NAME)

        # Network phases: plain echo server, netem on its eth0.
        start_server(SERVER_NAME, work=False)
        for name, expected, spec, timeout_s in (
                ("netem_delay", "network_delay", TC_DELAY_SPEC, 2.0),
                ("netem_loss", "network_retransmit", TC_LOSS_SPEC, 3.0)):
            _checked(runner, tc_add_cmd(SERVER_NAME, spec), timeout=30)
            try:
                summary, features = _measure_phase(
                    runner, SERVER_NAME, max(20, count - 10),
                    timeout_s=timeout_s)
            finally:
                runner(tc_del_cmd(SERVER_NAME), timeout=30)
            diag = diagnose.diagnose(features, base_summary, summary,
                                     baseline_features=base_features)
            phases.append({"name": name, "expected": expected,
                           "mechanism": "tc qdisc add dev eth0 root "
                                        "netem %s (server container)"
                                        % spec,
                           "latency": summary,
                           "diagnosis": diag["label"],
                           "correct": diag["label"] == expected,
                           "reasons": diag["reasons"],
                           "features": features})
        stop_server(SERVER_NAME)

        results["phases"] = phases
        scored = [p for p in phases if p["name"] != "baseline"]
        results["accuracy"] = {
            "correct": sum(1 for p in scored if p["correct"]),
            "total": len(scored),
        }
    finally:
        for name in list(created):
            runner(container_rm_cmd(name), timeout=60)
        if network_created:
            runner(network_rm_cmd(), timeout=60)

    with open(out_path, "w") as handle:
        json.dump(results, handle, indent=2, default=str)
    for entry in results["phases"]:
        print("%-20s p99 %10s  %s (%s)"
              % (entry["name"],
                 ("%.2f" % entry["latency"]["p99"])
                 if entry["latency"].get("p99") is not None else "-",
                 entry["diagnosis"],
                 "correct" if entry["correct"] else "WRONG"))
    print("wrote %s" % out_path)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netspike.docker_experiment")
    parser.add_argument("--out", default="results-docker.json")
    parser.add_argument("--count", type=int, default=50)
    args = parser.parse_args(argv)
    run_docker_experiment(out_path=args.out, count=args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
