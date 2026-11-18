"""Kernel signal collectors.

Every collector reads a real kernel interface (a /proc or /sys file),
parses it with a pure function that takes text, and returns a dict.
If the file is missing or unreadable (older kernel, restricted
container, different cgroup setup) the collector returns None instead
of raising, so a snapshot degrades gracefully instead of failing.

The parse_* functions are deliberately separate from the read_*
functions: parsers take text and are unit tested with fixtures,
readers just fetch the text for a path.
"""

import os
import time

PROC = "/proc"
SYS_CGROUP = "/sys/fs/cgroup"


# ---------------------------------------------------------------- parsers

def parse_pressure(text):
    """Parse /proc/pressure/cpu (or io / memory).

    Format:
        some avg10=0.00 avg60=0.00 avg300=0.00 total=123456
        full avg10=0.00 avg60=0.00 avg300=0.00 total=123456
    Returns {"some": {...}, "full": {...}} with float averages and an
    int total (microseconds spent stalled).
    """
    out = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("some", "full"):
            continue
        entry = {}
        for token in parts[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if key == "total":
                entry[key] = int(value)
            else:
                entry[key] = float(value)
        out[parts[0]] = entry
    return out


# Field order on the aggregate "cpu" line of /proc/stat.
_CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq",
               "softirq", "steal", "guest", "guest_nice")
# Field order on the "softirq" line of /proc/stat.
_SOFTIRQ_FIELDS = ("hi", "timer", "net_tx", "net_rx", "block",
                   "block_iopoll", "tasklet", "sched", "hrtimer", "rcu")


def parse_proc_stat(text):
    """Parse the interesting lines of /proc/stat.

    Returns {"cpu": {...with total and idle_all}, "softirq": {...},
    "ctxt": int or None, "processes": int or None}.
    """
    out = {"cpu": {}, "softirq": {}, "ctxt": None, "processes": None}
    for line in text.splitlines():
        if line.startswith("cpu "):
            values = [int(v) for v in line.split()[1:]]
            cpu = dict(zip(_CPU_FIELDS, values))
            cpu["total"] = sum(values)
            cpu["idle_all"] = cpu.get("idle", 0) + cpu.get("iowait", 0)
            out["cpu"] = cpu
        elif line.startswith("softirq "):
            values = [int(v) for v in line.split()[1:]]
            softirq = {"total": values[0]}
            softirq.update(dict(zip(_SOFTIRQ_FIELDS, values[1:])))
            out["softirq"] = softirq
        elif line.startswith("ctxt "):
            out["ctxt"] = int(line.split()[1])
        elif line.startswith("processes "):
            out["processes"] = int(line.split()[1])
    return out


def parse_sockstat(text):
    """Parse /proc/net/sockstat.

    Format:
        sockets: used 123
        TCP: inuse 3 orphan 0 tw 1 alloc 5 mem 0
        UDP: inuse 1 mem 0
    Returns a flat dict like {"sockets_used": 123, "tcp_inuse": 3,
    "tcp_tw": 1, "tcp_alloc": 5, "udp_inuse": 1, ...}.
    """
    out = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        proto = parts[0].rstrip(":").lower()
        rest = parts[1:]
        if proto == "sockets" and len(rest) >= 2 and rest[0] == "used":
            out["sockets_used"] = int(rest[1])
            continue
        # Remaining lines are key/value pairs.
        for i in range(0, len(rest) - 1, 2):
            try:
                out["%s_%s" % (proto, rest[i])] = int(rest[i + 1])
            except ValueError:
                continue
    return out


def parse_snmp(text):
    """Parse /proc/net/snmp into {group: {field: int}}.

    The file is pairs of lines: a header line "Tcp: A B C" followed by
    a values line "Tcp: 1 2 3". Only the pairing matters here.
    """
    out = {}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    i = 0
    while i + 1 < len(lines):
        header = lines[i].split()
        values = lines[i + 1].split()
        if (len(header) >= 2 and len(values) == len(header)
                and header[0] == values[0] and header[0].endswith(":")):
            group = header[0].rstrip(":").lower()
            parsed = {}
            ok = True
            for name, raw in zip(header[1:], values[1:]):
                try:
                    parsed[name] = int(raw)
                except ValueError:
                    ok = False
                    break
            if ok:
                out[group] = parsed
            i += 2
        else:
            i += 1
    return out


def parse_cgroup_cpu_stat(text):
    """Parse cgroup v2 cpu.stat: "key value" lines, values are ints
    (microseconds for the *_usec fields)."""
    out = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                try:
                    out[parts[0]] = float(parts[1])
                except ValueError:
                    continue
    return out


def parse_cgroup_path(text, pid_hint=None):
    """Parse /proc/<pid>/cgroup and return the v2 path (the part after
    "0::"), or None if there is no v2 line."""
    for line in text.strip().splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            return parts[2]
    return None


def parse_schedstat(text):
    """Parse /proc/<pid>/schedstat: three numbers, run time on a CPU
    (ns), runqueue wait time (ns), and number of timeslices run."""
    parts = text.strip().split()
    if len(parts) < 3:
        return {}
    return {
        "runtime_ns": int(parts[0]),
        "wait_ns": int(parts[1]),
        "timeslices": int(parts[2]),
    }


def parse_status(text):
    """Parse the context switch lines (and state) of /proc/<pid>/status."""
    out = {}
    for line in text.splitlines():
        if line.startswith("voluntary_ctxt_switches:"):
            out["voluntary_ctxt_switches"] = int(line.split(":", 1)[1])
        elif line.startswith("nonvoluntary_ctxt_switches:"):
            out["nonvoluntary_ctxt_switches"] = int(line.split(":", 1)[1])
        elif line.startswith("State:"):
            out["state"] = line.split(":", 1)[1].strip()
    return out


def parse_pid_stat(text):
    """Parse /proc/<pid>/stat.

    The comm field is in parentheses and may contain spaces, so split
    on the last ")". After comm, token 0 is state (field 3), token 11
    is utime (field 14) and token 12 is stime (field 15).
    Returns {"state": str, "utime": int, "stime": int} in clock ticks.
    """
    rparen = text.rfind(")")
    if rparen == -1:
        return {}
    rest = text[rparen + 1:].split()
    if len(rest) < 13:
        return {}
    return {
        "state": rest[0],
        "utime": int(rest[11]),
        "stime": int(rest[12]),
    }


# ---------------------------------------------------------------- readers

def _read_text(path):
    try:
        with open(path, "r") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def read_pressure(kind):
    text = _read_text(os.path.join(PROC, "pressure", kind))
    return parse_pressure(text) if text is not None else None


def read_proc_stat():
    text = _read_text(os.path.join(PROC, "stat"))
    return parse_proc_stat(text) if text is not None else None


def read_sockstat():
    text = _read_text(os.path.join(PROC, "net", "sockstat"))
    return parse_sockstat(text) if text is not None else None


def read_snmp_tcp():
    text = _read_text(os.path.join(PROC, "net", "snmp"))
    if text is None:
        return None
    parsed = parse_snmp(text)
    return parsed.get("tcp")


def cgroup_cpu_stat_path(pid=None):
    """Resolve the cgroup v2 cpu.stat file for a process.

    Tries, in order: the path from /proc/<pid>/cgroup joined onto
    /sys/fs/cgroup, then the root /sys/fs/cgroup/cpu.stat. Returns the
    first path that exists, or None.
    """
    candidates = []
    cgroup_file = os.path.join(PROC, str(pid) if pid else "self", "cgroup")
    text = _read_text(cgroup_file)
    if text is not None:
        rel = parse_cgroup_path(text)
        if rel:
            candidates.append(os.path.join(SYS_CGROUP, rel.lstrip("/"),
                                           "cpu.stat"))
    candidates.append(os.path.join(SYS_CGROUP, "cpu.stat"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def read_cgroup_cpu(pid=None):
    path = cgroup_cpu_stat_path(pid)
    if path is None:
        return None
    text = _read_text(path)
    return parse_cgroup_cpu_stat(text) if text is not None else None


def read_schedstat(pid=None):
    path = os.path.join(PROC, str(pid) if pid else "self", "schedstat")
    text = _read_text(path)
    return parse_schedstat(text) if text is not None else None


def read_status(pid=None):
    path = os.path.join(PROC, str(pid) if pid else "self", "status")
    text = _read_text(path)
    return parse_status(text) if text is not None else None


def read_pid_stat(pid=None):
    path = os.path.join(PROC, str(pid) if pid else "self", "stat")
    text = _read_text(path)
    return parse_pid_stat(text) if text is not None else None


def sample_pid_states(pid, samples=40, interval_s=0.005):
    """Sample /proc/<pid>/stat state letters over a short window.

    Returns {"R": frac, "S": frac, "T": frac, ...} plus "samples": n.
    A process being duty cycled with SIGSTOP shows up as a large "T"
    (stopped) fraction, which no single point-in-time read can see.
    """
    counts = {}
    seen = 0
    for _ in range(samples):
        stat = read_pid_stat(pid)
        if stat and "state" in stat:
            counts[stat["state"]] = counts.get(stat["state"], 0) + 1
            seen += 1
        time.sleep(interval_s)
    if seen == 0:
        return None
    out = {state: count / seen for state, count in counts.items()}
    out["samples"] = seen
    return out


def collect_all(pid=None, sample_states=True):
    """Take a full snapshot. pid is the server process to watch;
    defaults to this process. Missing interfaces come back as None.
    """
    snapshot = {
        "time": time.time(),
        "pid": pid or os.getpid(),
        "pressure_cpu": read_pressure("cpu"),
        "pressure_io": read_pressure("io"),
        "proc_stat": read_proc_stat(),
        "sockstat": read_sockstat(),
        "snmp_tcp": read_snmp_tcp(),
        "cgroup_cpu": read_cgroup_cpu(pid),
        "schedstat": read_schedstat(pid),
        "status": read_status(pid),
        "pid_stat": read_pid_stat(pid),
    }
    if sample_states:
        snapshot["pid_states"] = sample_pid_states(snapshot["pid"])
    return snapshot
