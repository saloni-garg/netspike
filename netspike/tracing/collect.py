"""Run the bpftrace scripts in this directory for a few seconds and
parse their output into numbers.

bpftrace prints its maps when the script exits, so collection is:
start the script, let it run for the requested seconds, stop it
(SIGINT, the same as Ctrl-C), and parse the final dump. If
bpftrace is not installed, or the run fails (no permission, no
BTF, tracepoints missing), the collect_* functions return None
instead of raising -- the same degrade-gracefully rule the /proc
collectors follow. The parse_* functions are pure text functions
and are unit tested with fixture output.

Usage:
    from netspike.tracing import collect
    collect.collect_retransmits(5)   # {"total": int, "per_process": {...}} or None
    collect.collect_runqueue(5)      # {"buckets": [...], "total_samples": int,
                                     #  "offcpu_events": {...}} or None
"""

import os
import re
import shutil
import subprocess

SCRIPTS = {
    "retransmits": "tcp_retransmits.bt",
    "runqueue": "runqueue_latency.bt",
}

_DIR = os.path.dirname(os.path.abspath(__file__))


def script_path(name):
    """Absolute path of a bundled .bt script, by short name
    ("retransmits" / "runqueue") or by file name."""
    filename = SCRIPTS.get(name, name)
    return os.path.join(_DIR, filename)


def find_bpftrace(which=None):
    which = which or shutil.which
    return which("bpftrace")


_TOTAL_PRINTF = re.compile(r"total retransmits:\s*(\d+)")
_TOTAL_MAP = re.compile(r"@total:\s*(\d+)")
_PER_PROCESS = re.compile(r"@retransmits\[([^\]]+)\]:\s*(\d+)")
_OFFCPU = re.compile(r"@offcpu_events\[([^\]]+)\]:\s*(\d+)")
_HIST_HEADER = re.compile(r"@runq_lat_us:\s*$")
_HIST_LINE = re.compile(r"\[(\d+),\s*(\d+)\)\s+(\d+)")


def parse_retransmit_output(text):
    """Parse tcp_retransmits.bt output.

    Returns {"total": int or None, "per_process": {comm: count}}.
    The total comes from the END printf when present, else from the
    @total map dump, else from summing the per-process map.
    """
    per_process = {}
    for match in _PER_PROCESS.finditer(text or ""):
        per_process[match.group(1)] = int(match.group(2))
    total = None
    match = _TOTAL_PRINTF.search(text or "")
    if match:
        total = int(match.group(1))
    else:
        match = _TOTAL_MAP.search(text or "")
        if match:
            total = int(match.group(1))
        elif per_process:
            total = sum(per_process.values())
    return {"total": total, "per_process": per_process}


def parse_runqueue_output(text):
    """Parse runqueue_latency.bt output.

    bpftrace prints a hist() map as a header line "@runq_lat_us:"
    followed by bucket lines like "[0, 1)   123 |@@@@|". Returns
    {"buckets": [(low_us, high_us, count), ...] in printed order,
     "total_samples": sum of bucket counts,
     "offcpu_events": {comm: count}}.
    """
    buckets = []
    in_hist = False
    offcpu = {}
    for line in (text or "").splitlines():
        if _HIST_HEADER.match(line.strip()):
            in_hist = True
            continue
        if line.startswith("@"):
            in_hist = False
        match = _OFFCPU.search(line)
        if match:
            offcpu[match.group(1)] = int(match.group(2))
            continue
        if in_hist:
            match = _HIST_LINE.search(line)
            if match:
                buckets.append((int(match.group(1)),
                                int(match.group(2)),
                                int(match.group(3))))
    return {"buckets": buckets,
            "total_samples": sum(count for _lo, _hi, count in buckets),
            "offcpu_events": offcpu}


def run_script(name, seconds, bpftrace=None, timeout_slack=10):
    """Run a bundled script for `seconds` and return its combined
    output text, or None when bpftrace is missing or the run
    fails. Stopping is SIGINT (Ctrl-C), which is what makes
    bpftrace print its maps; a script that ignores it is killed
    after a short grace period and its partial output is used."""
    bpftrace = bpftrace or find_bpftrace()
    if bpftrace is None:
        return None
    try:
        proc = subprocess.Popen(
            [bpftrace, script_path(name)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
    except OSError:
        return None
    try:
        out, _ = proc.communicate(timeout=seconds)
        # The script ran to completion on its own inside the
        # window (unusual for these until-Ctrl-C scripts, but the
        # output is the output).
        return out
    except subprocess.TimeoutExpired:
        proc.send_signal(2)  # SIGINT: bpftrace prints maps on exit
        try:
            out, _ = proc.communicate(timeout=timeout_slack)
            return out
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            return out


def collect_retransmits(seconds=5):
    out = run_script("retransmits", seconds)
    if out is None:
        return None
    return parse_retransmit_output(out)


def collect_runqueue(seconds=5):
    out = run_script("runqueue", seconds)
    if out is None:
        return None
    return parse_runqueue_output(out)
