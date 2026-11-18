"""Load client: one fresh TCP connection per request, per request
latency recorded in milliseconds, percentiles computed from the raw
samples. Retries are counted and their time is included, because a
client that silently retries is exactly how a network fault shows up
as tail latency in production.
"""

import socket
import time


def percentile(sorted_values, pct):
    """Nearest-rank percentile. pct is 0..100."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


def summarize(latencies_ms):
    if not latencies_ms:
        return {"count": 0, "p50": None, "p95": None, "p99": None,
                "mean": None, "max": None}
    ordered = sorted(latencies_ms)
    return {
        "count": len(ordered),
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "p99": percentile(ordered, 99),
        "mean": sum(ordered) / len(ordered),
        "max": ordered[-1],
    }


def one_request(port, host="127.0.0.1", timeout_s=2.0, retries=0,
                payload=b"ping\n"):
    """Run one request, with optional retries on timeout or reset.

    Returns (latency_ms, attempts). If every attempt fails, the
    elapsed time is still returned as the latency, so a dead or
    resetting peer shows up as tail latency in the summary rather
    than as a crash of the experiment itself.
    """
    start = time.perf_counter()
    attempts = 0
    while True:
        attempts += 1
        try:
            with socket.create_connection((host, port),
                                          timeout=timeout_s) as sock:
                sock.settimeout(timeout_s)
                sock.sendall(payload)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("server closed early")
                    data += chunk
            break
        except (OSError, ConnectionError):
            if attempts > retries:
                break
            continue
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, attempts


def measure(port, count, host="127.0.0.1", timeout_s=2.0, retries=0):
    """Run count requests back to back. Returns (summary, attempts)
    where summary is summarize() over the per request latencies."""
    latencies = []
    total_attempts = 0
    for _ in range(count):
        latency_ms, attempts = one_request(
            port, host=host, timeout_s=timeout_s, retries=retries)
        latencies.append(latency_ms)
        total_attempts += attempts
    summary = summarize(latencies)
    summary["attempts"] = total_attempts
    summary["retries"] = total_attempts - count
    return summary
