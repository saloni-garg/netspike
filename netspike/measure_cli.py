"""Measurement CLI: run the load client against a host and port and
print the latency summary as one JSON object on stdout.

This exists for the Docker experiment: the client runs inside its
own container, on the same bridge network as the server container,
and the only thing that needs to cross back is the summary. It is
also handy on a host:

    python -m netspike.measure_cli --host 127.0.0.1 --port 8765 \
        --count 50 [--min-window 2.5]

Output: {"summary": {...client.summarize dict...}, "window_s": secs}
"""

import argparse
import json
import sys
import time

from . import client


def measure(host, port, count, timeout_s=2.0, retries=0,
            min_window_s=0.0):
    """Like client.measure(), but keeps repeating rounds of count
    requests until at least min_window_s has elapsed (the diagnoser
    counters need a window of a few seconds to accumulate on a fast
    machine). Returns (summary, elapsed_s)."""
    latencies = []
    attempts_total = 0
    started = time.perf_counter()
    while True:
        for _ in range(count):
            latency_ms, attempts = client.one_request(
                port, host=host, timeout_s=timeout_s, retries=retries)
            latencies.append(latency_ms)
            attempts_total += attempts
        if time.perf_counter() - started >= min_window_s:
            break
    summary = client.summarize(latencies)
    summary["attempts"] = attempts_total
    summary["retries"] = attempts_total - len(latencies)
    return summary, time.perf_counter() - started


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netspike.measure_cli")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--min-window", type=float, default=0.0)
    args = parser.parse_args(argv)
    summary, elapsed = measure(args.host, args.port, args.count,
                               timeout_s=args.timeout,
                               retries=args.retries,
                               min_window_s=args.min_window)
    print(json.dumps({"summary": summary, "window_s": elapsed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
