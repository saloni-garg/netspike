"""Integration test: real server process, real CPU saturation from
busy processes, real kernel counters. Asserts the tail latency
actually rises and that the diagnoser calls it a cpu class from the
counters alone.

The server runs as its own process on purpose: schedstat and process
state are per process kernel data, and watching a combined
client-plus-server process muddies exactly the counters the
diagnoser relies on. That is also how the experiment runs it.
"""

import multiprocessing

from netspike import client, collectors, diagnose, inject
from netspike.experiment import _free_port, _serve, _wait_connectable


def test_cpu_saturation_spike_is_diagnosed():
    port = _free_port()
    ctx = multiprocessing.get_context("fork")
    server_proc = ctx.Process(target=_serve, args=(port,), daemon=True)
    server_proc.start()
    try:
        assert _wait_connectable(port)
        baseline = client.measure(port, 20, timeout_s=2.0)
        before = collectors.collect_all(pid=server_proc.pid,
                                        sample_states=False)
        injector = inject.CpuSaturationInjector()
        injector.start()
        try:
            saturated = client.measure(port, 40, timeout_s=2.0)
            after = collectors.collect_all(pid=server_proc.pid,
                                           sample_states=True)
        finally:
            injector.stop()
    finally:
        server_proc.terminate()
        server_proc.join(timeout=3.0)

    assert saturated["p99"] > baseline["p99"] + 5, (
        "expected a clear tail rise under saturation: baseline p99 "
        "%.2f ms, saturated p99 %.2f ms" % (baseline["p99"],
                                            saturated["p99"]))
    features = diagnose.diff_snapshots(before, after)
    result = diagnose.diagnose(features, baseline, saturated)
    assert result["label"] in ("cpu_saturation", "cpu_throttle"), (
        "expected a cpu class, got %s with features %s"
        % (result["label"], features))
