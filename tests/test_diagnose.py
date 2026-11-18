"""Diagnoser rule tests with synthetic snapshots: one feature set per
class, built to look like what diff_snapshots() produces from real
counters, plus a diff_snapshots test on fake collect_all() output."""

from netspike import diagnose

BASE = {"p50": 0.5, "p95": 0.8, "p99": 1.0, "mean": 0.6, "max": 2.0,
        "count": 50}


def lat(p50, p99):
    return {"p50": p50, "p95": p99 * 0.8, "p99": p99, "mean": p50 * 1.5,
            "max": p99 * 1.2, "count": 50}


def test_throttle_from_stopped_fraction():
    features = {"pid_stopped_fraction": 0.72,
                "cpu_pressure_some_us": 40000}
    result = diagnose.diagnose(features, BASE, lat(0.6, 90.0))
    assert result["label"] == "cpu_throttle"
    assert result["reasons"]


def test_throttle_from_cgroup_counters():
    features = {"cgroup_throttled_us": 60000, "cgroup_nr_throttled": 12}
    result = diagnose.diagnose(features, BASE, lat(0.7, 80.0))
    assert result["label"] == "cpu_throttle"


def test_saturation_from_wait_ratio():
    features = {"schedstat_wait_ms": 300.0, "schedstat_runtime_ms": 100.0,
                "cpu_pressure_some_us": 120000, "cpu_util_ratio": 0.6}
    result = diagnose.diagnose(features, BASE, lat(3.0, 40.0))
    assert result["label"] == "cpu_saturation"


def test_saturation_from_util_and_absolute_wait():
    features = {"cpu_util_ratio": 0.92, "schedstat_wait_ms": 250.0,
                "schedstat_runtime_ms": 500.0,
                "cpu_pressure_some_us": 10000}
    result = diagnose.diagnose(features, BASE, lat(2.0, 30.0))
    assert result["label"] == "cpu_saturation"


def test_retransmit_from_kernel_counter():
    features = {"tcp_retrans_delta": 5, "tcp_outsegs_delta": 900}
    result = diagnose.diagnose(features, BASE, lat(2.0, 120.0))
    assert result["label"] == "network_retransmit"


def test_retransmit_from_churn_pattern():
    features = {"tcp_retrans_delta": 0, "proxy_dropped_delta": 11,
                "tcp_tw_delta": 20, "tcp_outsegs_delta": 800}
    result = diagnose.diagnose(features, BASE, lat(2.2, 500.0))
    assert result["label"] == "network_retransmit"


def test_network_delay_uniform_shift():
    result = diagnose.diagnose({}, BASE, lat(47.0, 56.0))
    assert result["label"] == "network_delay"


def test_io_pressure_tail_heavy():
    features = {"io_pressure_some_us": 80000, "cpu_util_ratio": 0.3,
                "schedstat_wait_ms": 1.0, "schedstat_runtime_ms": 50.0}
    result = diagnose.diagnose(features, BASE, lat(1.0, 60.0))
    assert result["label"] == "io_pressure"


def test_io_pressure_does_not_steal_uniform_shift():
    # System wide io counters are noisy on shared machines; a clean
    # uniform shift must still read as delay, not io.
    features = {"io_pressure_some_us": 600000, "cpu_util_ratio": 0.4}
    result = diagnose.diagnose(features, BASE, lat(47.0, 56.0))
    assert result["label"] == "network_delay"


def test_unknown_when_nothing_fires():
    result = diagnose.diagnose({}, BASE, BASE)
    assert result["label"] == "unknown"


# ------------------------------------------------ baseline-relative
# saturation (rule 3b). The feature values below are the recorded
# dedicated-machine echo-server saturation case (medians from
# results-verda.json): the old absolute gates (p99 rise > 5 ms,
# wait ratio >= 1.5) read it as unknown, 0 of 5 trials.

VERDA_BASE_FEATURES = {"window_s": 0.0047, "cpu_pressure_some_us": 646,
                       "schedstat_wait_ms": 0.0,
                       "schedstat_runtime_ms": 1.44}
VERDA_BASE_LAT = {"p50": 0.07, "p95": 0.14, "p99": 0.25,
                  "mean": 0.08, "max": 0.31, "count": 50}
VERDA_SAT_FEATURES = {"window_s": 2.51, "cpu_util_ratio": 1.0,
                      "cpu_pressure_some_us": 1233479,
                      "schedstat_wait_ms": 115.6,
                      "schedstat_runtime_ms": 137.8,
                      "tcp_retrans_delta": 0, "cgroup_throttled_us": 0,
                      "cgroup_nr_throttled": 0, "pid_stopped_fraction": 0.0}
VERDA_SAT_LAT = {"p50": 0.06, "p95": 2.03, "p99": 3.08,
                 "mean": 0.37, "max": 7.0, "count": 6600}


def test_relative_saturation_recorded_echo_case():
    result = diagnose.diagnose(VERDA_SAT_FEATURES, VERDA_BASE_LAT,
                               VERDA_SAT_LAT,
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "cpu_saturation"
    assert any("baseline-relative" in r for r in result["reasons"])


def test_relative_saturation_needs_baseline_features():
    # Same window, no baseline reference: the absolute branches do
    # not fire on these numbers (p99 rise 2.83 ms, wait ratio 0.84),
    # which is exactly the recorded blind spot.
    result = diagnose.diagnose(VERDA_SAT_FEATURES, VERDA_BASE_LAT,
                               VERDA_SAT_LAT)
    assert result["label"] == "unknown"


def test_relative_saturation_baseline_vs_baseline_stays_unknown():
    result = diagnose.diagnose(VERDA_BASE_FEATURES, VERDA_BASE_LAT,
                               VERDA_BASE_LAT,
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "unknown"


def test_relative_branch_does_not_steal_throttle():
    features = dict(VERDA_SAT_FEATURES)
    features["cgroup_throttled_us"] = 402438
    features["cgroup_nr_throttled"] = 6
    result = diagnose.diagnose(features, VERDA_BASE_LAT,
                               lat(3.35, 84.34),
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "cpu_throttle"


def test_relative_branch_does_not_steal_retransmit():
    features = dict(VERDA_SAT_FEATURES)
    features["tcp_retrans_delta"] = 73
    features["tcp_outsegs_delta"] = 437
    result = diagnose.diagnose(features, VERDA_BASE_LAT,
                               lat(0.32, 2828.41),
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "network_retransmit"


def test_relative_branch_does_not_steal_delay():
    # A delay phase on a host with cpu pressure noise: pressure is
    # present but the watched server waits on the network, not on a
    # runqueue (wait ratio near zero), and the shift is uniform.
    features = {"window_s": 10.0, "cpu_pressure_some_us": 76079,
                "schedstat_wait_ms": 0.9, "schedstat_runtime_ms": 12.7,
                "tcp_retrans_delta": 0}
    result = diagnose.diagnose(features, VERDA_BASE_LAT,
                               lat(201.08, 221.05),
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "network_delay"


def test_relative_branch_does_not_steal_io():
    features = {"window_s": 2.0, "io_pressure_some_us": 80000,
                "cpu_pressure_some_us": 2000, "cpu_util_ratio": 0.3,
                "schedstat_wait_ms": 1.0, "schedstat_runtime_ms": 50.0}
    result = diagnose.diagnose(features, BASE, lat(1.0, 60.0),
                               baseline_features={
                                   "window_s": 2.0,
                                   "cpu_pressure_some_us": 1000,
                                   "schedstat_wait_ms": 0.5,
                                   "schedstat_runtime_ms": 50.0})
    assert result["label"] == "io_pressure"


def test_relative_branch_rejects_pressure_without_queueing():
    # Pressure alone (a busy neighbour) with a server that is not
    # queueing for CPU must not read as this server's saturation.
    features = dict(VERDA_SAT_FEATURES)
    features["schedstat_wait_ms"] = 2.0
    features["schedstat_runtime_ms"] = 130.0
    result = diagnose.diagnose(features, VERDA_BASE_LAT, VERDA_SAT_LAT,
                               baseline_features=VERDA_BASE_FEATURES)
    assert result["label"] == "unknown"


def _snap(cpu_total, idle, retrans, throttled, wait_ns, stopped):
    return {
        "time": 1000.0,
        "proc_stat": {
            "cpu": {"total": cpu_total, "idle_all": idle},
            "softirq": {"net_rx": 10},
            "ctxt": 100,
        },
        "pressure_cpu": {"some": {"total": 1000}},
        "pressure_io": {"some": {"total": 2000}},
        "snmp_tcp": {"RetransSegs": retrans, "OutSegs": 1000},
        "sockstat": {"tcp_tw": 3},
        "cgroup_cpu": {"throttled_usec": throttled, "nr_throttled": 1},
        "schedstat": {"wait_ns": wait_ns, "runtime_ns": 5000000},
        "pid_states": {"S": 1.0 - stopped, "T": stopped, "samples": 40},
    }


def test_diff_snapshots():
    before = _snap(1000, 800, 10, 0, 1000000, 0.0)
    after = _snap(2000, 900, 15, 30000, 9000000, 0.5)
    after["time"] = 1003.0
    features = diagnose.diff_snapshots(before, after)
    assert features["window_s"] == 3.0
    assert features["cpu_util_ratio"] == 0.9
    assert features["tcp_retrans_delta"] == 5
    assert features["cgroup_throttled_us"] == 30000
    assert features["schedstat_wait_ms"] == 8.0
    assert features["pid_stopped_fraction"] == 0.5
