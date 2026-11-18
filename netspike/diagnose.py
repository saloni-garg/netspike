"""Diagnoser: classify a latency spike from kernel counters.

The input is a feature dict built by diff_snapshots() from two
collectors.collect_all() snapshots (before and during/after), plus
the baseline and current latency summaries. The fault that was
injected is never an input. Rules are applied in a fixed order and
every rule that fires is recorded in the result's reasons list, so a
classification can be traced back to the counters that caused it.

diagnose() also accepts an optional baseline_features: the feature
dict of the same workload measured with no fault (same keys as a
diff_snapshots() result). One rule -- the baseline-relative
saturation branch of rule 3 -- needs it, because it judges the
current window against the workload's own baseline instead of
against absolute thresholds. Without baseline_features that branch
simply does not fire and the older absolute branches stand alone.
Why a relative branch exists at all is documented at rule 3.

Feature dict keys (all optional; missing means the interface was
unavailable and rules that need it simply do not fire):
  cpu_util_ratio          fraction of the window the CPUs were busy
  cpu_pressure_some_us    /proc/pressure/cpu "some" total delta, us
  io_pressure_some_us     /proc/pressure/io "some" total delta, us
  softirq_net_rx_delta    NET_RX softirq count delta
  schedstat_wait_ms       server runqueue wait delta, ms
  schedstat_runtime_ms    server on-CPU runtime delta, ms
  cgroup_throttled_us     cgroup cpu.stat throttled_usec delta
  cgroup_nr_throttled     cgroup cpu.stat nr_throttled delta
  pid_stopped_fraction    fraction of state samples where the server
                          was in T (stopped) state, 0..1
  tcp_retrans_delta       Tcp RetransSegs delta
  tcp_outsegs_delta       Tcp OutSegs delta
  tcp_tw_delta            sockstat TCP time-wait count delta
  proxy_dropped_delta     requests the proxy reset without answering
  proxy_delay_ms_total    artificial delay the proxy applied, ms
  ctxt_delta              total context switch delta

Labels: cpu_throttle, cpu_saturation, network_retransmit,
network_delay, io_pressure, unknown.
"""


def _delta(section_before, section_after, key):
    if not section_before or not section_after:
        return None
    if key not in section_before or key not in section_after:
        return None
    return section_after[key] - section_before[key]


def _pressure_delta(before, after, which):
    b = (before or {}).get(which) or {}
    a = (after or {}).get(which) or {}
    b_some = (b.get("some") or {}).get("total")
    a_some = (a.get("some") or {}).get("total")
    if b_some is None or a_some is None:
        return None
    return a_some - b_some


def diff_snapshots(before, after, proxy_before=None, proxy_after=None):
    """Build the feature dict from two collect_all() snapshots.
    Proxy stats, when given, are the TcpProxy counters at the same
    two moments."""
    features = {}
    if before and after and before.get("time") and after.get("time"):
        features["window_s"] = after["time"] - before["time"]

    b_stat = (before or {}).get("proc_stat") or {}
    a_stat = (after or {}).get("proc_stat") or {}
    b_cpu = b_stat.get("cpu") or {}
    a_cpu = a_stat.get("cpu") or {}
    if b_cpu.get("total") is not None and a_cpu.get("total"):
        total_delta = a_cpu["total"] - b_cpu["total"]
        idle_delta = a_cpu["idle_all"] - b_cpu["idle_all"]
        if total_delta > 0:
            features["cpu_util_ratio"] = 1.0 - (idle_delta / total_delta)
    softirq_delta = _delta(b_stat.get("softirq"), a_stat.get("softirq"),
                           "net_rx")
    if softirq_delta is not None:
        features["softirq_net_rx_delta"] = softirq_delta
    ctxt = _delta(b_stat, a_stat, "ctxt")
    if ctxt is not None:
        features["ctxt_delta"] = ctxt

    cpu_p = _pressure_delta(before, after, "pressure_cpu")
    if cpu_p is not None:
        features["cpu_pressure_some_us"] = cpu_p
    io_p = _pressure_delta(before, after, "pressure_io")
    if io_p is not None:
        features["io_pressure_some_us"] = io_p

    wait = _delta((before or {}).get("schedstat"),
                  (after or {}).get("schedstat"), "wait_ns")
    if wait is not None:
        features["schedstat_wait_ms"] = wait / 1e6
    runtime = _delta((before or {}).get("schedstat"),
                     (after or {}).get("schedstat"), "runtime_ns")
    if runtime is not None:
        features["schedstat_runtime_ms"] = runtime / 1e6

    thr = _delta((before or {}).get("cgroup_cpu"),
                 (after or {}).get("cgroup_cpu"), "throttled_usec")
    if thr is not None:
        features["cgroup_throttled_us"] = thr
    nr = _delta((before or {}).get("cgroup_cpu"),
                (after or {}).get("cgroup_cpu"), "nr_throttled")
    if nr is not None:
        features["cgroup_nr_throttled"] = nr

    states = (after or {}).get("pid_states")
    if states:
        features["pid_stopped_fraction"] = states.get("T", 0.0)

    retrans = _delta((before or {}).get("snmp_tcp"),
                     (after or {}).get("snmp_tcp"), "RetransSegs")
    if retrans is not None:
        features["tcp_retrans_delta"] = retrans
    outsegs = _delta((before or {}).get("snmp_tcp"),
                     (after or {}).get("snmp_tcp"), "OutSegs")
    if outsegs is not None:
        features["tcp_outsegs_delta"] = outsegs
    tw = _delta((before or {}).get("sockstat"),
                (after or {}).get("sockstat"), "tcp_tw")
    if tw is not None:
        features["tcp_tw_delta"] = tw

    if proxy_before is not None and proxy_after is not None:
        features["proxy_dropped_delta"] = (proxy_after["dropped"]
                                           - proxy_before["dropped"])
        features["proxy_delay_ms_total"] = (proxy_after["delay_ms_total"]
                                            - proxy_before["delay_ms_total"])
    return features


# Thresholds. These are deliberately plain constants, tuned for
# short (a few seconds) measurement windows on a small machine, and
# stated here so a reader can disagree with them concretely.
TH = {
    "stopped_fraction": 0.15,      # server stopped 15%+ of samples
    "throttled_us": 20000,         # 20 ms of real cgroup throttling
    "cpu_util": 0.75,              # CPUs busy 75%+ of the window
    "sched_wait_ms": 200.0,        # server waited 200 ms+ on runqueue
    "wait_ratio": 1.5,             # runqueue wait vs on-CPU runtime
    "cpu_pressure_us": 50000,      # 50 ms of cpu pressure (some)
    "retrans_min": 2,              # at least 2 retransmitted segments
    "proxy_dropped": 3,            # at least 3 reset requests
    "io_pressure_us": 50000,       # 50 ms stalled on io (some)
    "delay_shift_ms": 8.0,         # median latency rose by 8 ms+
    # Baseline-relative saturation branch (rule 3b). See the long
    # comment there for why these are relative, not absolute.
    "sat_rel_pressure_floor_us": 100000,  # 100 ms of cpu stall, min
    "sat_rel_pressure_rate_ratio": 3.0,   # stall rate vs baseline
    "sat_rel_stall_fraction": 0.20,  # stall as a share of the window
    "sat_rel_wait_ms": 20.0,         # server runqueue wait, min
    "sat_rel_wait_ratio": 0.5,       # wait vs on-CPU runtime, min
    "sat_rel_wait_ratio_growth": 0.4,  # wait ratio growth vs baseline
    "sat_rel_tail_ratio": 3.0,       # p95 and p99 growth vs baseline
}


def _wait_ratio(features):
    """Runqueue wait over on-CPU runtime for a feature dict, or None
    when either schedstat number is missing (missing is not zero:
    a rule that needs the ratio must not fire on absent data)."""
    wait = features.get("schedstat_wait_ms")
    runtime = features.get("schedstat_runtime_ms")
    if wait is None or runtime is None or runtime <= 0:
        return None
    return wait / runtime


def _pressure_rate(features):
    """Cpu pressure stall rate in us per second of window, or None
    when the pressure delta or the window length is missing."""
    pressure = features.get("cpu_pressure_some_us")
    window = features.get("window_s")
    if pressure is None or not window:
        return None
    return pressure / window


def diagnose(features, baseline, current, baseline_features=None):
    """Classify. baseline and current are client.summarize() dicts.
    baseline_features, when given, is the feature dict of the same
    workload with no fault; only the baseline-relative saturation
    branch (rule 3b) uses it.
    Returns {"label": str, "reasons": [str, ...]}."""
    reasons = []
    f = features or {}
    base_p50 = (baseline or {}).get("p50") or 0.0
    cur_p50 = (current or {}).get("p50") or 0.0
    base_p95 = (baseline or {}).get("p95") or 0.0
    cur_p95 = (current or {}).get("p95") or 0.0
    base_p99 = (baseline or {}).get("p99") or 0.0
    cur_p99 = (current or {}).get("p99") or 0.0
    p50_delta = cur_p50 - base_p50
    p99_delta = cur_p99 - base_p99

    # Rule 1: throttling. Either the kernel says the cgroup was
    # throttled, or the server process spent a large fraction of the
    # window in the stopped state while work was arriving. Both are
    # "runnable but not allowed to run", which saturation is not.
    if (f.get("cgroup_throttled_us") or 0) >= TH["throttled_us"]:
        reasons.append(
            "cgroup throttled_usec rose by %d us"
            % f["cgroup_throttled_us"])
        return {"label": "cpu_throttle", "reasons": reasons}
    if (f.get("pid_stopped_fraction") or 0) >= TH["stopped_fraction"]:
        reasons.append(
            "server in stopped (T) state for %.0f%% of state samples"
            % (100 * f["pid_stopped_fraction"]))
        return {"label": "cpu_throttle", "reasons": reasons}

    # Rule 2: retransmit / loss. Checked before saturation because
    # it is the more specific signal, and a lossy phase can also
    # leave the server waiting around. Either the kernel
    # retransmitted segments, or the connection churn pattern
    # matches loss: many requests reset without an answer plus a
    # sharp tail rise. On loopback a userspace drop often produces
    # no kernel retransmit at all (the kernel already delivered the
    # bytes to the proxy), so the churn branch is what fires there.
    retrans = f.get("tcp_retrans_delta") or 0
    dropped = f.get("proxy_dropped_delta") or 0
    if retrans >= TH["retrans_min"] and p99_delta > 5:
        reasons.append("Tcp RetransSegs rose by %d" % retrans)
        return {"label": "network_retransmit", "reasons": reasons}
    if dropped >= TH["proxy_dropped"] and p99_delta > 20:
        reasons.append("%d requests reset without an answer and "
                       "p99 rose by %.0f ms" % (dropped, p99_delta))
        if retrans:
            reasons.append("Tcp RetransSegs also rose by %d" % retrans)
        return {"label": "network_retransmit", "reasons": reasons}

    # Rule 3: saturation. The signature is queueing for CPU: the
    # server spent more time waiting on a runqueue than running,
    # while cpu pressure (time tasks spent runnable but not running,
    # system wide) climbed, and the tail rose far more than the
    # median. A light server has tiny absolute wait numbers, so the
    # wait-to-runtime ratio is the load bearing measure, not an
    # absolute wait threshold. The /proc/stat utilization branch is
    # kept for busier servers where it is meaningful.
    cpu_hot = (f.get("cpu_util_ratio") or 0) >= TH["cpu_util"]
    waited = (f.get("schedstat_wait_ms") or 0) >= TH["sched_wait_ms"]
    runtime_ms = f.get("schedstat_runtime_ms") or 0
    wait_ms = f.get("schedstat_wait_ms") or 0
    wait_ratio = (wait_ms / runtime_ms) if runtime_ms > 0 else 0.0
    pressure_us = f.get("cpu_pressure_some_us") or 0
    if cpu_hot and waited and p99_delta > 5:
        reasons.append("cpu utilization %.0f%% of window"
                       % (100 * f["cpu_util_ratio"]))
        reasons.append("server runqueue wait rose by %.0f ms"
                       % f["schedstat_wait_ms"])
        return {"label": "cpu_saturation", "reasons": reasons}
    if wait_ratio >= TH["wait_ratio"] \
            and pressure_us >= TH["cpu_pressure_us"] and p99_delta > 5:
        reasons.append("server runqueue wait %.0f ms vs %.0f ms "
                       "on-CPU (ratio %.1f)"
                       % (wait_ms, runtime_ms, wait_ratio))
        reasons.append("cpu pressure 'some' total rose by %d us"
                       % pressure_us)
        return {"label": "cpu_saturation", "reasons": reasons}

    # Rule 3b: saturation, baseline-relative. The two branches above
    # gate on absolutes: a p99 rise above 5 ms and a wait ratio of
    # at least 1.5. Those gates assume the watched service is hurt
    # in absolute terms when the CPUs saturate. A cheap service
    # breaks that assumption. Recorded case (dedicated machine, see
    # results-verda.json): busy processes on every core against the
    # echo server accumulated 1,233,479 us of cpu pressure stall in
    # a 2.5 s window and the server waited 116 ms on runqueues, but
    # at 0.07 ms of work per request its p99 only reached 3.08 ms
    # (rise 2.8 ms, under the 5 ms gate) and its wait ratio was
    # 0.90 (under the 1.5 gate), so every trial read as unknown.
    # The machine was saturated and the counters said so; only the
    # service's absolute numbers were small.
    #
    # The fix is to judge the window against the same workload's
    # own baseline, which the caller passes as baseline_features.
    # All three legs must hold, and each is relative except for a
    # floor that keeps noise from qualifying:
    #   (a) Pressure: the cpu stall rate (pressure delta over the
    #       window) is at least 3x the baseline stall rate, the
    #       stall is at least 20% of the current window, and the
    #       absolute stall is at least 100 ms. Rates, not raw
    #       deltas, because baseline and fault windows rarely have
    #       the same length. When either window length is missing
    #       the fallback is a raw delta at least 10x the baseline
    #       delta, on top of the same absolute floor.
    #   (b) Queueing: the server's wait-to-runtime ratio is at
    #       least 0.5 (it spent at least half as long waiting for a
    #       CPU as running on one) and grew by at least 0.4 over
    #       its baseline ratio, with at least 20 ms of absolute
    #       wait. This leg is what keeps the branch specific: a
    #       network delay or loss phase on a noisy host can show
    #       cpu pressure from a neighbour, but the watched server
    #       is blocked on the network, not on a runqueue, so its
    #       ratio stays near zero.
    #   (c) Latency: p99 and p95 each at least 3x their baselines,
    #       even when the absolute rise is under 5 ms, and the
    #       damage is tail heavy (the p99 growth ratio is at least
    #       1.5x the p50 growth ratio), so a uniform shift -- which
    #       is delay's signature, and delay is checked after this
    #       rule -- is not stolen.
    # Throttle and retransmit are checked before this rule and keep
    # their phases: a throttled server's cgroup counters and a lossy
    # phase's retransmit counters fire first. Baseline against
    # itself cannot fire: every ratio is 1 and every growth is 0.
    bf = baseline_features or {}
    if bf:
        rel_ratio = _wait_ratio(f)
        base_ratio = _wait_ratio(bf)
        rel_pressure = f.get("cpu_pressure_some_us")
        base_pressure = bf.get("cpu_pressure_some_us")
        if rel_ratio is not None and base_ratio is not None \
                and rel_pressure is not None \
                and base_pressure is not None:
            window_s = f.get("window_s") or 0
            rel_rate = _pressure_rate(f)
            base_rate = _pressure_rate(bf)
            if rel_rate is not None and base_rate is not None \
                    and window_s > 0:
                pressure_ok = (
                    rel_pressure >= TH["sat_rel_pressure_floor_us"]
                    and rel_rate >= TH["sat_rel_pressure_rate_ratio"]
                    * max(base_rate, 1000.0)
                    and rel_pressure / (window_s * 1e6)
                    >= TH["sat_rel_stall_fraction"])
            else:
                pressure_ok = (
                    rel_pressure >= TH["sat_rel_pressure_floor_us"]
                    and rel_pressure >= 10 * max(base_pressure, 1))
            wait_ok = (
                wait_ms >= TH["sat_rel_wait_ms"]
                and rel_ratio >= TH["sat_rel_wait_ratio"]
                and rel_ratio >= base_ratio
                + TH["sat_rel_wait_ratio_growth"])
            tail_ok = base_p99 > 0 \
                and cur_p99 >= TH["sat_rel_tail_ratio"] * base_p99
            if tail_ok and base_p95 > 0 and cur_p95:
                tail_ok = cur_p95 >= TH["sat_rel_tail_ratio"] * base_p95
            p50_ratio = (cur_p50 / base_p50) if base_p50 > 0 else 1.0
            p99_ratio = (cur_p99 / base_p99) if base_p99 > 0 else 0.0
            tail_heavy = p99_ratio >= 1.5 * max(p50_ratio, 1.0)
            if pressure_ok and wait_ok and tail_ok and tail_heavy:
                reasons.append(
                    "baseline-relative saturation: cpu pressure stall "
                    "%d us in window (baseline %d us), stall rate "
                    "several times baseline" % (rel_pressure,
                                                base_pressure))
                reasons.append(
                    "server runqueue wait %.0f ms vs %.0f ms on-CPU "
                    "(ratio %.2f, baseline ratio %.2f)"
                    % (wait_ms, runtime_ms, rel_ratio, base_ratio))
                reasons.append(
                    "p99 %.2f ms is %.1fx baseline %.2f ms and p95 "
                    "%.1fx baseline, tail heavy, though the absolute "
                    "p99 rise is only %.2f ms"
                    % (cur_p99, p99_ratio, base_p99,
                       (cur_p95 / base_p95) if base_p95 else 0.0,
                       p99_delta))
                return {"label": "cpu_saturation", "reasons": reasons}

    # Rule 4: plain delay. The whole distribution moved: the median
    # rose almost as much as the tail, and no cpu, throttle, or loss
    # counter explains it. A uniform shift is what a fixed extra hop
    # of latency looks like. Checked before io pressure because an
    # io stall is tail heavy; it does not lift the median evenly.
    if p50_delta >= TH["delay_shift_ms"] and p99_delta > 0 \
            and p50_delta >= 0.4 * p99_delta:
        reasons.append("p50 rose by %.1f ms and p99 by %.1f ms "
                       "(uniform shift, no cpu/loss signal)"
                       % (p50_delta, p99_delta))
        return {"label": "network_delay", "reasons": reasons}
    if (f.get("proxy_delay_ms_total") or 0) > 0 and p50_delta >= 3:
        reasons.append("proxy applied %.0f ms of delay in total and "
                       "p50 rose by %.1f ms"
                       % (f["proxy_delay_ms_total"], p50_delta))
        return {"label": "network_delay", "reasons": reasons}

    # Rule 5: io pressure. Tasks stalled on io for a large slice of
    # the window, the CPUs were not the bottleneck, and the latency
    # damage is in the tail rather than a uniform shift. Pressure
    # counters are system wide, so on a shared machine this rule is
    # deliberately the hardest of the positive rules to fire.
    if (f.get("io_pressure_some_us") or 0) >= TH["io_pressure_us"] \
            and not cpu_hot and p99_delta > 3 * max(p50_delta, 0.0) + 10:
        reasons.append("io pressure 'some' total rose by %d us with "
                       "a tail heavy latency rise"
                       % f["io_pressure_some_us"])
        return {"label": "io_pressure", "reasons": reasons}

    reasons.append("no rule fired: cpu, throttle, loss, io, and "
                   "uniform-shift signals all below threshold")
    return {"label": "unknown", "reasons": reasons}
