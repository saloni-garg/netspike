"""Docker experiment tests: command construction and output
parsing only. No Docker daemon is needed (or used) here; the live
multi-container run is a separate, on-machine step. One test runs
the degradation path end to end with docker hidden, and one runs
measure_cli against a real local server."""

import json

from netspike import docker_experiment as dx
from netspike import measure_cli
from netspike.server import EchoServer


def test_build_image_cmd():
    cmd = dx.build_image_cmd("/some/context")
    assert cmd[:4] == ["docker", "build", "-t", "netspike:latest"]
    assert cmd[4] == "/some/context"


def test_network_cmds():
    assert dx.network_create_cmd() == ["docker", "network", "create",
                                       "netspike-net"]
    assert dx.network_rm_cmd() == ["docker", "network", "rm",
                                   "netspike-net"]


def test_server_run_cmd_with_cpu_limit_and_work():
    cmd = dx.server_run_cmd(name="netspike-server-limited", cpus=0.25,
                            work=True)
    assert cmd[:3] == ["docker", "run", "-d"]
    assert "--name" in cmd and "netspike-server-limited" in cmd
    assert "--network" in cmd and "netspike-net" in cmd
    # The two flags the experiment's honesty depends on: a real CPU
    # limit, and NET_ADMIN so tc works inside the container.
    assert "--cpus" in cmd and "0.25" in cmd
    assert "--cap-add" in cmd and "NET_ADMIN" in cmd
    assert cmd[-3:] == ["netspike.server", "8765", "--work"]


def test_server_run_cmd_plain_has_no_limit():
    cmd = dx.server_run_cmd()
    assert "--cpus" not in cmd
    assert "--work" not in cmd
    assert "netspike-server" in cmd


def test_client_measure_cmd():
    cmd = dx.client_measure_cmd(count=40, host="netspike-server",
                                min_window_s=2.5)
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network" in cmd and "netspike-net" in cmd
    assert "netspike.measure_cli" in cmd
    assert "--host" in cmd and "netspike-server" in cmd
    assert "--min-window" in cmd and "2.5" in cmd


def test_tc_cmds_target_server_eth0():
    add = dx.tc_add_cmd("netspike-server", "loss 15%")
    assert add == ["docker", "exec", "netspike-server", "tc", "qdisc",
                   "add", "dev", "eth0", "root", "netem", "loss", "15%"]
    delete = dx.tc_del_cmd("netspike-server")
    assert delete == ["docker", "exec", "netspike-server", "tc",
                      "qdisc", "del", "dev", "eth0", "root"]


def test_cleanup_cmds():
    assert dx.container_rm_cmd("netspike-server") == \
        ["docker", "rm", "-f", "netspike-server"]
    assert dx.read_file_cmd("netspike-server", "/proc/net/snmp") == \
        ["docker", "exec", "netspike-server", "cat", "/proc/net/snmp"]


MEASURE_OUTPUT = """some container noise line
{"summary": {"count": 50, "p50": 0.07, "p95": 0.14, "p99": 0.25, "mean": 0.08, "max": 0.3, "attempts": 50, "retries": 0}, "window_s": 2.51}
"""


def test_parse_measure_output():
    parsed = dx.parse_measure_output(MEASURE_OUTPUT)
    assert parsed["summary"]["p99"] == 0.25
    assert parsed["window_s"] == 2.51


def test_parse_measure_output_rejects_noise():
    try:
        dx.parse_measure_output("no json here\n")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


CGROUP_BEFORE = """usage_usec 1000000
nr_periods 100
nr_throttled 0
throttled_usec 0
"""
CGROUP_AFTER = """usage_usec 3000000
nr_periods 400
nr_throttled 6
throttled_usec 402438
"""

SNMP_BEFORE = """Tcp: ActiveOpens OutSegs RetransSegs
Tcp: 10 1000 5
"""
SNMP_AFTER = """Tcp: ActiveOpens OutSegs RetransSegs
Tcp: 12 1437 78
"""


def test_cgroup_feature_delta():
    features = dx.cgroup_feature_delta(CGROUP_BEFORE, CGROUP_AFTER)
    assert features == {"cgroup_throttled_us": 402438,
                        "cgroup_nr_throttled": 6}


def test_snmp_feature_delta():
    features = dx.snmp_feature_delta(SNMP_BEFORE, SNMP_AFTER)
    assert features == {"tcp_retrans_delta": 73,
                        "tcp_outsegs_delta": 437}


def test_run_degrades_gracefully_without_docker(tmp_path):
    out = tmp_path / "results-docker.json"
    calls = []

    def runner(cmd, timeout=120):
        calls.append(cmd)
        raise AssertionError("runner must not be called without docker")

    result = dx.run_docker_experiment(out_path=str(out), runner=runner,
                                      which=lambda name: None)
    assert result["available"] is False
    assert "not found" in result["reason"]
    assert calls == []
    written = json.loads(out.read_text())
    assert written["available"] is False


def test_measure_cli_against_local_server(capsys):
    server = EchoServer().start_in_thread()
    try:
        rc = measure_cli.main(["--host", "127.0.0.1",
                               "--port", str(server.port),
                               "--count", "10"])
    finally:
        server.stop()
    assert rc == 0
    parsed = dx.parse_measure_output(capsys.readouterr().out)
    assert parsed["summary"]["count"] == 10
    assert parsed["window_s"] > 0
