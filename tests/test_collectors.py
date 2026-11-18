"""Parser tests: every parser gets fixture text in the exact format
the kernel produces, including the awkward cases (a comm field with
spaces in /proc/<pid>/stat, paired header/value lines in snmp)."""

import os

import pytest

from netspike import collectors


PRESSURE = """some avg10=1.50 avg60=0.50 avg300=0.10 total=123456
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
"""

PROC_STAT = """cpu  100 0 100 800 0 0 10 0 0 0
cpu0 50 0 50 400 0 0 5 0 0 0
intr 12345
ctxt 987654
processes 4321
softirq 1000 1 200 30 400 50 60 70 80 90 19
"""

SOCKSTAT = """sockets: used 231
TCP: inuse 7 orphan 0 tw 3 alloc 9 mem 1
UDP: inuse 2 mem 0
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
"""

SNMP = """Ip: Forwarding DefaultTTL InReceives InHdrErrors
Ip: 2 64 1000 0
Tcp: ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
Tcp: 10 20 1 2 3 5000 6000 42 0 7
Udp: InDatagrams NoPorts InErrors OutDatagrams
Udp: 100 0 0 100
"""

CGROUP_CPU_STAT = """usage_usec 1000000
user_usec 600000
system_usec 400000
nice_usec 0
nr_periods 100
nr_throttled 7
throttled_usec 123456
"""

CGROUP = """0::/user.slice/user-1000.slice/session-3.scope
"""

SCHEDSTAT = "123456789 98765432 42\n"

STATUS = """Name:\tpython3
State:\tS (sleeping)
voluntary_ctxt_switches:\t123
nonvoluntary_ctxt_switches:\t45
"""

# comm contains spaces on purpose: "(my proc name)".
PID_STAT = ("4242 (my proc name) S 100 1234 1234 0 -1 4194560 100 0 "
            "0 0 111 222 0 0 20 0 1 0 1000 5000000\n")


def test_parse_pressure():
    parsed = collectors.parse_pressure(PRESSURE)
    assert parsed["some"]["avg10"] == 1.50
    assert parsed["some"]["total"] == 123456
    assert parsed["full"]["total"] == 0


def test_parse_proc_stat_cpu_and_softirq():
    parsed = collectors.parse_proc_stat(PROC_STAT)
    assert parsed["cpu"]["user"] == 100
    assert parsed["cpu"]["total"] == 1010
    assert parsed["cpu"]["idle_all"] == 800
    assert parsed["softirq"]["total"] == 1000
    assert parsed["softirq"]["net_rx"] == 400
    assert parsed["softirq"]["net_tx"] == 30
    assert parsed["ctxt"] == 987654
    assert parsed["processes"] == 4321


def test_parse_sockstat():
    parsed = collectors.parse_sockstat(SOCKSTAT)
    assert parsed["sockets_used"] == 231
    assert parsed["tcp_inuse"] == 7
    assert parsed["tcp_tw"] == 3
    assert parsed["tcp_alloc"] == 9
    assert parsed["udp_inuse"] == 2


def test_parse_snmp_tcp_retrans():
    parsed = collectors.parse_snmp(SNMP)
    assert parsed["tcp"]["OutSegs"] == 6000
    assert parsed["tcp"]["RetransSegs"] == 42
    assert parsed["tcp"]["InSegs"] == 5000
    assert parsed["udp"]["InDatagrams"] == 100


def test_parse_cgroup_cpu_stat():
    parsed = collectors.parse_cgroup_cpu_stat(CGROUP_CPU_STAT)
    assert parsed["nr_throttled"] == 7
    assert parsed["throttled_usec"] == 123456
    assert parsed["usage_usec"] == 1000000


def test_parse_cgroup_path():
    assert collectors.parse_cgroup_path(CGROUP) == \
        "/user.slice/user-1000.slice/session-3.scope"
    assert collectors.parse_cgroup_path("2:cpu:/foo\n") is None


def test_parse_schedstat():
    parsed = collectors.parse_schedstat(SCHEDSTAT)
    assert parsed["runtime_ns"] == 123456789
    assert parsed["wait_ns"] == 98765432
    assert parsed["timeslices"] == 42


def test_parse_status():
    parsed = collectors.parse_status(STATUS)
    assert parsed["voluntary_ctxt_switches"] == 123
    assert parsed["nonvoluntary_ctxt_switches"] == 45
    assert parsed["state"].startswith("S")


def test_parse_pid_stat_with_spaces_in_comm():
    parsed = collectors.parse_pid_stat(PID_STAT)
    assert parsed["state"] == "S"
    assert parsed["utime"] == 111
    assert parsed["stime"] == 222


@pytest.mark.skipif(not os.path.exists("/proc/stat"),
                    reason="needs a Linux /proc")
def test_collect_all_live():
    snap = collectors.collect_all(sample_states=False)
    assert snap["proc_stat"]["cpu"]["total"] > 0
    assert snap["sockstat"] is not None
    tcp = snap["snmp_tcp"]
    assert tcp is not None and "RetransSegs" in tcp
    if snap["pressure_cpu"] is not None:
        assert "some" in snap["pressure_cpu"]
    if snap["cgroup_cpu"] is not None:
        assert "usage_usec" in snap["cgroup_cpu"]


def test_readers_degrade_gracefully(monkeypatch):
    monkeypatch.setattr(collectors, "PROC", "/nonexistent-proc")
    assert collectors.read_proc_stat() is None
    assert collectors.read_sockstat() is None
    assert collectors.read_pressure("cpu") is None
    assert collectors.read_schedstat(999999) is None
