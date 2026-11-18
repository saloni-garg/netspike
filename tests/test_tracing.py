"""Tracing wrapper tests: the output parsers against fixture
bpftrace output, and the graceful-None behaviour when bpftrace is
absent. Live script runs need a bpftrace install and a suitable
kernel, and are not part of this suite."""

import os

from netspike.tracing import collect

RETRANSMIT_OUTPUT = """Attaching 2 probes...
counting TCP retransmits per process, Ctrl-C to stop

@retransmits[python3]: 41
@retransmits[kworker/0:1]: 2

@total: 43
total retransmits: 43
"""

RUNQUEUE_OUTPUT = """Attaching 4 probes...
measuring runqueue latency, Ctrl-C to stop

@offcpu_events[python3]: 17
@offcpu_events[redis-server]: 3

@runq_lat_us:
[0, 1)               812 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1, 2)               240 |@@@@@@@@@@|
[2, 4)                96 |@@@@|
[4, 8)                12 |@|
"""


def test_parse_retransmit_output():
    parsed = collect.parse_retransmit_output(RETRANSMIT_OUTPUT)
    assert parsed["total"] == 43
    assert parsed["per_process"] == {"python3": 41, "kworker/0:1": 2}


def test_parse_retransmit_output_map_only():
    text = "@retransmits[curl]: 3\n@retransmits[python3]: 4\n"
    parsed = collect.parse_retransmit_output(text)
    assert parsed["total"] == 7
    assert parsed["per_process"]["curl"] == 3


def test_parse_runqueue_output():
    parsed = collect.parse_runqueue_output(RUNQUEUE_OUTPUT)
    assert parsed["buckets"] == [(0, 1, 812), (1, 2, 240),
                                 (2, 4, 96), (4, 8, 12)]
    assert parsed["total_samples"] == 812 + 240 + 96 + 12
    assert parsed["offcpu_events"] == {"python3": 17,
                                       "redis-server": 3}


def test_parse_runqueue_output_empty():
    parsed = collect.parse_runqueue_output("")
    assert parsed["buckets"] == []
    assert parsed["total_samples"] == 0
    assert parsed["offcpu_events"] == {}


def test_scripts_exist_and_are_named():
    for short in ("retransmits", "runqueue"):
        path = collect.script_path(short)
        assert os.path.exists(path), path
        assert path.endswith(".bt")


def test_run_script_missing_binary_returns_none():
    # A bpftrace path that does not exist: the run degrades to
    # None instead of raising, whatever the host has installed.
    assert collect.run_script("retransmits", 1,
                              bpftrace="/nonexistent/bpftrace") is None
