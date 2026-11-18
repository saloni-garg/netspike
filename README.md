# netspike -- a kernel and container latency-spike detective

A latency spike lands on a service and the first question is always
the same: is this the CPU, the network, or the disk? netspike is a
small, dependency free toolkit for answering that question from
kernel counters instead of guesswork.

It does three things:

1. **Collects** real kernel signals: pressure stall information,
   softirq counts, TCP retransmit counters, cgroup v2 throttling
   stats, per process runqueue wait, and process state samples.
2. **Injects** real latency faults: CPU saturation from busy
   processes, CPU throttling simulated by duty cycling a process
   with SIGSTOP/SIGCONT, and network delay plus loss through a
   userspace TCP proxy.
3. **Diagnoses** each spike blind. The diagnoser sees only the
   before/during kernel counters and the latency percentiles, never
   which fault was injected, and classifies the spike as
   `cpu_throttle`, `cpu_saturation`, `network_retransmit`,
   `network_delay`, `io_pressure`, or `unknown`, with the reasons
   (the actual counter values) attached.

Pure Python 3 standard library. No pip installs. Linux only, because
the counters are Linux kernel interfaces.

A second experiment module, `netspike/real_experiment.py`, runs the
same blind diagnosis against faults created by real kernel
mechanisms instead of simulations: a real cgroup v2 `cpu.max`
limit for throttling, and real `tc`/netem qdiscs on loopback for
network delay and loss. See "Results on a dedicated machine".

Two more modules extend the same idea: `netspike/docker_experiment.py`
runs the server and the client as separate Docker containers on a
bridge network, with the CPU limit and the netem qdisc applied
inside the server container, and `netspike/tracing/` holds bpftrace
scripts for the eBPF view of two of the signals (TCP retransmits
per process, and runqueue latency as a histogram). Both are
described in their own sections below.

## Architecture

| File | What it does |
| --- | --- |
| `netspike/collectors.py` | Parsers and readers for every kernel interface below. Parsers take text and are unit tested with fixtures; readers return None when an interface is unavailable instead of raising. |
| `netspike/server.py` | A tiny line based TCP echo server. One request per connection. Runs in a thread for tests or as its own process for experiments, where a separate pid is the point: schedstat, status, and process state are per process data. |
| `netspike/client.py` | Load client. One fresh connection per request, per request latency in milliseconds, p50/p95/p99 from the raw samples. Retry time is included in the latency, because that is how loss shows up in real life. |
| `netspike/inject.py` | The fault injectors: `CpuSaturationInjector` (busy processes pinned to the available CPUs), `CpuThrottleInjector` (SIGSTOP/SIGCONT duty cycle), and `TcpProxy` (delay, jitter, and blackhole-then-reset loss). |
| `netspike/diagnose.py` | `diff_snapshots()` turns two snapshots into a feature dict; `diagnose()` applies the documented rules in a fixed order and returns the label plus reasons. |
| `netspike/experiment.py` | Runs baseline plus each fault in sequence against a server subprocess, diagnoses each phase blind, and writes `results.json`. |
| `netspike/real_experiment.py` | Same trial structure, real kernel faults: the server runs in its own cgroup with a real `cpu.max` limit and a CPU-hungry workload for throttling, `tc qdisc ... netem` on loopback for delay and loss, busy processes for saturation, plus a supplementary saturation phase against the CPU-hungry server. Needs root. Writes `results-verda.json`. |
| `netspike/docker_experiment.py` | Multi-container version: server and client containers on a user-defined bridge network, server started with `--cpus=0.25` for the CPU phase, netem applied to the server container's `eth0`. Snapshots are taken inside the server container with `docker exec` and fed to the same diagnoser. Writes `results-docker.json`; degrades gracefully when Docker is absent. |
| `netspike/measure_cli.py` | Tiny CLI that runs the load client against a host/port and prints the latency summary as JSON. It is how the client container reports back. |
| `netspike/tracing/` | bpftrace scripts (`tcp_retransmits.bt`, `runqueue_latency.bt`) plus `collect.py`, a wrapper that runs a script for a few seconds and parses its output into numbers, returning None when bpftrace is unavailable. |

## Kernel interfaces

| Interface | What is read | What it tells you |
| --- | --- | --- |
| `/proc/pressure/cpu` | `some` and `full` stall totals (us) and averages | Time tasks spent runnable but not running, system wide. The single best "the CPU is oversubscribed" signal. |
| `/proc/pressure/io` | Same shape, for io | Time tasks stalled waiting on storage. |
| `/proc/stat` | Aggregate `cpu` line, `softirq` line (NET_RX, NET_TX, BLOCK, ...), `ctxt` | CPU busy fraction over a window, packet processing load in softirq context, context switch rate. |
| `/proc/net/snmp` | `Tcp:` group: `RetransSegs`, `OutSegs`, `InSegs`, ... | Kernel level retransmits. The ground truth for loss, when the loss is real packet loss. |
| `/proc/net/sockstat` | TCP inuse / orphan / tw / alloc, sockets used | Connection population, including time-wait growth during connection churn. |
| `/sys/fs/cgroup/cpu.stat` (v2) | `nr_throttled`, `throttled_usec`, `usage_usec` | Real cgroup CPU throttling, resolved per process through `/proc/<pid>/cgroup`. |
| `/proc/<pid>/schedstat` | Run time, runqueue wait time, timeslices | How long the watched process waited for a CPU versus ran on one. The wait-to-runtime ratio separates queueing from working. |
| `/proc/<pid>/status` | Voluntary and nonvoluntary context switches | Whether a process gives up the CPU itself or gets taken off it. |
| `/proc/<pid>/stat` | State letter, utime, stime | Sampled repeatedly over a window: a process that is stopped (T state) for most samples is being throttled or frozen, whatever the other counters say. |

Every collector has a graceful fallback: if the file does not exist
(restricted container, older kernel, different cgroup setup) the
snapshot records None for that section and the diagnoser's rules
that need it simply do not fire.

## How the diagnosis rules work

Rules fire in this order, most specific signal first. Thresholds are
plain constants at the top of `diagnose.py`, tuned for measurement
windows of a few seconds on a small machine.

1. **cpu_throttle** -- `throttled_usec` rose by 20 ms or more in the
   server's cgroup, or the server spent at least 15% of process
   state samples in the stopped (T) state. Runnable, but not
   allowed to run.
2. **network_retransmit** -- `RetransSegs` rose by at least 2 with a
   tail rise, or many requests were reset without an answer while
   p99 climbed sharply (the loopback churn pattern; see
   Limitations).
3. **cpu_saturation** -- Two absolute branches, then a
   baseline-relative one.
   Absolute: the server's runqueue wait is at least 1.5x its
   on-CPU runtime while cpu pressure climbed by 50 ms or more, or
   CPU utilization is at least 75% with a large absolute runqueue
   wait.
   Baseline-relative (rule 3b): the absolute gates assume a
   saturated machine hurts the watched service in absolute terms.
   A cheap service breaks that (see the dedicated-machine results:
   an echo server at 0.07 ms per request, saturated, reached a
   p99 of only 3.08 ms and a wait ratio of 0.90, and read as no
   fault). When the caller passes `baseline_features` -- the
   feature dict of the same workload with no fault -- this branch
   instead requires all of: (a) the cpu pressure stall rate is at
   least 3x the baseline rate, the stall is at least 20% of the
   window, and the absolute stall is at least 100 ms; (b) the
   server's wait-to-runtime ratio is at least 0.5 and grew by at
   least 0.4 over its baseline ratio, with at least 20 ms of
   absolute wait -- this is what keeps the branch specific, since
   a server blocked on the network does not queue on a runqueue;
   (c) p95 and p99 each grew to at least 3x baseline, with the
   damage tail heavy rather than a uniform shift. Without
   `baseline_features` this branch does not fire. Both experiment
   runners pass it (the real experiment aggregates it as medians
   across the baseline trials).
4. **network_delay** -- A uniform shift: p50 rose by at least 8 ms
   and by at least 40% of the p99 rise, with no cpu or loss signal.
   A fixed extra hop lifts the whole distribution; a stall does
   not.
5. **io_pressure** -- Io pressure rose by 50 ms or more, CPUs are
   not hot, and the latency damage is tail heavy rather than a
   uniform shift. Pressure counters are system wide and noisy on
   shared machines, so this is deliberately the hardest positive
   rule to fire.
6. **unknown** -- Nothing fired. Baseline phases land here, which
   is the correct answer for "nothing is wrong".

## Running it

Locally (Python 3.10+, Linux):

```sh
python3 -m netspike.experiment --out results.json --count 50
```

That starts the echo server as a subprocess, measures a baseline,
injects each fault in turn, diagnoses each one blind, prints a
table, and writes the full record (latencies, features, reasons) to
`results.json`.

The real-fault version (root required, for the cgroup and tc
operations):

```sh
python3 -m netspike.real_experiment --out results-verda.json --trials 5
```

Each phase runs 5 independent trials, every trial is diagnosed
blind, and the qdisc is removed after every phase and from a
finally block.

Tests (needs pytest, which is a test-only dependency; the toolkit
itself has none):

```sh
python3 -m pytest tests/ -q
```

In Docker:

```sh
docker build -t netspike .
docker run --rm netspike
docker run --rm --cpus=1 netspike   # watch real cgroup throttling
```

The multi-container experiment (needs a Docker daemon; it builds
the image itself, creates and always cleans up its containers and
network, and writes `results-docker.json`):

```sh
python3 -m netspike.docker_experiment --out results-docker.json
```

What it runs, in order: a baseline phase against a CPU-hungry
server container (`python -m netspike.server 8765 --work`, the
server-only entrypoint) on a user-defined bridge network
(`netspike-net`), with the load client in its own container
(`python -m netspike.measure_cli`, which prints its summary as
JSON); then the same server started with a real container CPU
limit, `--cpus=0.25`, diagnosed from that container's own cgroup
`cpu.stat` read via `docker exec`; then netem delay (`50ms 10ms`)
and loss (`15%`) applied inside the server container with
`tc qdisc add dev eth0 root netem ...` (the container runs with
`--cap-add NET_ADMIN`, and the image carries iproute2 for `tc`),
diagnosed from the server container's kernel TCP counters. When
Docker is absent the module says so plainly, writes a results
file recording `available: false` with the reason, and exits 0.
A live run is recorded in `results-docker.json` (dedicated
machine, Docker 29.1.3): the CPU-limit and delay phases were
diagnosed correctly from the containers' own counters, and the
loss phase was missed, for reasons stated in "Results on a
dedicated machine" below.

With eBPF (needs bpftrace and a kernel with BTF and the tcp /
sched tracepoints; live-verified on the dedicated machine,
kernel 6.8, bpftrace 0.20.2 -- see "Results on a dedicated
machine" below):

```sh
sudo bpftrace netspike/tracing/tcp_retransmits.bt
sudo bpftrace netspike/tracing/runqueue_latency.bt
```

or, parsed into numbers from Python:

```python
from netspike.tracing import collect
collect.collect_retransmits(5)  # {"total": ..., "per_process": {...}}
collect.collect_runqueue(5)     # {"buckets": [...], "total_samples": ...,
                                #  "offcpu_events": {...}}
```

`tcp_retransmits.bt` hooks `tracepoint:tcp:tcp_retransmit_skb`
and counts retransmits per process: the eBPF view of the same
ground truth `/proc/net/snmp` totals in `RetransSegs`, except
attributed to the process whose socket retransmitted. (One
portability note: the script keeps a plain integer counter
next to its `count()` map for the printed total, because
bpftrace 0.20 rejects printing a `count()` value with `%ld`
and rejects casting it to an integer.)
`runqueue_latency.bt` pairs `sched:sched_wakeup` with
`sched:sched_switch` to histogram how long runnable tasks wait
for a CPU -- the runqlat idea, and the distribution form of what
schedstat reports per process -- and counts off-CPU switch-outs
(a task leaving a CPU in a non-running state) per process. The
wrapper returns None when bpftrace is missing or the run fails,
instead of raising.

The Dockerfile header explains which interfaces are host wide and
which are the container's own inside a container. Short version:
pressure and `/proc/stat` describe the whole machine, while
`/sys/fs/cgroup/cpu.stat` is the container's own cgroup under
Docker, so with `--cpus=1` the saturation phase moves the real
`nr_throttled` / `throttled_usec` counters and the throttle rule
fires on kernel data rather than on the SIGSTOP simulation.

## Results

Recorded run, from `results.json` in this repo. Machine: a shared
virtual machine, Linux 7.0.0-44-generic x86_64, 4 CPUs visible,
Python 3.12.3. 50 requests per phase (40 for the network phases),
one request per connection, on loopback.

| Phase | p50 (ms) | p95 (ms) | p99 (ms) | Diagnosis | Correct |
| --- | --- | --- | --- | --- | --- |
| baseline | 0.51 | 0.64 | 0.73 | unknown | yes (no fault) |
| cpu_saturation | 1.88 | 23.35 | 65.01 | cpu_saturation | yes |
| cpu_throttle | 0.80 | 4.34 | 92.34 | cpu_throttle | yes |
| network_delay | 46.50 | 51.84 | 56.15 | network_delay | yes |
| network_retransmit | 2.46 | 502.40 | 502.53 | network_retransmit | yes |

Diagnosis accuracy on this run: **4 of 4 faults**, plus the baseline
correctly read as no fault.

The counter values behind two of the calls:

- Saturation: the server waited 27 ms on runqueues against 9 ms of
  on-CPU time (ratio 3.0), and cpu pressure (`some`) climbed by
  232,104 us during the phase, against 1,022 us during baseline.
- Throttle: the server was in the stopped (T) state for 82% of
  process state samples, while its median latency stayed at
  0.80 ms. Most requests landed in a run window; the unlucky tail
  waited out a stop window, which is exactly the shape throttling
  produces.
- Retransmit: 27 of 40 requests were blackholed and reset, the
  client retried 16 times, and p99 went to half a second. The
  kernel `RetransSegs` delta was 0. See Limitations; on loopback
  that counter honestly does not move for userspace loss.

Tests: **50 passed** (collector parsers with fixture text, diagnoser
rules with synthetic snapshots for every class including the
baseline-relative saturation branch, the Docker module's command
construction and output parsers, the tracing wrapper's output
parsers, and one integration test that saturates the CPUs against
a live server and checks both the p99 rise and the cpu class
diagnosis).

Two honest notes about variance: during development, earlier runs
of this same experiment on this same machine scored 2/4 and then
3/4. The misses were informative: system wide counters on a shared
VM are noisy enough that an io pressure rule fired on a pure delay
phase, and a light server's absolute runqueue wait was far below a
threshold copied from busier systems. The rule order and the
wait-to-runtime ratio in the current diagnoser are the direct
result. Treat 4/4 as "on this run, on this machine", not as a
guarantee.

## Results on a dedicated machine

Recorded run, from `results-verda.json` in this repo, using
`netspike/real_experiment.py` (real kernel faults, root). Machine:
a dedicated Verda CPU-TURIN.4V.16G instance, 4 vCPU, 16 GB,
Ubuntu 24.04 (FIN-03), Linux 6.8.0-147-generic x86_64,
Python 3.12.3. Five independent trials per phase, every trial
diagnosed blind; the numbers below are medians across trials.
This is a fresh re-run with the current diagnoser (including the
baseline-relative saturation rule, rule 3b) on a second dedicated
instance of the same type; the first dedicated run, scored with
the previous diagnoser, is kept as `results-verda-v1.json`.

| Phase | Real mechanism | p50 (ms) | p95 (ms) | p99 (ms) | Correct |
| --- | --- | --- | --- | --- | --- |
| baseline | none | 0.06 | 0.13 | 0.23 | 5 of 5 (read as no fault) |
| cpu_saturation | busy processes (cores + 1) vs echo server | 0.05 | 2.03 | 3.12 | 5 of 5 |
| cpu_saturation (CPU-bound) | busy processes (2x cores + 1) vs CPU-hungry server | 14.02 | 17.49 | 19.92 | 5 of 5 |
| cpu_throttle | cgroup v2 `cpu.max` = "20000 100000" | 3.39 | 83.42 | 84.19 | 5 of 5 |
| network_delay | `tc` netem `delay 50ms 10ms` on lo | 200.01 | 220.29 | 224.21 | 5 of 5 |
| network_retransmit | `tc` netem `loss 15%` on lo | 0.30 | 1273.04 | 3003.15 | 5 of 5 |

The kernel evidence behind the calls, again as medians:

- **Throttling moved the real cgroup counters.** In the server's
  own cgroup, `nr_throttled` rose by a median of 6 per trial
  (5 to 6 across trials) and `throttled_usec` rose by a median of
  421,380 us per trial window. That is the counter the diagnoser's
  throttle rule fired on, not process state sampling. The same
  CPU-hungry server with no limit had a p50 of about 3.3 ms;
  under the 20% limit its median stayed near that (most requests
  fit inside a period's budget) while the tail stretched to
  about 84 ms.
- **Loss moved the real kernel retransmit counter.** Under
  netem `loss 15%`, the `Tcp RetransSegs` delta was a median of
  69 per trial (48 to 75 across trials), against `OutSegs` rising
  by a median of 444. In the shared-VM run above, the same delta
  was 0 in every phase; with real packet loss the diagnoser's
  kernel-counter branch is the one that fires, as designed.
- **Delay was a clean uniform shift.** A 50 ms netem setting
  showed up as about 200 ms of round trip time on loopback (a
  loopback round trip passes the egress qdisc more than once),
  the median rose with the tail, and the retransmit delta stayed
  at 0.
- **Saturation against the echo server: the recorded miss is
  fixed, and the fix is now verified live.** In the first
  dedicated run this phase scored 0 of 5 (kept in
  `results-verda-v1.json`): the fault was real (cpu pressure
  `some` accumulated over a second of stall per trial window),
  but the echo server spends about 0.07 ms per request, so even
  saturated its p99 only reached about 3 ms and its runqueue
  wait ratio stayed under the diagnoser's absolute gates (p99
  rise above 5 ms, ratio at least 1.5); every trial was read as
  `unknown`. Rule 3 now has a baseline-relative branch (rule 3b,
  described under "How the diagnosis rules work"): judged
  against the workload's own baseline instead of absolute gates,
  the echo-server window qualifies on all three legs -- stall
  rate several times baseline with seconds of absolute stall, a
  wait ratio that grew from about 0 to 0.82, and a tail that grew
  about 13x while the median did not move. In this fresh live
  re-run the phase scored **5 of 5** (pressure median
  1,239,463 us per window, wait ratio 0.82, p99 3.12 ms), and
  every other phase stayed at 5 of 5, so the relative branch did
  not cost the absolute rules anything on this run. Pointed at
  the CPU-hungry server (supplementary phase, 2x cores + 1 busy
  processes), the same mechanism gave a wait ratio of 5.48,
  pressure of 2,557,825 us, and 5 of 5 correct, as before.

### Docker and eBPF, live on the same class of machine

Recorded in `results-docker.json`, run on a dedicated
CPU-TURIN.4V.16G instance (Docker 29.1.3, same kernel as above),
server and client as separate containers on the `netspike-net`
bridge network:

| Phase | Mechanism | p99 (ms) | Diagnosis |
| --- | --- | --- | --- |
| baseline | CPU-hungry server container, no limit | 0.10 | `unknown` (correct) |
| container_cpu_limit | same server with `--cpus=0.25` | 0.10 | `cpu_throttle` (correct) |
| netem_delay | netem `delay 50ms 10ms` on the server container's `eth0` | 97.40 | `network_delay` (correct) |
| netem_loss | netem `loss 15%` on the server container's `eth0` | 1023.71 | `unknown` (**wrong**, expected `network_retransmit`) |

- **The container CPU limit was diagnosed from the container's
  own cgroup.** During the limited phase the server container's
  `cpu.stat` showed `nr_throttled` up by 2 and `throttled_usec`
  up by 37,007 us, and the throttle rule fired on that counter
  (`cgroup throttled_usec rose by 37007 us`). The p99 did not
  move (0.10 ms in both phases): the counters carried the call,
  not the latency.
- **Netem delay inside the container worked as on the host**:
  p50 rose by 51.3 ms, p99 by 97.3 ms, retransmit delta 0, read
  as a clean uniform shift.
- **Netem loss inside the container was a genuine miss.** The
  client's p99 rose to 1023.71 ms, so the fault was visible in
  latency, but the server container's `RetransSegs` delta over
  the phase window was 0 (and `OutSegs` rose by only 44, about
  one segment per measured request). The diagnoser snapshots
  only the server container; under egress-only loss with a
  client that does not retry and closes stalled connections,
  the retransmissions happen on the client side and after the
  window, so the server-side kernel-counter branch never saw
  its signal and no other rule fired. On the host loopback run
  the client and server share one kernel and one counter, which
  is why the same phase scores 5 of 5 there and missed here.
  The miss is recorded in `results-docker.json` as scored
  (2 of 3 fault phases correct, baseline also correct).

The eBPF scripts were run live on the same machine (bpftrace
0.20.2, kernel 6.8):

- **Retransmits, eBPF vs /proc, same window.** With netem
  `loss 15%` on loopback and the echo server under load,
  `tcp_retransmits.bt` counted **75** retransmits in a 10 second
  collection (the `@total` map dump said 76; the END printf and
  the map are read at slightly different moments), while the
  `/proc/net/snmp` `RetransSegs` delta over the bracketing
  window was **150**. Same order of magnitude, a factor of two
  apart: the /proc window brackets the whole run including the
  load tail after the script stopped, and /proc counts every
  retransmitted segment system wide, while the tracepoint count
  covers only its collection window. Per-process attribution
  worked as the script header predicts: most retransmits were
  attributed to the `swapper` (idle/softirq) contexts (33 + 28 +
  5 + 4 across the four CPUs), with 6 attributed to `python3`.
- **Runqueue latency under saturation.** With the busy-process
  injector running, `runqueue_latency.bt` collected 1,816
  wakeup-to-switch samples in 10 seconds. The mass sits in the
  [2, 4) us bucket (1,518 samples, about 84%), with a tail that
  reaches the [256, 512) us bucket: 43 samples waited at least
  16 us and 12 at least 128 us. The off-CPU counter recorded
  9,998 switch-outs in a non-running state, led by `python3`
  (6,515, the load and server processes) and `rcu_preempt`
  (2,567). The busy processes themselves barely appear in the
  histogram: a task that never sleeps is never woken, so
  saturation shows up in the tail and in other tasks' waits,
  not in the saturating task's own wakeups.
- **One script fix was needed.** bpftrace 0.20 rejects
  `printf("%ld", @total)` when `@total` holds a `count()`
  ("printf: %ld specifier expects a value of type integer
  (count supplied)"), and a cast from count to int64 is also
  rejected. `tcp_retransmits.bt` now keeps a plain integer
  counter (`@total_int`) next to the count map and prints that;
  the printed format the parser expects is unchanged.
  `runqueue_latency.bt` ran as written.

## Limitations

- **The original experiment still uses a userspace proxy, not
  tc/netem.** The proxy cannot drop packets the kernel has already
  accepted. Loss is simulated by accepting a request, blackholing
  it for 250 ms, and resetting the connection, so the client
  experiences a stall and a retry. On loopback this produces
  little or no kernel level retransmission (`RetransSegs` stayed
  at a 0 delta in every phase of the shared-VM run), and the
  diagnoser's retransmit rule has an explicit churn branch for
  that. The real experiment above removes this limitation: under
  real netem loss the kernel counter moved (delta 73 per trial)
  and the kernel-counter branch fired.
- **The original experiment's throttling is SIGSTOP duty cycling,
  not a cgroup limit.** A real `cpu.max` limit is enforced by the
  scheduler and recorded in `cpu.stat`. The simulation reproduces
  the visible symptom (a runnable process periodically not
  running) without needing write access to cgroupfs, and the
  diagnoser detects it through process state sampling rather than
  through the throttling counters. The real experiment above
  removes this limitation too: it sets a real `cpu.max`, and
  `nr_throttled` / `throttled_usec` in the server's cgroup rose
  on every trial. Run the Docker image with `--cpus=1` to see
  the same counters move in a container.
- **A nearly free workload hides saturation from absolute
  thresholds.** As the first dedicated run showed, if the watched
  service does almost no work per request, saturating the CPUs
  barely moves its latency in absolute terms, and the original
  absolute gates (p99 rise above 5 ms, wait ratio at least 1.5)
  read the phase as no fault. The baseline-relative branch (rule
  3b) fixes that case: it judges pressure, queueing, and tail
  growth against the workload's own baseline, and the fresh live
  re-run with the new rule scored 5 of 5 on the echo-saturation
  phase with no other phase changed. One caveat remains: the
  branch needs the caller to supply baseline features (a caller
  that does not, gets the old behaviour). The deeper point
  also stands: the counters say the machine is saturated; saying
  a specific cheap service is *hurt* by it rests on its tail
  actually growing relative to its own baseline, which is what
  the branch requires.
- **System wide counters on a shared machine are noisy.** Pressure,
  `/proc/stat`, and snmp describe the whole host. Neighbours show
  up in them. The rules cope by combining signals and by preferring
  per process counters (schedstat, process state) where they exist,
  but a busy neighbour can still pollute a window.
- **Loopback only, and a deliberately tiny server.** The echo
  server does almost no work per request, which keeps the signal
  clean and also means absolute numbers (a server runtime of about
  9 ms per phase) are small. Thresholds are tuned for this scale
  and stated in `diagnose.py`; a busier service would want them
  revisited.
- **The Docker loss phase is diagnosed from the wrong side of
  the connection.** Both the Docker and eBPF paths are now live
  verified (dedicated machine, Docker 29.1.3, bpftrace 0.20.2,
  kernel 6.8; results in `results-docker.json` and in the
  dedicated-machine section above). The live Docker run exposed
  a real blind spot the unit tests could not: the experiment
  snapshots only the server container, and under egress-only
  netem loss the server container's `RetransSegs` delta stayed
  at 0 for the whole phase window (the retransmitting side is
  the client, and a non-retrying client that closes stalled
  connections leaves little for the server's stack to
  retransmit), so the loss phase was read as `unknown` despite
  a p99 of 1023.71 ms. Fixing that means snapshotting the
  client container's counters too, or correlating both sides;
  as shipped, the Docker diagnosis of loss is weaker than the
  host one, where client and server share a kernel. The Docker
  module also assumes the server is PID 1 in its container for
  schedstat, which holds for the image's entrypoint as this repo
  runs it.
- **Virtualized CPU accounting.** In this VM the aggregate
  `/proc/stat` busy fraction read 0.30 during baseline and 0.50
  during saturation, which understates what five busy processes on
  four cores are doing. The diagnoser therefore treats utilization
  as a supporting signal, never the only one.

## License

MIT, see LICENSE.
