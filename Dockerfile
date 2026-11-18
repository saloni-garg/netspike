# netspike -- latency spike detective in a container.
#
# What this image reads from inside a container:
#   /proc/pressure/cpu and /proc/pressure/io
#       Host wide on most runtimes: pressure is not namespaced, so in
#       a container these describe the whole machine, not just this
#       container. Treat them as neighbourhood signals.
#   /proc/stat, /proc/net/sockstat, /proc/net/snmp
#       Also host or network-namespace wide depending on runtime.
#       sockstat and snmp follow the network namespace; on a default
#       bridge network they mostly reflect this container plus the
#       namespace plumbing.
#   /sys/fs/cgroup/cpu.stat (cgroup v2)
#       This one IS the container's own cgroup when the runtime
#       mounts the container cgroup at /sys/fs/cgroup, which Docker
#       does. nr_throttled and throttled_usec here are the real
#       thing: if the container has a cpu limit (docker run
#       --cpus=1), a CPU heavy phase will move these counters, and
#       the diagnoser's throttle rule fires on kernel data, not on
#       the SIGSTOP simulation used on the host.
#   /proc/<pid>/schedstat, /proc/<pid>/status, /proc/<pid>/stat
#       Per process and fully valid inside a container for pids in
#       the container's pid namespace. The experiment watches its own
#       server process, which is in the same namespace, so these work
#       unchanged.
#
# To see real cgroup throttling in the experiment, run the built
# image with a limit, for example:
#   docker build -t netspike .
#   docker run --rm --cpus=1 netspike
# The cpu_saturation phase then competes with itself for a single
# limited CPU and the throttling counters in cpu.stat climb.
#
# The multi-container experiment (netspike/docker_experiment.py)
# also uses this image three ways: as the server (python -m
# netspike.server PORT [--work], a server-only entrypoint), as the
# load client (python -m netspike.measure_cli, which prints its
# latency summary as JSON), and as the place tc runs (docker exec
# ... tc qdisc add dev eth0 root netem ...), which is why iproute2
# is installed below. The Python code itself still has no
# dependencies beyond the standard library.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY netspike/ ./netspike/
COPY README.md LICENSE ./

# No Python dependencies: the standard library is the whole supply
# chain. (iproute2 above is a system tool, for tc inside the
# container.)
CMD ["python", "-m", "netspike.experiment", "--out", "/app/results.json"]
