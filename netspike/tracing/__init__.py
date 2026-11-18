"""eBPF tracing helpers: bpftrace scripts plus a small wrapper that
runs them and parses their output. See collect.py and the README
section on tracing. The scripts need a kernel with BTF and the
tcp / sched tracepoints; the wrapper returns None when bpftrace is
not available instead of raising."""
