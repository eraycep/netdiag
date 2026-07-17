# netdiag

`netdiag` is an experimental Linux flight recorder for explaining TCP latency
regressions with local, evidence-backed captures.

It records low-cost host, interface and kernel-networking counters over a
bounded interval, writes a versioned JSON capture, and turns counter deltas into
conservative findings. The goal is not to be a metrics dashboard; the goal is
to preserve the right evidence during an incident and make the next debugging
step explicit.

This is still early-stage software. Findings describe measured correlations,
not proven root cause. Later milestones will add per-flow TCP timing and deeper
kernel-path attribution.

## Current capabilities

- Bounded local recording with `--duration`, `--interval` and `--max-samples`
- Atomic `0600` JSON writes using a temporary file and rename
- UTC timestamps plus monotonic elapsed nanoseconds for stable interval analysis
- Recording-level collector manifest with status, failure reason and visibility
  scope
- Best-effort optional collectors that degrade without aborting the capture
- Local analyzer that reports findings with evidence and a concrete next step
- Fixture coverage for procfs/sysfs parsing and diagnostic rules
- Root-enabled eBPF integration test for controlled TCP retransmissions
- Reproducible packet-loss experiment using an isolated network namespace
- Capture-overhead benchmark scripts

## Build and run

Requirements:

- Linux
- Go
- `make`
- `tc` from iproute2 when collecting qdisc counters or running experiments
- root or suitable BPF/perf capabilities when enabling the eBPF collector

Build and run tests:

```sh
make test
make build
```

Record a 30 second capture:

```sh
sudo ./bin/netdiag record \
  --duration 30s \
  --interval 1s \
  --max-samples 3600 \
  --interface eth0 \
  --output capture.json
```

Analyze the capture:

```sh
./bin/netdiag analyze capture.json
```

Disable eBPF explicitly when running unprivileged:

```sh
./bin/netdiag record --ebpf=false --duration 30s --output capture.json
```

## Recording behavior

Recordings stop when either `--duration` or `--max-samples` is reached. The
sample limit defaults to `3600` and must be positive.

The completed recording is written to a temporary file with `0600` permissions
and atomically renamed over the output path. If the process is interrupted
during writing, an existing capture is not replaced by partial JSON.

The recording format is versioned JSON. Each sample includes:

- wall-clock UTC timestamp for correlation with external events;
- monotonic elapsed nanoseconds for duration and delta calculations;
- collected counter groups;
- optional collector outputs when available.

Version 3 and later recordings use monotonic elapsed time during analysis, so
wall-clock corrections cannot create invalid capture durations.

## Current signals

| Signal | Source | Scope |
| --- | --- | --- |
| TCP segments, retransmits and input errors | `/proc/net/snmp` | network namespace |
| `NET_RX` and `NET_TX` softirq counters | `/proc/softirqs` | per CPU and host totals |
| CPU scheduler counters | `/proc/stat` | per CPU |
| CPU pressure | `/proc/pressure/cpu` | host, optional |
| Interface packets, bytes, drops and errors | `/sys/class/net/*/statistics` | selected interface |
| IRQ counts and affinity | `/proc/interrupts`, `/proc/irq/*/smp_affinity_list`, `/sys/class/net/*/device/msi_irqs` | selected interface when discoverable |
| Qdisc counters | `tc -s qdisc show dev <iface>` | selected interface |
| TCP retransmit tracepoint count | eBPF `tcp_retransmit_skb` | host-wide |
| Host metadata | hostname, kernel release | host |

The IRQ, qdisc and eBPF collectors are best-effort optional signals. If one of
them is unavailable, `netdiag` records the failure in the collector manifest and
continues capturing required counters.

Required collectors:

- `proc_tcp`
- `proc_softirq`
- `proc_cpu`
- `interface_stats` when `--interface` is set

Optional collectors:

- `proc_interrupts`
- `tc_qdisc`
- `ebpf_tcp_retransmit`

## Current findings

The analyzer currently reports conservative counter-level findings:

- elevated TCP retransmissions;
- selected-interface drops or errors;
- cumulative counter resets during the capture;
- network receive processing concentrated on a busy CPU.

Each finding includes:

- severity;
- confidence;
- factual evidence;
- next verification step.

Example:

```text
Finding 1: TCP retransmissions were elevated during the capture
Confidence: strong correlation
Severity: warning
Evidence: 153 retransmitted of 1101 outbound TCP segments (13.90%)
Evidence: eBPF observed 161 tcp_retransmit_skb tracepoint events
Next step: Check packet loss, ECN/congestion signals, peer health, and interface error counters.
```

## Development commands

```sh
make test
make build
make fmt
make generate
```

`make generate` regenerates the committed eBPF Go bindings and embedded BPF
object:

```sh
go generate ./internal/ebpfcollector
```

The generated files are committed so users do not need Clang to build the CLI.

## Privileged integration test

The eBPF integration test loads the real `tcp_retransmit_skb` program, creates
an isolated network namespace, applies 100% packet loss to that namespace's
loopback device, and verifies that the BPF map count increases. It does not
modify the host network namespace.

Requirements:

- Linux
- root privileges
- `unshare`
- `ip` and `tc` from iproute2

Run:

```sh
make test-integration
```

Regular `make test` remains unprivileged and skips this test.

## Packet-loss experiment

Run the reproducible isolated `tc netem` experiment with:

```sh
make experiment-loss
```

The experiment records host procfs and eBPF retransmission evidence without
applying loss to an existing host interface. See
[docs/experiments/tcp-loss.md](docs/experiments/tcp-loss.md) for setup,
configuration, expected evidence and visibility limitations.

## Capture overhead benchmark

Run the unprivileged recorder benchmark with:

```sh
make benchmark
```

Set `INTERFACE` to include interface, IRQ and qdisc collectors:

```sh
INTERFACE=eth0 make benchmark
```

See [docs/benchmarks/capture-overhead.md](docs/benchmarks/capture-overhead.md)
for the test matrix, privileged eBPF mode and interpretation limits.

## Discovery documentation

The [Phase 0 discovery package](docs/discovery/README.md) contains the initial
NGINX proxy workload, diagnostic hypotheses, controlled incident narratives,
artifact and interview templates, privacy policy, and provisional NIC driver
targets.

## Limitations

- The eBPF retransmit count is host-wide, not scoped to the selected interface,
  process, socket or flow.
- Procfs TCP counters are network-namespace scoped while the eBPF counter is
  host-wide, so their retransmission deltas need not match.
- Counter correlation does not locate latency precisely inside the kernel path.
- Qdisc collection depends on `tc` and netlink access.
- IRQ-to-interface matching depends on kernel/driver naming and sysfs metadata.
- CPU concentration findings are conservative correlations, not proof that CPU
  contention caused latency.
- No packet payloads are collected by default.

See [ROADMAP.md](ROADMAP.md) for product scope and implementation milestones.
