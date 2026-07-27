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
- Baseline-versus-incident comparison for two recordings
- Fixture coverage for procfs/sysfs parsing and diagnostic rules
- Root-enabled eBPF integration test for controlled TCP retransmissions
- Reproducible packet-loss experiment using an isolated network namespace
- Reproducible CPU-contention experiment for receive-path concentration
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

Compare a baseline capture against an incident capture:

```sh
./bin/netdiag compare baseline.json incident.json
```

Disable eBPF explicitly when running unprivileged:

```sh
./bin/netdiag record --ebpf=false --duration 30s --output capture.json
```

Limit serialized eBPF per-flow retransmit entries:

```sh
./bin/netdiag record --max-ebpf-flows=64 --duration 30s --output capture.json
```

Use `--max-ebpf-flows=0` to keep the host-wide eBPF retransmission counter and
flow-count metadata while omitting per-flow entries from each sample.

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

eBPF per-flow retransmission entries are bounded twice: the kernel map uses an
LRU cap, and the recorder serializes at most `--max-ebpf-flows` entries per
sample. Samples include `tcp_retransmit_flow_count` and
`tcp_retransmit_flows_truncated` when the flow map contains more entries than
were serialized.

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
| TCP retransmit per-flow counters | eBPF `tcp_retransmit_skb` | bounded IPv4 flow tuples, host-wide source, truncated by `--max-ebpf-flows` |
| Host metadata | hostname, kernel release | host |

The IRQ, qdisc and eBPF collectors are best-effort optional signals. If one of
them is unavailable, `netdiag` records the failure in the collector manifest and
continues capturing required counters. eBPF recordings also include an
`ebpf_features` section so individual eBPF signals can report `enabled`,
`disabled` or `unavailable` as the collector grows beyond the initial
all-or-nothing retransmit tracepoint object.

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

When eBPF per-flow retransmission data is available, TCP retransmission findings
include the top IPv4 flow tuples as supporting evidence. If the serialized flow
list was capped by `--max-ebpf-flows`, the finding also reports the truncation.
If an eBPF feature was disabled or unavailable, the finding reports that
visibility gap with the recorded reason when one is available.

Each finding includes:

- severity;
- confidence;
- factual evidence;
- next verification step.

`netdiag compare` groups findings into incident-only, shared and baseline-only
sets, reports collector visibility differences, and prints key counter delta
changes such as TCP retransmits and qdisc drops. TCP retransmit deltas include
outbound segment denominators and percentages so raw retransmit counts are not
misread without traffic volume. When both captures include eBPF retransmit flow
data, the comparison also shows the top IPv4 flow tuples and whether a flow list
was truncated by `--max-ebpf-flows`.

Example:

```text
Finding 1: TCP retransmissions were elevated during the capture
Confidence: strong correlation
Severity: warning
Evidence: 153 retransmitted of 1101 outbound TCP segments (13.90%)
Evidence: eBPF observed 161 tcp_retransmit_skb tracepoint events
Evidence: Top retransmitting IPv4 flow: 127.0.0.1:43946 -> 127.0.0.1:40981 had 4 retransmits
Next step: Check packet loss, ECN/congestion signals, peer health, and interface error counters.
```

When eBPF visibility is missing, evidence uses the feature-level status from
the capture:

```text
Evidence: eBPF tcp_retransmit_events unavailable: permission denied
Evidence: eBPF tcp_retransmit_ipv4_flows disabled
```

Comparison example:

```text
Comparison: qdisc-drop-baseline.json -> qdisc-drop-impaired.json

Visibility differences:
- none

Incident-only findings:
- TCP retransmissions were elevated during the capture
- The selected interface qdisc recorded drops or overlimits

Shared findings:
- none

Baseline-only findings:
- none

Key delta changes:
- TCP retransmits: 3411/15204971 outbound segments (0.02%) -> 694/1829 outbound segments (37.94%)
- top NET_RX softirq CPU: CPU14 7.3% of 629844 -> CPU2 92.1% of 8663
- top NET_RX CPU busy: CPU14 50.6% -> CPU2 8.0%
- qdisc drops: 0 -> 882
- qdisc overlimits: 0 -> 0
- interface drops: 0 -> 0
- interface errors: 0 -> 0
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

## Controlled experiments

Run the reproducible isolated `tc netem` experiment with:

```sh
make experiment-loss
```

The experiment records host procfs and eBPF retransmission evidence without
applying loss to an existing host interface. See
[docs/experiments/tcp-loss.md](docs/experiments/tcp-loss.md) for setup,
configuration, expected evidence and visibility limitations.

Run the CPU-contention experiment with:

```sh
make experiment-cpu-contention
```

It records a baseline capture and an impaired capture with a CPU burner pinned
to the target receive CPU. See
[docs/experiments/cpu-contention.md](docs/experiments/cpu-contention.md) for
parameters, expected evidence and tuning guidance.

Run the qdisc-drop collection experiment with:

```sh
make experiment-qdisc-drop
```

It records a baseline capture and an impaired capture with a tiny delayed netem
queue on a temporary host veth. See
[docs/experiments/qdisc-drop.md](docs/experiments/qdisc-drop.md) for expected
raw qdisc evidence and tuning guidance.

## Capture overhead benchmark

Run the unprivileged recorder benchmark with:

```sh
make benchmark
```

Run the privileged eBPF-enabled recorder benchmark with:

```sh
make benchmark-ebpf
```

Set `INTERFACE` to include interface, IRQ and qdisc collectors:

```sh
INTERFACE=eth0 make benchmark
```

See [docs/benchmarks/capture-overhead.md](docs/benchmarks/capture-overhead.md)
for the test matrix, privileged eBPF mode and interpretation limits.

Run the end-to-end workload impact benchmark with:

```sh
make benchmark-workload-impact
```

This compares local HTTP throughput with and without `netdiag record` running
against an isolated veth workload driven by the `netdiag-workload` benchmark
binary. See
[docs/benchmarks/workload-impact.md](docs/benchmarks/workload-impact.md) for
method, tuning and interpretation limits.

## Discovery documentation

The [Phase 0 discovery package](docs/discovery/README.md) contains the initial
NGINX proxy workload, diagnostic hypotheses, controlled incident narratives,
artifact and interview templates, privacy policy, and provisional NIC driver
targets.

## Limitations

- The eBPF retransmit event count is host-wide. Bounded IPv4 per-flow
  retransmit counters are also collected, but they are not scoped to the
  selected interface or process and do not include IPv6. Per-flow entries are
  capped per sample by `--max-ebpf-flows`.
- Procfs TCP counters are network-namespace scoped while the eBPF counter is
  host-wide, so their retransmission deltas need not match.
- Counter correlation does not locate latency precisely inside the kernel path.
- Qdisc collection depends on `tc` and netlink access.
- IRQ-to-interface matching depends on kernel/driver naming and sysfs metadata.
- CPU concentration findings are conservative correlations, not proof that CPU
  contention caused latency.
- Queue-level NIC driver counters are deferred to Phase 4.
- No packet payloads are collected by default.

See [ROADMAP.md](ROADMAP.md) for product scope and implementation milestones.
