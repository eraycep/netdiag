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
- Reproducible selected-process scheduler-delay experiment
- Capture-overhead benchmark scripts

## Build and run

Requirements:

- Linux
- Go
- `make`
- `tc` from iproute2 when collecting qdisc counters or running experiments
- `ss` from iproute2 when enabling optional TCP info collection
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

Measure workload-level TCP connect latency with the synthetic workload client:

```sh
./bin/netdiag-workload client \
  --url http://127.0.0.1:18080/payload \
  --duration 10s \
  --concurrency 8 \
  --new-connection
```

`--new-connection` disables keepalives so each request creates a TCP
connection. This is workload output, not `netdiag record` evidence.

Disable eBPF explicitly when running unprivileged:

```sh
./bin/netdiag record --ebpf=false --duration 30s --output capture.json
```

Record selected-process scheduler counters:

```sh
./bin/netdiag record --pid 1234 --duration 30s --output capture.json
```

Limit serialized TCP socket queue snapshots:

```sh
./bin/netdiag record --max-tcp-socket-queues=16 --duration 30s --output capture.json
```

Use `--max-tcp-socket-queues=0` to keep aggregate socket queue counters while
omitting per-socket queue tuples from each sample. Socket queue tuples include
local and remote IP addresses and ports.

Collect optional TCP RTT and congestion details from `ss -tin`:

```sh
./bin/netdiag record --tcp-info --max-tcp-info-sockets=32 --duration 30s --output capture.json
```

Use `--max-tcp-info-sockets=0` to keep the collector visibility entry while
omitting per-socket TCP info tuples. TCP info tuples include local and remote IP
addresses and ports.

Limit serialized eBPF per-flow retransmit entries:

```sh
./bin/netdiag record --max-ebpf-flows=64 --duration 30s --output capture.json
```

Use `--max-ebpf-flows=0` to keep the host-wide eBPF retransmission counter and
flow-count metadata while omitting per-flow entries from each sample.

Limit how many samples can serialize eBPF per-flow entries:

```sh
./bin/netdiag record --max-ebpf-flow-samples=10 --duration 30s --output capture.json
```

Use `--max-ebpf-flow-samples=-1` for the default unlimited sample budget.

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

TCP socket queue tuples are bounded by `--max-tcp-socket-queues`. Aggregate TCP
socket queue counters are still collected when the tuple limit is zero. Samples
include `socket_queue_count` and `top_queues_truncated` when more non-empty
socket queues were observed than serialized. Socket queue tuples include local
and remote IP addresses and ports; set `--max-tcp-socket-queues=0` to omit them
while keeping aggregate socket queue counters.

eBPF per-flow retransmission entries are bounded twice: the kernel map uses an
LRU cap, and the recorder serializes at most `--max-ebpf-flows` entries per
sample. `--max-ebpf-flow-samples` can also limit how many samples serialize
flow details during a recording. Samples include `tcp_retransmit_flow_count`,
`tcp_retransmit_flows_truncated` and, when a recording-wide budget omits flow
details, `tcp_retransmit_flows_omitted_reason`.

TCP info collection is opt-in because it stores endpoint metadata from
established sockets. When enabled with `--tcp-info`, the recorder runs `ss -tin`
once per sample and stores a bounded list sorted by highest RTT first. Samples
include `count` and `truncated` when more established sockets were observed
than serialized.

## Current signals

| Signal | Source | Scope |
| --- | --- | --- |
| TCP segments, retransmits and input errors | `/proc/net/snmp` | network namespace |
| TCP socket queue aggregates | `/proc/net/tcp`, `/proc/net/tcp6` | network namespace |
| TCP RTT and congestion details | `ss -tin` | network namespace, opt-in, endpoint metadata, truncated by `--max-tcp-info-sockets` |
| `NET_RX` and `NET_TX` softirq counters | `/proc/softirqs` | per CPU and host totals |
| CPU scheduler counters | `/proc/stat` | per CPU |
| CPU pressure | `/proc/pressure/cpu` | host, optional |
| Selected process scheduler counters | `/proc/<pid>/schedstat` | selected process when `--pid` is set |
| Interface packets, bytes, drops and errors | `/sys/class/net/*/statistics` | selected interface |
| IRQ counts and affinity | `/proc/interrupts`, `/proc/irq/*/smp_affinity_list`, `/sys/class/net/*/device/msi_irqs` | selected interface when discoverable |
| Qdisc counters | `tc -s qdisc show dev <iface>` | selected interface |
| TCP retransmit tracepoint count | eBPF `tcp_retransmit_skb` | host-wide |
| TCP retransmit per-flow counters | eBPF `tcp_retransmit_skb` | bounded IPv4 and IPv6 flow tuples, host-wide source, truncated by `--max-ebpf-flows` |
| Host metadata | hostname, kernel release | host |

The IRQ, qdisc, TCP info and eBPF collectors are best-effort optional signals.
If one of them is unavailable, `netdiag` records the failure in the collector
manifest and continues capturing required counters. eBPF recordings also include an
`ebpf_features` section so individual eBPF signals can report `enabled`,
`disabled` or `unavailable` as the collector grows beyond the initial
all-or-nothing retransmit tracepoint object.

Required collectors:

- `proc_tcp`
- `proc_tcp_sockets`
- `proc_softirq`
- `proc_cpu`
- `interface_stats` when `--interface` is set

Optional collectors:

- `proc_pid_schedstat`
- `proc_interrupts`
- `tc_qdisc`
- `ss_tcp_info`
- `ebpf_tcp_retransmit`

## Current findings

The analyzer currently reports conservative evidence-backed findings:

- elevated TCP retransmissions;
- TCP socket queue growth;
- elevated TCP RTT when `--tcp-info` is enabled;
- selected-process runqueue wait growth when `--pid` is set;
- selected-interface drops or errors;
- cumulative counter resets during the capture;
- network receive processing concentrated on a busy CPU.

When eBPF per-flow retransmission data is available, TCP retransmission findings
include the top IPv4 and IPv6 flow tuples as supporting evidence. If the serialized flow
list was capped by `--max-ebpf-flows`, the finding also reports the truncation.
If an eBPF feature was disabled or unavailable, the finding reports that
visibility gap with the recorded reason when one is available.

When `--tcp-info` is enabled, TCP RTT findings report the highest observed RTT
from `ss -tin`, the socket endpoint tuple, and cwnd/retransmission metadata
when present. This is a conservative signal; it does not prove path congestion
by itself.

Each finding includes:

- severity;
- confidence;
- factual evidence;
- next verification step.

`netdiag compare` groups findings into incident-only, shared and baseline-only
sets, reports collector visibility differences, and prints key counter delta
changes such as TCP retransmits and qdisc drops. TCP retransmit deltas include
outbound segment denominators and percentages so raw retransmit counts are not
misread without traffic volume, and TCP socket queue deltas show the final
aggregate queue sizes, non-empty socket counts, and top bounded socket queue
tuples when available. Captures recorded with `--pid` also include
selected-process scheduler deltas. Captures recorded with `--tcp-info` include
the highest observed TCP RTT when either side has TCP info socket data. When
both captures include eBPF retransmit flow data, the comparison also shows the
top IPv4 and IPv6 flow tuples and whether a flow list was truncated by
`--max-ebpf-flows`. If an eBPF feature reports sample-level errors in either
capture, compare includes an `eBPF feature errors` row.

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

TCP info example:

```text
Finding 1: TCP RTT was elevated during the capture
Confidence: possible
Severity: warning
Evidence: highest observed TCP RTT was 123.4 ms
Evidence: Top TCP RTT socket: tcp4 10.0.0.3:50001 -> 10.0.0.4:443 state ESTAB had 123.4 ms RTT
Evidence: congestion window was 10 segments
Next step: Check packet loss, congestion window, retransmissions, peer health, and whether the path is congested.
```

When eBPF visibility is missing, evidence uses the feature-level status from
the capture:

```text
Evidence: eBPF tcp_retransmit_events unavailable: permission denied
Evidence: eBPF tcp_retransmit_ipv4_flows disabled
Evidence: eBPF tcp_retransmit_ipv6_flows disabled
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
- highest TCP RTT: 12.3 ms -> 123.4 ms
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

The eBPF integration tests load the real `tcp_retransmit_skb` program, create
isolated network namespaces, apply 100% packet loss to each namespace's loopback
device, and verify that the BPF event count increases with matching IPv4 and
IPv6 loopback flow entries. They do not modify the host network namespace.

Requirements:

- Linux
- root privileges
- `unshare`
- `ip` and `tc` from iproute2

Run:

```sh
make test-integration
```

Equivalent direct command:

```sh
sudo env NETDIAG_ROOT_TESTS=1 /usr/local/go/bin/go test -count=1 -v ./internal/ebpfcollector -run '^TestTCPRetransmit.*Integration$'
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

Run the TCP receive-queue experiment with:

```sh
make experiment-rx-queue
```

It records a loopback TCP connection where the server accepts but does not read.
See [docs/experiments/tcp-rx-queue.md](docs/experiments/tcp-rx-queue.md) for
expected socket queue evidence and tuning guidance.

Run the TCP RTT delay experiment with:

```sh
make experiment-rtt-delay
```

It records baseline and delayed veth captures with `--tcp-info` enabled and
validates the elevated TCP RTT finding. See
[docs/experiments/tcp-rtt-delay.md](docs/experiments/tcp-rtt-delay.md) for
expected RTT evidence and visibility limits.

Run the workload-level TCP connect-latency experiment with:

```sh
make experiment-connect-latency
```

It runs `netdiag-workload client --new-connection` against a temporary
namespace workload and validates that `tc netem delay` increases connect
latency. See
[docs/experiments/connect-latency.md](docs/experiments/connect-latency.md) for
expected output and visibility limits.

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

The [Phase 2 status note](docs/phase2-status.md) summarizes current per-flow
TCP and scheduler attribution evidence, remaining gaps, operator guidance and
the next engineering direction.

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
