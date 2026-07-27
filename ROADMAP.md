# netdiag roadmap

## Product statement

An evidence-based Linux flight recorder that attributes TCP tail-latency
regressions to application scheduling, socket/TCP behavior, kernel networking,
or NIC queue pressure.

The first supported environment is a recent Linux kernel on bare metal or a
dedicated VM, running high-throughput TCP services. Kubernetes, arbitrary
virtualized paths and multi-host causality are explicitly deferred.

## Diagnostic contract

Every finding must contain:

1. A factual observation and its measured interval.
2. The evidence used to derive it.
3. A confidence level: confirmed, strong correlation, possible, or unknown.
4. Known visibility gaps.
5. A concrete next verification step.

The product must never present correlation as proven causality.

## Current status (July 2026)

Completed:

- `record` and `analyze` CLI skeleton.
- Versioned JSON recording format.
- Host-wide TCP collection from procfs.
- Per-CPU and total softirq collection from procfs.
- Per-CPU scheduler counters and optional CPU pressure collection.
- Selected-interface IRQ count and affinity collection when kernel metadata
  permits association.
- Selected-interface qdisc counter collection through `tc -s qdisc`.
- Interface packet, byte, drop and error collection from sysfs.
- Retransmission, interface-drop, receive-CPU-concentration and qdisc
  drops/overlimits findings.
- Minimal eBPF loader, generated bindings and embedded object.
- Host-wide `tcp_retransmit_skb` tracepoint counter.
- Bounded IPv4 per-flow `tcp_retransmit_skb` counters with root-enabled
  integration coverage.
- Per-sample eBPF retransmit-flow serialization limit with visible flow count
  and truncation metadata.
- Recording-level eBPF feature visibility metadata for enabled, disabled and
  unavailable eBPF signals.
- Graceful optional-collector fallback when BPF, IRQ or qdisc collection is
  unavailable.
- Unit coverage for current parsing and analysis rules.
- Recording-level collector visibility manifest.
- Atomic, sample-bounded recording writes and monotonic elapsed time.
- Fixture coverage for procfs/sysfs parsing and counter resets.
- Root-enabled controlled retransmission integration test.
- Reproducible packet-loss experiment with documented evidence.
- Reproducible CPU-contention experiment validating receive CPU concentration.
- Reproducible qdisc-drop experiment validating qdisc collection and analysis.
- Baseline-versus-incident comparison command.
- Initial CPU, memory and output-size benchmark at 100 ms, 500 ms and 1 s.
- Workload-impact benchmark tooling for controlled local HTTP experiments.
- eBPF-enabled recorder overhead benchmark at 100 ms, 500 ms and 1 s.

Current limitations:

- The eBPF retransmit event count is host-wide. Bounded IPv4 per-flow
  retransmit counters are available, but they are not scoped to the selected
  interface or process and do not include IPv6. Serialized per-flow entries are
  capped by `--max-ebpf-flows` per sample.
- Counter correlation cannot locate latency within the kernel path.
- Procfs TCP counters are network-namespace scoped while the eBPF counter is
  host-wide, so their retransmission deltas need not match.
- Qdisc collection depends on `tc` and netlink access.
- IRQ-to-interface mapping depends on sysfs metadata and driver naming.
- CPU concentration and qdisc findings are conservative correlations, not
  causal proof.
- Per-flow socket attribution is limited to IPv4 retransmit counters; connect
  latency, RTT, congestion state and socket queues are not implemented.
- Queue-level NIC driver counters are explicitly deferred to Phase 4; Phase 1
  uses interface, IRQ, qdisc, softirq and TCP counters only.
- Baseline-versus-incident comparison currently compares finding sets,
  collector visibility and key counter deltas; it does not yet compare tail
  latency percentiles.
- The eBPF-enabled recorder benchmark measured 0.200% median CPU at 500 ms and
  0.100% median CPU at 1 s. The 100 ms interval measured 1.130% median CPU and
  remains experimental.
- The Go workload-impact benchmark measured 0.09% median throughput impact and
  0.064 ms median p99 delta with eBPF disabled on the current controlled local
  HTTP workload.
- The 100 ms procfs/sysfs capture interval measured 0.998–1.299% CPU and does
  not reliably satisfy the less-than-1% target; 500 ms and 1 s did.

## Completed milestone: capture integrity (v0.1)

Complete these tasks before adding another eBPF probe:

1. [x] Add a recording-level collector manifest containing collector name, status,
   failure reason and visibility scope.
2. [x] Add fixture-based tests for `/proc/net/snmp`, `/proc/softirqs` and interface
   sysfs parsing, including malformed and counter-reset cases.
3. [x] Write recordings atomically through a temporary file and rename; enforce a
   configurable maximum sample count or capture size.
4. [x] Add elapsed monotonic time to samples so wall-clock adjustments cannot
   invalidate duration analysis.
5. [x] Create a root-enabled integration test that loads the BPF program, triggers
   a controlled TCP retransmission and verifies that the map count increases.
6. [x] Add a reproducible `tc netem` experiment for packet loss and document the
   expected procfs/eBPF evidence.
7. [x] Benchmark CPU, memory and output-size overhead at several sample intervals.

Exit criterion: a capture explicitly reports its visibility, survives an
interrupted write, detects a controlled retransmission experiment and stays
below 1% CPU overhead at the supported 500 ms and 1 s intervals in the initial
test environment. The 100 ms interval remains experimental.

## Phase 0: discovery and fixtures (weeks 1-3)

Phase 0 is split into lab discovery (Phase 0A) and external validation (Phase
0B). Phase 0A documentation and controlled experiments may proceed without
users, but they do not satisfy interview, real-incident, or design-partner
criteria. See [docs/discovery/README.md](docs/discovery/README.md).

- Interview 15 Linux performance, SRE, storage, proxy or database engineers.
- Collect sanitized artifacts from at least five real latency incidents.
- Write incident narratives: symptom, commands used, cause, time to resolution.
- Select one initial workload and two NIC drivers.
- Define a capture privacy and redaction policy.

Exit criterion: three design partners agree to run captures in staging.

## Phase 1: host flight recorder (weeks 2-6)

Implemented:

- [x] Versioned recording format and bounded local storage.
- [x] Capture TCP, softirq, IRQ affinity, CPU scheduling, qdisc and interface
  data.
- [x] Evidence-backed findings for retransmissions, interface drops/errors,
  receive CPU concentration and qdisc drops/overlimits.
- [x] Capture overhead benchmark for unprivileged procfs/sysfs collection.
- [x] Failure-injection fixtures and controlled packet-loss, CPU-contention and
  qdisc-drop experiments.
- [x] Baseline-versus-incident comparison for finding sets, collector
  visibility and key counter deltas.
- [x] Workload-impact benchmark tooling for controlled local HTTP experiments.
- [x] Workload-impact benchmark result for the eBPF-disabled controlled local
  HTTP benchmark.
- [x] eBPF-enabled overhead benchmark.
- [x] Queue-level NIC driver counters explicitly deferred to Phase 4.

Exit criterion: correctly classify controlled loss, CPU contention and queue
drop experiments with less than 2% workload overhead.

The repository now implements the host-counter slice of this phase and a
minimal eBPF tracepoint counter used to validate the loader and fallback path.
Phase 1 is complete for the current controlled local environment. External
host/kernel validation remains a Phase 0B/design-partner activity rather than a
blocking Phase 1 implementation task.

## Phase 2: per-flow TCP and scheduler attribution (months 2-4)

Implemented:

- [x] Bounded IPv4 per-flow retransmission counters from `tcp_retransmit_skb`.
- [x] Root integration test verifies a controlled retransmission produces both
  a host-wide eBPF event increase and a loopback per-flow entry.
- [x] Per-sample serialization budget for eBPF retransmit flows.
- [x] eBPF feature visibility is recorded and surfaced in TCP retransmission
  findings.

Remaining:

- Expand the CO-RE eBPF collector with feature detection and graceful
  degradation beyond the initial host-wide tracepoint counter.
- Track connect latency, RTT, congestion state and socket queues.
- Measure wakeup-to-run delay for selected service processes.
- Correlate flow events without retaining payloads.
- Add broader capture budgets, sampling and cardinality controls for future
  eBPF event types.

Exit criterion: explain a TCP tail-latency regression in a reproducible test
without requiring an expert to inspect raw traces.

## Phase 3: kernel networking path (months 4-7)

- Attribute time to qdisc, driver handoff, NAPI/softirq and socket delivery.
- Collect IRQ affinity and CPU run-queue pressure.
- Integrate `tc`, `ethtool` and `devlink` data.
- Support queue-level counters for the selected NIC drivers.
- Report instrumentation gaps caused by offloads or unavailable tracepoints.

Exit criterion: distinguish qdisc delay, delayed NAPI service and socket-reader
delay in controlled experiments.

## Phase 4: NIC queue diagnosis (months 7-10)

- Map flows to RX/TX queues when RSS and driver visibility permit.
- Correlate queue counters, IRQ CPUs, NAPI instances and application CPUs.
- Add hardware timestamp support where available.
- Detect queue imbalance and validate suggested RSS/IRQ changes experimentally.

Exit criterion: reproduce and diagnose queue imbalance on two common NIC
families, including a report of what cannot be observed.

## Phase 5: commercial validation (parallel, months 3-12)

- Keep the recorder and local analyzer open source.
- Offer paid incident analysis before building a hosted control plane.
- Charge for fleet history, regression comparison, retention and collaboration.
- Require five recurring paid users before investing in a broad UI.

## Explicit non-goals for year one

- General application performance monitoring
- Packet payload inspection
- Full Kubernetes service maps
- Universal NIC and kernel support
- Automatic tuning without operator approval
- AI-generated diagnoses unsupported by deterministic evidence

## Engineering quality gates

- Tests on every supported kernel line.
- Fault-injection tests for every diagnostic rule.
- Capture overhead reported with each release.
- No payload collection by default.
- Stable recording format with migrations.
- Signed releases and least-privilege capability documentation.
