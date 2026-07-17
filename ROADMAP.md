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
- Host-wide TCP and softirq collection from procfs.
- Interface packet, byte, drop and error collection from sysfs.
- Initial retransmission and interface-drop findings.
- Minimal eBPF loader, generated bindings and embedded object.
- Host-wide `tcp_retransmit_skb` tracepoint counter.
- Graceful procfs/sysfs fallback when BPF cannot be loaded.
- Unit coverage for the initial analysis rule.
- Recording-level collector visibility manifest.
- Atomic, sample-bounded recording writes and monotonic elapsed time.
- Fixture coverage for procfs/sysfs parsing and counter resets.
- Root-enabled controlled retransmission integration test.
- Reproducible packet-loss experiment with documented evidence.
- Initial CPU, memory and output-size benchmark at 100 ms, 500 ms and 1 s.

Current limitations:

- The eBPF count is host-wide, not scoped to the selected interface, process,
  socket or flow.
- Counter correlation cannot locate latency within the kernel path.
- Procfs TCP counters are network-namespace scoped while the eBPF counter is
  host-wide, so their retransmission deltas need not match.
- Qdisc, IRQ affinity, scheduler and per-socket visibility are not collected.
- The eBPF-enabled overhead path and end-to-end workload impact still need
  benchmarks.
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

- Versioned recording format and bounded local storage.
- Capture TCP, softirq, IRQ affinity, CPU scheduling, qdisc and interface data.
- Baseline-versus-incident comparison.
- Evidence-backed findings for retransmissions, drops and softirq saturation.
- Capture overhead benchmarks and failure-injection fixtures.

Exit criterion: correctly classify controlled loss, CPU contention and queue
drop experiments with less than 2% workload overhead.

The repository scaffold implements the first thin slice of this phase and a
minimal eBPF tracepoint counter used to validate the loader and fallback path.

## Phase 2: per-flow TCP and scheduler attribution (months 2-4)

- Expand the CO-RE eBPF collector with feature detection and graceful
  degradation beyond the initial host-wide tracepoint counter.
- Track connect latency, retransmits, RTT, congestion state and socket queues.
- Measure wakeup-to-run delay for selected service processes.
- Correlate flow events without retaining payloads.
- Add capture budgets, sampling and cardinality controls.

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
