# Phase 2 status: per-flow TCP and scheduler attribution

Status: implementation checkpoint as of August 18, 2026.

Phase 2 is now useful for controlled local TCP latency experiments, but it is
not complete per-flow causality. The current implementation preserves bounded
evidence and reports visibility gaps instead of claiming exact root cause.

## Implemented evidence

- Host-wide eBPF `tcp_retransmit_skb` event counts.
- Bounded IPv4 eBPF retransmit flow counters.
- Recording-level eBPF feature visibility for enabled, disabled and unavailable
  signals.
- Per-sample eBPF feature errors when per-flow map reads degrade while
  host-wide retransmit counting remains available.
- Per-sample and recording-wide eBPF flow serialization budgets:
  `--max-ebpf-flows` and `--max-ebpf-flow-samples`.
- Aggregate TCP socket queue counters from `/proc/net/tcp` and
  `/proc/net/tcp6`.
- Bounded top TCP socket queue tuples from `/proc/net/tcp` and
  `/proc/net/tcp6`, controlled by `--max-tcp-socket-queues`.
- Opt-in TCP RTT and congestion details from `ss -tin`, controlled by
  `--tcp-info` and bounded by `--max-tcp-info-sockets`.
- Conservative receive-queue and transmit-queue findings using peak queue
  samples during the capture.
- Conservative elevated TCP RTT finding when `--tcp-info` is enabled.
- Workload-level TCP connect latency measurement in `netdiag-workload client`,
  including `--new-connection` mode for one TCP connection per request.
- Optional selected-process scheduler counters from `/proc/<pid>/schedstat`
  with conservative runqueue-wait analysis.
- Baseline-versus-incident comparison for retransmits, socket queues, top
  socket queue tuples, highest TCP RTT, eBPF retransmit flows, eBPF feature
  errors and selected process scheduler counters.
- Controlled experiments for packet loss, receive CPU concentration, qdisc
  drops, TCP receive queues, TCP RTT delay, workload-level TCP connect latency
  and selected-process scheduler delay.

## Remaining gaps

- Connect latency is measured by the synthetic workload client, but it is not
  collected by `netdiag record` and is not attributed to kernel-path stages.
- TCP RTT has a conservative threshold-based analysis rule behind `--tcp-info`.
- Congestion metadata from `ss -tin` is recorded as supporting evidence, but
  deeper congestion attribution is not implemented.
- TCP socket queue tuples do not include process ownership.
- Socket tuples and eBPF flow tuples are not tied to individual application
  requests.
- eBPF retransmit flow tuples are IPv4-only.
- Kernel-path timing is not implemented; qdisc, driver handoff, NAPI/softirq
  and socket delivery timing remain Phase 3 work.
- Procfs TCP socket and counter data is network-namespace scoped, while the
  current eBPF retransmit counter is host-wide.

## Operator guidance

- Use `--pid <pid>` when you need selected-process scheduler runtime,
  runqueue-wait and timeslice counters.
- Use `--max-tcp-socket-queues=0` when local/remote IP:port socket queue tuples
  are too sensitive. Aggregate socket queue counters are still collected.
- Use `--max-ebpf-flows` to cap per-sample eBPF retransmit flow entries.
- Use `--max-ebpf-flow-samples` to cap how many samples serialize eBPF flow
  details during a recording.
- Use `--tcp-info` when you need TCP RTT, cwnd, byte and retransmission metadata
  from `ss -tin`. The analyzer can report elevated RTT and compare can show
  highest observed TCP RTT across baseline and incident captures.
- Use `--max-tcp-info-sockets=0` when local/remote IP:port TCP info tuples are
  too sensitive.
- Interpret TCP socket queue tuples as network-namespace scoped evidence. They
  may include sockets unrelated to the experiment or selected process.
- Treat all findings as measured correlations unless a controlled experiment
  or external evidence establishes causality.

## Suggested next engineering direction

The next deeper TCP step should be recorder-level connect-latency collection if
connection establishment is the next target, or deeper congestion attribution
if RTT classification needs more precision. Do not start both at once. Each
needs its own analysis rules, experiments and privacy review.
