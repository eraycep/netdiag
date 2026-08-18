# Diagnostic hypotheses

Status: engineering hypotheses, not validated user findings.

Each hypothesis must be tested with a baseline, one controlled impairment, and
a recovery run. A failed hypothesis is a useful result and should be retained.

## H1: packet loss

When TCP packet loss causes tail-latency growth, `RetransSegs` and
`tcp_retransmit_skb` events increase during the affected interval.

- Confounders: unrelated host traffic and different network-namespace scope.
- Falsifier: latency regresses under controlled loss without either signal
  increasing despite confirmed collector visibility.

## H2: interface errors

When a physical interface reports receive or transmit errors, the corresponding
sysfs counters increase and netdiag can confirm the observation without
claiming which layer caused the application latency.

- Confounders: qdisc and driver drops may not appear in generic sysfs fields.
- Falsifier: injected driver-visible errors do not change the captured fields.

## H3: softirq saturation

When network receive processing is delayed by CPU contention, per-interval
softirq work and CPU scheduling pressure correlate with tail latency.

- Current visibility: netdiag captures per-CPU softirq counters, CPU counters,
  optional CPU pressure, and optional selected-process scheduler delay.
- Required future evidence: scheduler timing for more than one selected
  process and deeper kernel-path timing.

## H4: socket-reader stall

When the application or backend stops reading, socket receive/send queues grow
before latency increases, without requiring packet loss.

- Current visibility: aggregate socket queue counters and bounded top socket
  queue tuples are implemented. Process ownership and exact request
  attribution remain gaps.
- Falsifier: controlled reader stalls produce no queue growth at sufficient
  sampling resolution.

## H5: qdisc pressure

When an egress qdisc becomes the bottleneck, qdisc backlog, delay, or drops
increase while generic interface drop counters may remain unchanged.

- Current visibility: selected-interface qdisc counters are collected through
  `tc -s qdisc` when available.
- Falsifier: a controlled shallow queue drops packets without qdisc evidence.

## H6: queue or IRQ imbalance

When flows concentrate on an overloaded receive queue or CPU, queue-level
drops and interrupt/softirq work become imbalanced even if host totals appear
healthy.

- Current visibility gap: queue-level NIC counters are not collected. Selected
  interface IRQ counts and affinity are collected when kernel metadata permits
  association.
- Required environment: a multi-queue physical NIC.

## H7: negative findings require visibility

A clean counter result is meaningful only when the recording manifest confirms
that the relevant collectors were enabled for the entire interval.

- Falsifier: analysis presents absence of evidence as evidence of absence when
  the necessary collector is unavailable.

## H8: low-overhead capture

At supported intervals, netdiag adds less than 1% CPU overhead in the initial
capture-integrity environment and less than 2% workload overhead in Phase 1.

- Required method: repeated A/B runs with confidence intervals, output size,
  resident memory, and CPU time recorded.
