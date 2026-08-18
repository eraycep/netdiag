# Controlled incident narratives

These are laboratory incidents, not sanitized production incidents. They do
not count toward the roadmap requirement for five real incidents.

## CI-001: TCP packet loss

- Date: 2026-07-07
- Status: completed
- Environment: Linux host, temporary network namespace and veth pair
- Symptom: HTTP traffic traversed a 10% `tc netem` loss profile
- Workload: 100 HTTP requests; all completed successfully
- Capture: 20 seconds at a 1-second interval
- Observation: 153 retransmitted of 1101 outbound TCP segments (13.90%)
- eBPF evidence: 161 `tcp_retransmit_skb` events
- Finding: elevated retransmissions, strong correlation
- Visibility gap: procfs was scoped to the host network namespace while eBPF
  was host-wide; exact counts were therefore not expected to match
- Verification: removing the temporary namespace removed the impairment
- Reproduction: [TCP loss experiment](../experiments/tcp-loss.md)

## CI-002: proxy CPU contention

- Status: partially validated with synthetic local workload
- Impairment: concentrate receive processing, client work, or selected process
  execution on a busy CPU
- Expected symptom: reduced throughput or increased tail latency without
  requiring retransmission evidence
- Evidence available: per-CPU softirq, CPU busy time, optional selected-process
  scheduler delay, workload latency
- Remaining gap: validation with a real proxy workload and request-level
  attribution

## CI-003: backend socket-reader stall

- Status: partially validated with loopback socket-reader experiment
- Impairment: pause backend reads for controlled intervals
- Expected symptom: growing socket queues and proxy request latency
- Evidence available: aggregate socket queues and bounded top socket queue
  tuples
- Remaining gap: process ownership, wakeup-to-run delay, and exact request
  attribution

## CI-004: shallow qdisc queue

- Status: completed in controlled qdisc-drop experiment
- Impairment: rate limit traffic with a deliberately shallow egress queue
- Expected symptom: qdisc backlog/drops, retransmissions, and tail latency
- Evidence available: `tc -s qdisc` counters in the recording, retransmission
  counters, and baseline-versus-incident comparison

## Narrative template

For every new controlled or real incident, record:

1. Environment and workload.
2. User-visible symptom and measured interval.
3. Commands and reasoning used during diagnosis.
4. Evidence that confirmed or rejected each hypothesis.
5. Root cause and corrective action, if known.
6. Time to first useful clue and time to resolution.
7. Visibility gaps and the next verification step.
