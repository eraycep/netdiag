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

- Status: planned
- Impairment: pin NGINX and a CPU burner to the same CPU
- Expected symptom: increased tail latency without retransmission evidence
- Evidence needed: per-CPU softirq, process scheduling delay, workload latency
- Current blocker: scheduler instrumentation is not implemented

## CI-003: backend socket-reader stall

- Status: planned
- Impairment: pause backend reads for controlled intervals
- Expected symptom: growing socket queues and proxy request latency
- Evidence needed: per-socket queues and wakeup-to-run delay
- Current blocker: per-flow/socket instrumentation is not implemented

## CI-004: shallow qdisc queue

- Status: planned
- Impairment: rate limit traffic with a deliberately shallow egress queue
- Expected symptom: qdisc backlog/drops, retransmissions, and tail latency
- Evidence needed: `tc -s qdisc` counters in the recording
- Current blocker: qdisc collection is not implemented

## Narrative template

For every new controlled or real incident, record:

1. Environment and workload.
2. User-visible symptom and measured interval.
3. Commands and reasoning used during diagnosis.
4. Evidence that confirmed or rejected each hypothesis.
5. Root cause and corrective action, if known.
6. Time to first useful clue and time to resolution.
7. Visibility gaps and the next verification step.
