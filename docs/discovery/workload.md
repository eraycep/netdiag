# Initial workload: NGINX reverse proxy

Status: selected for lab validation; not yet validated by external users.

## Why this workload

The initial workload is an NGINX reverse proxy forwarding HTTP requests to a
controlled backend over TCP. It exercises the boundaries netdiag intends to
distinguish:

- application worker scheduling and socket-reader stalls;
- connection establishment, retransmission, RTT, and socket queues;
- qdisc and kernel networking pressure;
- softirq, IRQ, RSS/RPS, and NIC queue behavior.

A database or storage service would add locking, caching, and disk latency that
could obscure early networking experiments. A proxy keeps the service logic
small while still producing realistic fan-in, fan-out, connection reuse, and
tail-latency behavior.

References:

- [NGINX core worker and connection directives](https://nginx.org/en/docs/ngx_core_module.html)
- [Linux networking scaling: RSS, RPS, RFS, and XPS](https://docs.kernel.org/networking/scaling.html)

## Topology

```text
load generator -> NGINX proxy -> controlled backend
                       |
                    netdiag
```

Start with all components on one dedicated Linux host using separate network
namespaces. Repeat later with the load generator on a second host so physical
NIC queues, IRQ affinity, and driver counters are exercised.

## Traffic matrix

Every experiment must first capture an unimpaired baseline with the same
traffic parameters.

| Dimension | Initial values |
| --- | --- |
| Protocol | HTTP/1.1 over TCP |
| Connection behavior | keepalive; opt-in one request per connection for connect-latency measurement |
| Response size | 1 KiB; 64 KiB; 1 MiB |
| Concurrency | 1; 32; 256; saturation search |
| Request rate | steady; burst; step increase |
| Backend service time | immediate; fixed 10 ms; injected stalls |
| Capture interval | 100 ms; 1 s |

Record request throughput and p50, p95, p99, and p99.9 latency outside
netdiag. Use one-request-per-connection client mode when the diagnostic target
is TCP connect latency. Netdiag should explain a regression; it should not
become the source of application latency measurements.

## Initial failure experiments

1. Packet loss: host-side `tc netem` loss, already implemented.
2. CPU contention: pin proxy workers and a CPU burner to the same CPU.
3. Socket-reader stall: periodically stop or delay the backend reader.
4. Qdisc pressure: apply a rate limit and a deliberately shallow queue.
5. Queue imbalance: constrain RSS/IRQ processing when physical hardware is
   available.

For each experiment, preserve the workload configuration, impairment command,
netdiag capture, latency output, host metadata, and cleanup procedure.

## Success criteria

- Baseline results are stable across at least five repetitions.
- The impairment causes a repeatable tail-latency regression.
- Netdiag reports factual evidence and its visibility limitations.
- Removing the impairment returns both workload and counters to baseline.
- Capture overhead remains within the milestone budget.
