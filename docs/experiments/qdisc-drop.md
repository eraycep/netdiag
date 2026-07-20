# Reproducible qdisc-drop experiment

This experiment validates netdiag's `tc_qdisc` collection path and the
qdisc-drop analyzer finding. The raw evidence is stored under each sample's
`qdisc.qdiscs[]` field, and analysis should report qdisc drops or overlimits
when the impaired qdisc counters increase.

The experiment creates a temporary network namespace and veth pair. Unlike the
packet-loss experiment, the HTTP server runs in the host namespace and the
client runs inside the temporary namespace. This makes the large HTTP response
leave through the host side of the veth pair, where the host egress qdisc is
visible to:

```sh
tc -s qdisc show dev <host-veth>
```

## Requirements

- Linux with network namespace, veth and `sch_netem` support
- Root privileges
- `ip` and `tc` from iproute2
- Python 3
- `timeout` from GNU coreutils
- A built `bin/netdiag`

Run the default experiment with:

```sh
make experiment-qdisc-drop
```

The output defaults to:

```text
qdisc-drop-baseline.json
qdisc-drop-baseline.txt
qdisc-drop-impaired.json
qdisc-drop-impaired.txt
```

## Parameters

Override defaults with environment variables:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  DURATION=30s \
  CLIENT_DURATION=28 \
  CLIENT_TIMEOUT_GRACE=10 \
  CLIENT_REQUEST_TIMEOUT=2 \
  CONCURRENCY=64 \
  PAYLOAD_BYTES=8388608 \
  NETEM_LIMIT=1 \
  NETEM_DELAY=100ms \
  STRICT=1 \
  bash experiments/qdisc-drop.sh "$PWD"
```

Important parameters:

- `NETEM_LIMIT`: packet limit for the impaired netem qdisc.
- `NETEM_DELAY`: delay applied by the impaired netem qdisc.
- `CONCURRENCY`: number of HTTP client workers inside the namespace.
- `PAYLOAD_BYTES`: size of the served file.
- `CLIENT_REQUEST_TIMEOUT`: per-request timeout used by the Python client.
- `CLIENT_TIMEOUT_GRACE`: extra seconds allowed after `CLIENT_DURATION` before
  forcefully stopping the client.
- `STRICT=1`: fail the script if baseline qdisc counters are not quiet or the
  impaired qdisc counters do not increase.

By default, expectation mismatches are warnings. This keeps the experiment
usable across kernels and development hosts with different scheduling behavior.

## Expected evidence

The baseline capture should normally have zero qdisc drops and overlimits.

The impaired capture should normally show `drops > 0` or `overlimits > 0` in
the final sample's qdisc counters. Example raw JSON shape:

```json
"qdisc": {
  "qdiscs": [
    {
      "interface": "ndh12345",
      "kind": "netem",
      "drops": 10,
      "overlimits": 0,
      "backlog_packets": 1
    }
  ]
}
```

The analyzer should report:

```text
The selected interface qdisc recorded drops or overlimits
```

If qdisc drops cause TCP loss, the analyzer may also report elevated TCP
retransmissions. That downstream retransmission finding is useful, but the
qdisc finding is the direct validation target for this experiment.

## Validated run

On July 18, 2026, the default experiment was run on the development host with:

```text
DURATION=20s
CLIENT_DURATION=18
CLIENT_REQUEST_TIMEOUT=2
CLIENT_TIMEOUT_GRACE=10
CONCURRENCY=32
PAYLOAD_BYTES=4194304
NETEM_LIMIT=1
NETEM_DELAY=100ms
```

The baseline capture stayed quiet at the qdisc layer:

```text
HTTP requests: 5227 succeeded, 0 failed
Finding 1: No counter-level network anomaly was detected
Confidence: unknown
Severity: info
Evidence: analyzed 20 samples across 19.0 seconds
Next step: Use per-flow and scheduler instrumentation before excluding kernel or application latency.
baseline qdisc totals: drops=0, overlimits=0, backlog_packets=0
```

The impaired run installed this netem qdisc on the temporary host veth:

```text
qdisc netem 8002: root refcnt 17 limit 1 delay 100ms
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
```

During traffic generation, the client hit the experiment's hard timeout:

```text
warning: impaired client exited with status 124; continuing to analyze recorder output
```

This is acceptable for this experiment. The recorder still completed and the
capture contained the qdisc evidence needed to validate collection and
analysis:

```text
Finding 1: TCP retransmissions were elevated during the capture
Confidence: strong correlation
Severity: warning
Evidence: 694 retransmitted of 1829 outbound TCP segments (37.94%)
Evidence: eBPF observed 971 tcp_retransmit_skb tracepoint events
Next step: Check packet loss, ECN/congestion signals, peer health, and interface error counters.

Finding 2: The selected interface qdisc recorded drops or overlimits
Confidence: confirmed
Severity: warning
Evidence: qdisc netem on ndh56104 recorded 882 drops and 0 overlimits
Evidence: qdisc backlog ended at 1 packets
Next step: Inspect qdisc configuration, traffic shaping, queue limits, and whether retransmissions align with qdisc drops.

impaired qdisc totals: drops=882, overlimits=0, backlog_packets=1
```

The same captures were compared with:

```sh
./bin/netdiag compare qdisc-drop-baseline.json qdisc-drop-impaired.json
```

The comparison output made the baseline-versus-incident contrast explicit:

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

The ratio-aware TCP line is intentional. The baseline had a larger raw
retransmit delta, but it occurred across much higher outbound traffic volume and
did not cross the analyzer's retransmission-ratio threshold.

The receive-CPU lines are context rather than a finding in this experiment: the
impaired capture concentrated NET_RX softirq work on CPU2, but that CPU was only
8.0% busy, so the queue impairment remains the primary signal.

This run validates that `tc_qdisc` captures qdisc drop evidence under
controlled queue impairment and that the analyzer reports the direct qdisc
finding alongside the downstream TCP retransmission symptom.

## Cleanup and safety

The script cleans up its namespace, veth pair, qdisc, HTTP server, recorder and
temporary payload on normal exit or interruption. It never applies qdisc changes
to an existing host interface.

## Limitations

- veth behavior is not identical to a physical NIC.
- qdisc drop counts depend on timing, payload size, concurrency and host load.
- Some runs may show backlog or overlimits instead of drops.
- This validates qdisc counter collection and qdisc-drop analysis; it does not
  prove a user-facing latency cause.

If impaired counters stay at zero, increase `CONCURRENCY`, `PAYLOAD_BYTES` or
`NETEM_DELAY`, or reduce `NETEM_LIMIT`.
