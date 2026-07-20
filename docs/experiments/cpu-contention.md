# Reproducible CPU-contention experiment

This experiment validates netdiag's receive-path CPU concentration finding. It
creates a temporary network namespace and veth pair, serves a fixed payload from
inside the namespace, generates host-side HTTP traffic, and compares two
captures:

1. baseline traffic without an artificial CPU burner;
2. impaired traffic with the HTTP client and a CPU burner pinned to the same
   CPU selected for receive processing.

The script attempts to steer host-side veth queue processing to `TARGET_CPU`
by writing the corresponding mask to RPS and XPS files such as:

```text
/sys/class/net/<host-veth>/queues/rx-0/rps_cpus
/sys/class/net/<host-veth>/queues/tx-0/xps_cpus
```

This makes the experiment more deterministic, but scheduler behavior and veth
processing are still kernel- and host-load-dependent.

## Requirements

- Linux with network namespace and veth support
- Root privileges
- `ip` from iproute2
- `taskset` from util-linux
- Python 3
- A built `bin/netdiag`
- At least two CPUs

Run the default experiment with:

```sh
make experiment-cpu-contention
```

The output defaults to:

```text
cpu-contention-baseline.json
cpu-contention-baseline.txt
cpu-contention-impaired.json
cpu-contention-impaired.txt
```

## Parameters

Override defaults with environment variables:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  TARGET_CPU=2 \
  BASELINE_CLIENT_CPU=0 \
  IMPAIRED_CLIENT_CPU=2 \
  DURATION=30s \
  CLIENT_DURATION=28 \
  CONCURRENCY=32 \
  PAYLOAD_BYTES=2097152 \
  STRICT=1 \
  bash experiments/cpu-contention.sh "$PWD"
```

Important parameters:

- `TARGET_CPU`: CPU that should receive RPS-steered network processing and the
  CPU burner. The namespace HTTP server is also pinned here.
- `BASELINE_CLIENT_CPU`: CPU used by the HTTP client during the baseline run.
  It should differ from `TARGET_CPU`.
- `IMPAIRED_CLIENT_CPU`: CPU used by the HTTP client during the impaired run.
  It defaults to `TARGET_CPU` to make the concentration condition easier to
  reproduce.
- `DURATION`: netdiag recording duration.
- `CLIENT_DURATION`: HTTP traffic duration in seconds.
- `CONCURRENCY`: number of HTTP client workers.
- `PAYLOAD_BYTES`: size of the served file.
- `STRICT=1`: fail the script if the baseline reports the finding or the
  impaired run does not.

By default, the script warns instead of failing when expectations are not met.
This is intentional: CPU scheduling experiments are more sensitive to host
noise than the packet-loss experiment.

## Expected evidence

The baseline analysis should normally avoid this finding:

```text
Network receive processing was concentrated on a busy CPU
```

The impaired analysis should normally report it with evidence similar to:

```text
Evidence: CPU2 handled 90.0% of NET_RX softirq work
Evidence: CPU2 was 80.0% busy during the capture
Evidence: IRQ counts also increased on CPU2 by ...
```

On veth devices there may be no hardware IRQ evidence. The finding only
requires per-CPU `NET_RX` softirq deltas and per-CPU CPU busy deltas. IRQ
evidence is appended when available.

## Validated run

On July 18, 2026, the default experiment was run on the development host with:

```text
TARGET_CPU=1
BASELINE_CLIENT_CPU=0
IMPAIRED_CLIENT_CPU=1
DURATION=20s
CLIENT_DURATION=18
CONCURRENCY=16
PAYLOAD_BYTES=1048576
```

The script successfully steered the temporary veth queue processing toward CPU1:

```text
steered ndh27528 queue processing toward CPU 1 with mask 2
```

Baseline traffic completed without triggering the receive-path CPU finding:

```text
HTTP requests: 12012 succeeded, 0 failed
Finding 1: No counter-level network anomaly was detected
Confidence: unknown
Severity: info
Evidence: analyzed 20 samples across 19.0 seconds
Next step: Use per-flow and scheduler instrumentation before excluding kernel or application latency.
```

The impaired run pinned both the HTTP client and CPU burner to CPU1. The
analyzer reported the intended finding:

```text
HTTP requests: 7900 succeeded, 0 failed
Finding 1: Network receive processing was concentrated on a busy CPU
Confidence: strong correlation
Severity: warning
Evidence: CPU1 handled 83.1% of NET_RX softirq work
Evidence: CPU1 was 100.0% busy during the capture
Next step: Check RSS/IRQ affinity and whether application workers or CPU-intensive tasks share the same CPU.
```

This run crossed both conservative analysis thresholds:

- at least 80% of `NET_RX` softirq work on one CPU;
- at least 70% busy time on that same CPU.

No IRQ evidence appeared in this run, which is expected for the veth topology.
The finding is valid with softirq and CPU evidence alone; IRQ evidence is
reported only when the collector can associate selected-interface IRQs with the
same CPU.

## Cleanup and safety

The script cleans up its namespace, veth pair, temporary HTTP payload, recorder,
server and CPU burner on normal exit or interruption. It does not change
existing host interfaces. If RPS steering is applied to the temporary veth, the
old value is restored during cleanup.

## Limitations

- veth behavior is not identical to a physical NIC.
- RPS steering may be unavailable or ineffective on some kernels.
- Background host load can make the baseline look busy.
- Low traffic volume can keep `NET_RX` softirq deltas below the analyzer's
  threshold.
- This validates a conservative correlation, not root cause.

If the impaired run does not trigger the finding, increase `CONCURRENCY`,
`CLIENT_DURATION` or `PAYLOAD_BYTES`, keep `IMPAIRED_CLIENT_CPU` equal to
`TARGET_CPU`, or choose a quieter `TARGET_CPU`.
