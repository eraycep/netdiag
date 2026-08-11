# Reproducible selected-process scheduler-delay experiment

This experiment validates netdiag's selected-process runqueue wait finding. It
runs a local HTTP workload server, records that server with `netdiag record
--pid`, and compares two captures:

1. baseline traffic while the selected server process can run on all CPUs
   allowed by the current shell affinity mask;
2. impaired traffic after pinning the selected server process, client and a CPU
   burner to the same target CPU.

The experiment uses `/proc/<pid>/schedstat`. It does not need root and does not
change host networking state.

Run it with:

```sh
make experiment-process-sched-delay
```

The output defaults to:

```text
process-sched-delay-baseline.json
process-sched-delay-baseline.txt
process-sched-delay-impaired.json
process-sched-delay-impaired.txt
```

## Parameters

Override defaults with environment variables:

```sh
NETDIAG_BIN="$PWD/bin/netdiag" \
WORKLOAD_BIN="$PWD/bin/netdiag-workload" \
TARGET_CPU=2 \
BASELINE_CLIENT_CPU=0 \
IMPAIRED_CLIENT_CPU=2 \
DURATION=30s \
CLIENT_DURATION=28s \
BASELINE_CONCURRENCY=4 \
IMPAIRED_CONCURRENCY=64 \
PAYLOAD_BYTES=1048576 \
STRICT=1 \
bash experiments/process-sched-delay.sh "$PWD"
```

Important parameters:

- `TARGET_CPU`: CPU used by the selected HTTP server process during the
  impaired run. The impaired CPU burner also runs here.
- `BASELINE_CLIENT_CPU`: CPU used by the HTTP client during baseline traffic.
  It should differ from `TARGET_CPU`.
- `IMPAIRED_CLIENT_CPU`: CPU used by the HTTP client during impaired traffic.
  It defaults to `TARGET_CPU`.
- `DURATION`: netdiag recording duration.
- `CLIENT_DURATION`: HTTP traffic duration.
- `BASELINE_CONCURRENCY`: number of HTTP client workers during the baseline
  run. Keep this low enough that the selected process does not accumulate
  significant runqueue wait without the CPU burner.
- `IMPAIRED_CONCURRENCY`: number of HTTP client workers during the impaired
  run. It defaults to `CONCURRENCY`, which defaults to `32`.
- `CONCURRENCY`: compatibility default used for `IMPAIRED_CONCURRENCY` when
  that variable is not set.
- `PAYLOAD_BYTES`: response payload size served by the selected process.
- `STRICT=1`: fail the script if the baseline reports the finding or the
  impaired run does not.

By default, the script warns instead of failing when expectations are not met.
Scheduler experiments are sensitive to host noise and CPU topology.

## Expected evidence

The baseline analysis should normally avoid this finding:

```text
Selected process accumulated runqueue wait time
```

The impaired analysis should normally report it with evidence similar to:

```text
Finding 1: Selected process accumulated runqueue wait time
Confidence: possible
Severity: warning
Evidence: process 12345 runqueue wait increased by 5000.0 ms
Evidence: process 12345 ran for 9000.0 ms across 1200 timeslices
Next step: Check CPU saturation, scheduler pressure, and whether this process shares CPUs with softirq or IRQ handling.
```

This finding means the selected process spent more time runnable but not
executing during the capture. It does not prove the scheduler delay caused a
network latency regression by itself; it identifies a local scheduling signal
that should be checked against request latency, CPU saturation, softirq
placement and IRQ affinity.

## Cleanup and safety

The script cleans up the recorder, workload server and CPU burner on normal
exit or interruption. It binds the temporary server to `127.0.0.1` and chooses
a port derived from the script process ID.

## Limitations

- The workload runs over loopback, not a physical NIC.
- The selected process is a synthetic HTTP server, not a production service.
- Background host load can make the baseline show runqueue wait.
- Some kernels or container environments may restrict useful schedstat data.
- This validates a conservative correlation, not root cause.

If the baseline triggers the finding, reduce `BASELINE_CONCURRENCY` or choose
a quieter target CPU. If the impaired run does not trigger the finding,
increase `IMPAIRED_CONCURRENCY`, `CLIENT_DURATION` or `PAYLOAD_BYTES`, keep
`IMPAIRED_CLIENT_CPU` equal to `TARGET_CPU`, or choose a quieter CPU.
