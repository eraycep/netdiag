# Workload impact benchmark

This benchmark measures end-to-end workload throughput with and without the
recorder running. It complements `capture-overhead.sh`, which measures only the
recorder process.

## Method

The benchmark creates an isolated network namespace and veth pair, starts the
`netdiag-workload` Go HTTP server in the namespace, and runs the
`netdiag-workload` Go client from the host. Each measured run performs a warmup
before collecting throughput and latency. For each repetition it records two
runs:

1. `without_recorder`: workload only.
2. `with_recorder`: same workload while `netdiag record` collects from the host
   veth interface.

The order is randomized for each repetition so recorder runs are not always
penalized or helped by fixed first-run effects.

The primary metric is request throughput delta:

```text
impact = 100 * (without_recorder_rps - with_recorder_rps) / without_recorder_rps
```

The benchmark also reports request latency p50, p95, and p99 for each run and
the paired p99 delta.

The Phase 1 target is less than 2% median workload impact in controlled
experiments. Negative impact means the recorder run was faster than the paired
baseline, which can happen with short noisy runs.

## Run

Build the binary and run the benchmark with root privileges:

```sh
make benchmark-workload-impact
```

Raw results are written to:

```text
benchmarks/results/workload-impact.tsv
```

Recorder captures from the measured runs are written under:

```text
benchmarks/results/workload-impact-captures/
```

Tune the matrix with environment variables:

```sh
CLIENT_DURATION=30 \
WARMUP_SECONDS=5 \
REPETITIONS=5 \
CONCURRENCY=32 \
PAYLOAD_BYTES=1048576 \
INTERVAL=1s \
make benchmark-workload-impact
```

Measure the eBPF-enabled path separately:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  EBPF=true \
  CLIENT_DURATION=30 \
  REPETITIONS=5 \
  bash benchmarks/workload-impact.sh \
  benchmarks/results/workload-impact-ebpf.tsv
```

Do not mix eBPF-disabled and eBPF-enabled rows in the same result table.

## Interpretation limits

- This is a local synthetic HTTP workload, not a real production incident.
- The Go HTTP server and client are intentionally simple, so the result is
  useful for regression tracking but not for absolute service-capacity claims.
- Run enough repetitions for release claims. The default five 30-second pairs
  are a stronger development baseline than the original smoke run, but release
  claims should still be repeated on a quiet host.
- Run on a quiet host. Background CPU or network activity can dominate a small
  percentage delta.
- The benchmark reports client-side request latency percentiles. These are not
  kernel-path latency measurements; they are workload-level symptoms.

## Initial smoke result

Measured 2026-07-18 on the current development host:

- Hostname: `eray-pc`
- Kernel: Ubuntu `6.8.0-136-generic`
- Recorder interval: 1 second
- eBPF: disabled
- Workload: isolated veth HTTP server, 1 MiB payload
- Client duration: 18 seconds
- Concurrency: 16
- Repetitions: 3

| Run | Without recorder | With recorder | Impact |
| ---: | ---: | ---: | ---: |
| 1 | 972.61 req/s | 696.78 req/s | 28.36% |
| 2 | 671.61 req/s | 886.61 req/s | -32.01% |
| 3 | 726.67 req/s | 654.78 req/s | 9.89% |

| Summary | Without recorder | With recorder | Impact |
| --- | ---: | ---: | ---: |
| Median | 726.67 req/s | 696.78 req/s | 9.89% |
| Range | 671.61–972.61 req/s | 654.78–886.61 req/s | -32.01–28.36% |

This result used the first benchmark version, before warmup, randomized pair
order, and latency percentile reporting were added. It is not a clean Phase 1
pass/fail measurement. The range crosses
from -32.01% to 28.36%, which means run-to-run workload variance is larger than
the target being measured. Treat this as a benchmark smoke test only.

Before making an overhead claim, rerun with the improved benchmark:

```sh
CLIENT_DURATION=30 REPETITIONS=5 CONCURRENCY=32 make benchmark-workload-impact
```

If the result remains noisy, increase `CLIENT_DURATION` and `REPETITIONS` and
run on a quieter host.

## Improved benchmark result

Measured 2026-07-18 on the current development host after moving the benchmark
workload to the Go `netdiag-workload` binary:

- Hostname: `eray-pc`
- Kernel: Ubuntu `6.8.0-136-generic`
- Recorder interval: 1 second
- eBPF: disabled
- Workload: isolated veth HTTP server, 1 MiB payload
- Client duration: 30 seconds
- Warmup: 5 seconds per measured run
- Concurrency: 32
- Repetitions: 5

| Run | Without recorder | With recorder | Throughput impact | p99 without | p99 with | p99 delta |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 4028.00 req/s | 4057.17 req/s | -0.72% | 20.706 ms | 20.647 ms | -0.059 ms |
| 2 | 4194.20 req/s | 4418.93 req/s | -5.36% | 21.015 ms | 21.702 ms | 0.687 ms |
| 3 | 4900.27 req/s | 4889.07 req/s | 0.23% | 16.816 ms | 16.880 ms | 0.064 ms |
| 4 | 4887.40 req/s | 4882.80 req/s | 0.09% | 16.878 ms | 16.874 ms | -0.004 ms |
| 5 | 4911.13 req/s | 4889.80 req/s | 0.43% | 16.865 ms | 17.010 ms | 0.145 ms |

| Summary | Without recorder | With recorder | Throughput impact | p99 without | p99 with | p99 delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Median | 4887.40 req/s | 4882.80 req/s | 0.09% | 16.878 ms | 17.010 ms | 0.064 ms |
| Range | 4028.00–4911.13 req/s | 4057.17–4889.80 req/s | -5.36–0.43% | 16.816–21.015 ms | 16.874–21.702 ms | -0.059–0.687 ms |

This satisfies the Phase 1 less-than-2% median workload-impact target for the
current controlled local HTTP benchmark with eBPF disabled. The remaining
throughput range still includes negative impact, so treat sub-percent
differences as measurement noise rather than evidence that the recorder improves
throughput. The eBPF-enabled path must be measured separately.
