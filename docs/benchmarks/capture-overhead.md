# Capture overhead benchmark

This benchmark measures the recorder process rather than workload impact. It
reports process CPU time as a percentage of elapsed wall time, peak resident
memory, recording size, and bytes per sample.

## Method

The default matrix runs three repetitions at 100 ms, 500 ms, and 1 s sample
intervals. Each repetition lasts 10 seconds. eBPF is disabled by default so the
unprivileged procfs recorder has a stable baseline. Set `INTERFACE` to include
the interface sysfs collector in the measurement.

```sh
INTERFACE=eth0 make benchmark
```

Raw per-run results are written to
`benchmarks/results/capture-overhead.tsv`. Results include the hostname,
kernel, duration, repetitions, and eBPF mode. The directory is intentionally
ignored because measurements are environment-specific.

Run a longer matrix or change intervals with:

```sh
DURATION_SECONDS=30 REPETITIONS=5 \
INTERVALS="50ms 100ms 500ms 1s" \
make benchmark
```

Measure the eBPF-enabled path separately with root privileges:

```sh
make benchmark-ebpf
```

Do not combine privileged and unprivileged runs in one result table. When
`EBPF=true`, the benchmark validates each recording manifest and fails if the
`ebpf_tcp_retransmit` collector is unavailable or missing.

To customize the privileged run:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  EBPF=true \
  DURATION_SECONDS=30 \
  REPETITIONS=5 \
  INTERVALS="100ms 500ms 1s" \
  bash benchmarks/capture-overhead.sh \
  benchmarks/results/capture-overhead-ebpf.tsv
```

## Interpretation

- The capture-integrity target is less than 1% recorder CPU in the initial test
  environment.
- Peak RSS is the maximum for a run, not incremental memory attributable to
  each sample.
- JSON is retained in memory until capture completion, so longer runs require
  separate memory-growth measurements; a 10-second run is not a storage-bound
  stress test.
- Output size should scale approximately with sample count. Structural JSON
  metadata makes short recordings have higher bytes per sample.
- A process-only result does not satisfy Phase 1's workload-overhead target.
  That requires A/B workload latency and throughput measurements.

## Initial results

Measured 2026-07-07 on the current development host:

- CPU: AMD Ryzen 7 5700U, 8 cores/16 threads
- Memory: 14 GiB
- Kernel: Ubuntu `6.8.0-134-generic`, x86-64
- Interface: active `wlp3s0`
- Collectors: procfs TCP/softirq and interface sysfs; eBPF disabled
- Run length: 10 seconds, three repetitions per interval

| Interval | Runs | Median CPU | CPU range | Peak RSS | Mean samples | Mean output | Bytes/sample |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 ms | 3 | 1.000% | 0.998–1.299% | 8576 KiB | 100 | 56634 B | 566.4 B |
| 500 ms | 3 | 0.100% | 0.100–0.100% | 6016 KiB | 20 | 12093 B | 604.6 B |
| 1 s | 3 | 0.100% | 0.100–0.100% | 5376 KiB | 10 | 6526 B | 652.6 B |

The 500 ms and 1 s intervals satisfy the initial less-than-1% recorder CPU
target. The 100 ms interval does not satisfy it reliably and must not be
described as below 1%; it is an experimental high-frequency mode until the
collector is optimized and remeasured.

GNU time reports CPU time with limited resolution in these short runs, so the
0.100% values should be interpreted as low measurements rather than precise
estimates. Longer five-repetition runs are required for release claims.

## eBPF-enabled result

Measured 2026-07-18 on the current development host:

- Hostname: `eray-pc`
- Kernel: Ubuntu `6.8.0-136-generic`
- Collectors: procfs TCP/softirq/CPU plus host-wide
  `ebpf_tcp_retransmit`; no selected interface
- eBPF manifest validation: enabled for every run
- Run length: 30 seconds, five repetitions per interval

| Interval | Runs | Median CPU | CPU range | Peak RSS | Mean samples | Mean output | Bytes/sample |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 ms | 5 | 1.130% | 1.097–1.131% | 15188 KiB | 300 | 2004862 B | 6682.9 B |
| 500 ms | 5 | 0.200% | 0.200–0.233% | 10112 KiB | 60 | 402059 B | 6701.0 B |
| 1 s | 5 | 0.100% | 0.067–0.133% | 8064 KiB | 30 | 201761 B | 6725.4 B |

The 500 ms and 1 s intervals satisfy the less-than-1% recorder CPU target with
the current host-wide eBPF retransmission counter enabled. The 100 ms interval
does not satisfy the target and remains experimental.
