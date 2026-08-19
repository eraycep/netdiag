# Reproducible workload-level TCP connect latency experiment

This experiment validates `netdiag-workload client --new-connection` connect
latency measurement. It uses a temporary network namespace and veth pair. The
HTTP workload server runs in the temporary namespace, and the workload client
runs in the host namespace with one TCP connection per request.

The impaired run applies `tc netem delay` to the host side of the veth pair.
Because each request creates a new TCP connection, the TCP handshake crosses the
delayed path and the workload client's connect latency percentiles should
increase.

This is a workload-level measurement, not `netdiag record` evidence.

## Requirements

- Linux with network namespace and `sch_netem` support
- Root privileges
- `ip` and `tc` from iproute2
- Python 3
- A built `bin/netdiag-workload`

Run the default experiment with:

```sh
make experiment-connect-latency
```

The output defaults to:

- `connect-latency-baseline.txt`
- `connect-latency-impaired.txt`

Parameters can be overridden:

```sh
sudo env \
  WORKLOAD_BIN="$PWD/bin/netdiag-workload" \
  NETEM_DELAY=150ms \
  CLIENT_DURATION=15 \
  CONCURRENCY=8 \
  bash experiments/connect-latency.sh "$PWD"
```

Set `STRICT=1` to fail the script if impaired connect p99 does not increase
above baseline connect p99.

## Expected evidence

The baseline output should include low connect latency:

```text
Connect latency milliseconds: p50=... p95=... p99=... samples=...
```

The impaired output should show a higher connect p99. The script prints:

```text
baseline connect p99: ... ms
impaired connect p99: ... ms
```

## Visibility limits

The measurement is client-side workload timing from Go's `net/http/httptrace`.
It measures elapsed time between `ConnectStart` and successful `ConnectDone`.
It does not attribute time to DNS, SYN send, SYN-ACK receive, qdisc delay,
driver handoff, peer accept backlog, or application scheduling.

The experiment disables HTTP keepalives with `--new-connection` so each request
creates a TCP connection. This intentionally lowers throughput compared with
the default keepalive workload and should not be used for recorder-overhead
claims unless connect latency is the explicit diagnostic target.

Exact latency values are non-deterministic. If the impaired p99 does not rise
on a busy host, increase `NETEM_DELAY`, increase `CLIENT_DURATION`, or lower
background host activity.
