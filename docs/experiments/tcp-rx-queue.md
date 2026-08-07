# Reproducible TCP receive-queue experiment

This experiment validates aggregate TCP socket queue collection and the
conservative receive-queue analyzer finding.

It runs entirely on loopback and does not require root. A local Python server
accepts one TCP connection and intentionally does not read from it for a short
period. A client writes data into that connection while `netdiag record` samples
`/proc/net/tcp` and `/proc/net/tcp6`.

Run it with:

```sh
make experiment-rx-queue
```

The output defaults to:

```text
tcp-rx-queue.json
tcp-rx-queue.txt
```

## Parameters

Override defaults with environment variables:

```sh
NETDIAG_BIN="$PWD/bin/netdiag" \
DURATION=10s \
INTERVAL=500ms \
PAYLOAD_BYTES=16777216 \
SERVER_SLEEP=8 \
bash experiments/tcp-rx-queue.sh "$PWD"
```

Important parameters:

- `PAYLOAD_BYTES`: maximum bytes the client attempts to write.
- `SERVER_SLEEP`: seconds the server keeps the accepted socket open without
  reading.
- `DURATION`: recorder duration.
- `INTERVAL`: recorder sample interval.

## Expected evidence

The analyzer should normally report:

```text
TCP socket receive queues grew during the capture
```

Expected evidence includes:

```text
Evidence: TCP receive queues increased by ... bytes
Evidence: ... sockets ended with non-zero receive queues
```

This finding is intentionally conservative. It shows aggregate receive queue
growth, but it does not identify the process or socket responsible and does not
prove application causality.

If the finding is not reported, increase `PAYLOAD_BYTES` or `SERVER_SLEEP`.

## Validated run

On August 7, 2026, a short validation run completed on the development host
with:

```text
DURATION=5s
SERVER_SLEEP=4
PAYLOAD_BYTES=33554432
```

The client wrote enough data to block behind the server that accepted the
connection but did not read:

```text
client sent 1900544 bytes; send timeouts 16
```

The analyzer reported the receive-queue validation target:

```text
Finding 2: TCP socket receive queues grew during the capture
Confidence: possible
Severity: warning
Evidence: TCP receive queues increased by 127168 bytes
Evidence: 1 sockets ended with non-zero receive queues
Evidence: largest observed receive queue was 127168 bytes
Next step: Check whether the application or peer was slow to read from established sockets.
```

The same run also reported a small TCP retransmission finding on loopback:

```text
Finding 1: TCP retransmissions were elevated during the capture
Evidence: 1 retransmitted of 43 outbound TCP segments (2.33%)
```

That retransmission finding is timing-sensitive context, not the validation
target. The receive-queue finding is the direct signal this experiment is meant
to exercise.
