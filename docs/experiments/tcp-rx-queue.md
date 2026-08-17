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
MAX_TCP_SOCKET_QUEUES=16 \
bash experiments/tcp-rx-queue.sh "$PWD"
```

Important parameters:

- `PAYLOAD_BYTES`: maximum bytes the client attempts to write.
- `SERVER_SLEEP`: seconds the server keeps the accepted socket open without
  reading.
- `DURATION`: recorder duration.
- `INTERVAL`: recorder sample interval.
- `MAX_TCP_SOCKET_QUEUES`: maximum queued socket tuples serialized per sample.
  Set to `0` to keep only aggregate queue counters.

## Expected evidence

The analyzer should normally report:

```text
TCP socket receive queues grew during the capture
```

Expected evidence includes:

```text
Evidence: TCP receive queues increased by ... bytes
Evidence: ... sockets had non-zero receive queues at peak
Evidence: Top TCP socket receive queue: tcp4 127.0.0.1:<port> -> 127.0.0.1:<port> state 01 had ... bytes queued
```

This finding is intentionally conservative. It shows aggregate receive queue
growth and, when `--max-tcp-socket-queues` is greater than zero, the bounded top
socket queue tuples observed at the queue peak. It does not identify the
owning process and does not prove application causality.

If the finding is not reported, increase `PAYLOAD_BYTES` or `SERVER_SLEEP`.

`netdiag compare` also surfaces socket queue state in the key delta section
when comparing a baseline capture with an incident capture:

```text
- TCP receive queue: 0 B, 0 sockets non-zero -> 127168 B, 1 sockets non-zero
- TCP transmit queue: 0 B, 0 sockets non-zero -> 0 B, 0 sockets non-zero
- top TCP socket queues: none -> tcp4 127.0.0.1:<port> -> 127.0.0.1:<port> state 01 rx=127168B tx=0B
```

## Validated run

On August 17, 2026, a validation run completed on the development host
with:

```text
DURATION=10s
INTERVAL=500ms
SERVER_SLEEP=8
PAYLOAD_BYTES=16777216
MAX_TCP_SOCKET_QUEUES=16
```

The client wrote enough data to block behind the server that accepted the
connection but did not read:

```text
client sent 1900544 bytes; send timeouts 31
```

The analyzer reported the receive-queue validation target:

```text
Finding 2: TCP socket receive queues grew during the capture
Confidence: possible
Severity: warning
Evidence: TCP receive queues increased by 127168 bytes
Evidence: 1 sockets had non-zero receive queues at peak
Evidence: largest observed receive queue was 127168 bytes
Evidence: Top TCP socket receive queue: tcp4 127.0.0.1:35359 -> 127.0.0.1:33036 state 01 had 127168 bytes queued
Next step: Check whether the application or peer was slow to read from established sockets.
```

The same run also reported a small TCP retransmission finding:

```text
Finding 1: TCP retransmissions were elevated during the capture
Evidence: 1 retransmitted of 41 outbound TCP segments (2.44%)
```

That retransmission finding is timing-sensitive context, not the validation
target. The receive-queue finding is the direct signal this experiment is meant
to exercise.

The run also reported a transmit-queue finding. Its top socket queue evidence
included the loopback experiment connection and one unrelated established
external TCP socket:

```text
Finding 3: TCP socket transmit queues grew during the capture
Evidence: TCP transmit queues increased by 1773430 bytes
Evidence: 2 sockets had non-zero transmit queues at peak
Evidence: largest observed transmit queue was 1773376 bytes
Evidence: Top TCP socket transmit queue: tcp4 127.0.0.1:33036 -> 127.0.0.1:35359 state 01 had 1773376 bytes queued
Evidence: Top TCP socket transmit queue: tcp4 10.22.227.227:60712 -> 3.68.61.181:443 state 01 had 54 bytes queued
```

This is expected with the current collector because `/proc/net/tcp` is scoped
to the network namespace, not to the experiment process or connection. The
receive-queue finding remains the validation target.
