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
