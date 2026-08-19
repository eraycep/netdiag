# Reproducible TCP RTT delay experiment

This experiment validates the opt-in `--tcp-info` RTT signal using a temporary
network namespace and veth pair. A TCP echo server and the recorder run in the
temporary namespace, while a host-side client keeps one established TCP
connection open. Running the recorder inside the temporary namespace keeps
unrelated host sockets out of `ss -tin`. The impaired run applies `tc netem
delay` to the host side of the veth pair so the namespace-side socket can
observe elevated RTT.

The experiment never applies `netem` to an existing host interface.

## Requirements

- Linux with network namespace and `sch_netem` support
- Root privileges
- `ip`, `tc`, and `ss` from iproute2
- Python 3
- A built `bin/netdiag`

Run the default experiment with:

```sh
make experiment-rtt-delay
```

The output defaults to:

- `tcp-rtt-delay-baseline.json`
- `tcp-rtt-delay-baseline.txt`
- `tcp-rtt-delay-impaired.json`
- `tcp-rtt-delay-impaired.txt`
- `tcp-rtt-delay-compare.txt`

Parameters can be overridden:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  NETEM_DELAY=200ms \
  DURATION=15s \
  CLIENT_DURATION=12 \
  bash experiments/tcp-rtt-delay.sh "$PWD"
```

Set `STRICT=1` to fail the script if the impaired analysis does not report the
expected elevated RTT finding.

## Expected evidence

The baseline capture should normally have low `tcp_info.sockets[].rtt_ms`
values and should not report the elevated RTT finding. The impaired capture
should show at least one socket with RTT above the analyzer's elevated RTT
threshold.

The impaired analysis should normally report:

```text
Finding 1: TCP RTT was elevated during the capture
Confidence: possible
Severity: warning
Evidence: highest observed TCP RTT was ...
Evidence: Top TCP RTT socket: ...
Next step: Check packet loss, congestion window, retransmissions, peer health, and whether the path is congested.
```

The comparison output should include:

```text
- highest TCP RTT: ... ms -> ... ms
```

## Visibility limits

TCP info collection is opt-in and comes from `ss -tin`, so it is scoped to
established sockets visible in the recorder's network namespace. This
experiment runs the recorder in the temporary namespace to avoid unrelated host
sockets. TCP info includes local and remote IP addresses and ports. Use
`--max-tcp-info-sockets=0` outside this experiment when endpoint tuples are too
sensitive.

The finding is a conservative correlation. Elevated RTT does not prove the
cause of delay. The controlled `netem` impairment provides the causal context
for this experiment; production captures still need corroborating evidence such
as retransmissions, qdisc counters, peer health, or scheduler pressure.

Exact RTT values are non-deterministic. Scheduler timing, TCP behavior and the
kernel's RTT estimator can vary between runs. If the impaired finding does not
fire on a busy host, increase `NETEM_DELAY` or `CLIENT_DURATION`.
