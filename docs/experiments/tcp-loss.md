# Reproducible TCP packet-loss experiment

This experiment validates netdiag's current packet-loss evidence using a
temporary network namespace and veth pair. A client in the host network
namespace sends HTTP requests to a server in the temporary namespace while
`tc netem` applies seeded loss to the host side of the veth pair.

The host-side client is intentional: its TCP counters appear in the host
`/proc/net/snmp` read by netdiag. The eBPF tracepoint is host-wide and can also
observe retransmissions produced in the temporary namespace.

## Requirements

- Linux with network namespace and `sch_netem` support
- Root privileges
- `ip` and `tc` from iproute2
- Python 3
- A built `bin/netdiag`
- BPF privileges and the `tcp_retransmit_skb` tracepoint for eBPF evidence

Run the default experiment with:

```sh
make experiment-loss
```

The output defaults to `loss-capture.json`. Parameters can be overridden:

```sh
sudo env \
  NETDIAG_BIN="$PWD/bin/netdiag" \
  LOSS_PERCENT=15% \
  NETEM_SEED=123 \
  REQUESTS=200 \
  DURATION=30s \
  bash experiments/tcp-loss.sh custom-loss-capture.json
```

The script cleans up its namespace, veth pair, qdisc, server, and recorder on
normal exit or interruption. It never applies `netem` to an existing host
interface.

## Expected evidence

In the recording, compare the first and last samples:

- `tcp.out_segments` should increase because the host client sends traffic.
- `tcp.retransmits` should increase as lost host-side packets are retransmitted.
- `ebpf.tcp_retransmit_events` should increase when eBPF loaded successfully.
- `ebpf.tcp_retransmit_flows` should include bounded IPv4 and IPv6 flow
  counters when `--max-ebpf-flows` is greater than
  zero.
- `ebpf.tcp_retransmit_flow_count` reports how many flow entries were
  observed in the eBPF map at sample time.
- `ebpf.tcp_retransmit_flows_truncated` is true when only the top
  `--max-ebpf-flows` entries were serialized.
- Analysis should normally report elevated TCP retransmissions with strong
  correlation. When per-flow eBPF data is available, the finding should include
  top IPv4 or IPv6 retransmitting flow evidence.

The procfs retransmission delta and eBPF event delta need not be equal. Procfs
is scoped to the host network namespace, while the current eBPF program observes
host-wide tracepoint events across network namespaces. The eBPF per-flow
counters identify flow tuples but are not scoped to the selected interface or
process. Sampling boundaries can also place events just outside the
first-to-last delta.

Do not expect `interface.tx_dropped` or `interface.rx_dropped` to increase.
`netem` drops packets in the qdisc path, and those drops are not generally
reported by the veth device's sysfs drop counters. This experiment validates
loss and retransmission evidence; qdisc-specific drop collection is deferred.

Because other host TCP traffic contributes to the host-wide counters, run the
experiment on a quiet development machine and treat exact counts as
non-deterministic. When the installed iproute2 supports netem's `seed` option,
the fixed seed makes the impairment sequence more repeatable but does not make
scheduler and background traffic deterministic. Older iproute2 releases do
not support this option; the script detects them, prints a warning, and falls
back to unseeded random loss while preserving the rest of the experiment.
