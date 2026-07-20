# NIC queue counters

Queue-level NIC driver counters are deferred to Phase 4.

## Reason

Queue-level diagnosis requires driver-specific visibility and validation:

- mapping RX/TX queues to IRQs and CPUs;
- correlating queue counters with RSS, RPS and XPS configuration;
- handling driver-specific `ethtool -S` counter names;
- distinguishing queue imbalance from application CPU placement;
- validating behavior across at least two NIC families.

Phase 1 intentionally stops at portable host counters:

- `/proc/net/snmp`;
- `/proc/softirqs`;
- `/proc/stat`;
- `/proc/interrupts`;
- sysfs interface counters;
- `tc -s qdisc`;
- host-wide eBPF retransmission count.

This keeps the Phase 1 diagnostic surface reproducible on a single recent Linux
host without requiring driver-specific assumptions.

## Phase 4 acceptance criteria

Implement queue-level counters when netdiag can:

1. collect queue-level stats for at least two common NIC families;
2. map queue counters to IRQ CPUs when kernel metadata permits;
3. report unavailable mappings explicitly;
4. detect controlled queue imbalance;
5. avoid claiming causality from queue counters alone.

## Current user-facing behavior

When Phase 1 findings point toward possible queue pressure, netdiag should
direct the operator to inspect RSS/IRQ affinity, qdisc state, interface errors
and driver counters manually. It must not imply that queue-level NIC counters
were collected.
