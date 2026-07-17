# Provisional NIC driver matrix

The initial physical-NIC targets are `ixgbe` and `mlx5_core`. Selection is
provisional until hardware tests and external environment data are available.

| Driver | Role | Why selected | Current status |
| --- | --- | --- | --- |
| `ixgbe` | conventional 10-GbE baseline | mature multi-queue driver; useful comparison point for generic ethtool, IRQ, RSS, and queue evidence | selected, no hardware validation |
| `mlx5_core` | modern data-center NIC | rich multi-queue, offload, devlink, and driver-specific visibility | selected, no hardware validation |
| `virtio_net` | development VM coverage | accessible in dedicated VMs, but does not represent a physical NIC datapath | development only |
| `veth` | namespace experiments | deterministic lab topology and fault injection | validated for loss experiment; not a NIC substitute |

References:

- [ixgbe devlink support](https://docs.kernel.org/networking/devlink/ixgbe.html)
- [mlx5 driver documentation](https://docs.kernel.org/networking/device_drivers/ethernet/mellanox/mlx5.html)

## Validation checklist

For each physical driver, record:

- kernel, firmware, driver, and ethtool versions;
- queue counts, RSS indirection, IRQ mapping, and NUMA placement;
- offloads and interrupt-coalescing configuration;
- generic and driver-specific queue counters;
- baseline and impaired workload latency;
- which fields remain stable across resets and link changes;
- collector overhead at each supported interval.

Do not implement driver-specific diagnostic claims from documentation alone.
Every claim needs a controlled experiment on representative hardware.
