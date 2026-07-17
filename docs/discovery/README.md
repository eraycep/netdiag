# Phase 0 discovery

This directory separates internal lab discovery from evidence that requires
external engineers and production incidents. Synthetic exercises are useful
for designing netdiag, but they are not substitutes for user research.

## Phase 0A: lab discovery

Current status:

- Initial workload selected: NGINX reverse proxy with a controlled backend.
- Provisional driver targets selected: `ixgbe` and `mlx5_core`.
- Diagnostic hypotheses documented but not externally validated.
- Artifact intake, interview, and incident-narrative templates prepared.
- Privacy and redaction policy drafted.
- Controlled packet-loss incident completed successfully.

Phase 0A may guide implementation and controlled experiments. Its outputs must
be labelled `controlled`, `synthetic`, or `provisional` as applicable.

## Phase 0B: external validation

These roadmap requirements remain open:

- Interview 15 Linux performance, SRE, storage, proxy, or database engineers.
- Collect sanitized artifacts from at least five real latency incidents.
- Validate the workload and driver choices against actual environments.
- Obtain agreement from three design partners to run staging captures.

Until those conditions are met, netdiag has demonstrated technical behavior,
not product-market validation.

## Documents

- [Initial workload](workload.md)
- [Diagnostic hypotheses](hypotheses.md)
- [Controlled incident narratives](controlled-incidents.md)
- [Artifact intake](artifact-intake.md)
- [Interview guide](interview-guide.md)
- [Privacy and redaction policy](privacy.md)
- [NIC driver matrix](driver-matrix.md)
