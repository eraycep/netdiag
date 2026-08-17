# Capture privacy and redaction policy

Status: draft for lab use and external review. This is an engineering policy,
not legal advice.

## Default collection policy

Netdiag must not collect packet payloads by default. The current recorder stores
host metadata, an optional interface name, aggregate counters, collector
visibility, and timestamps. Future probes should prefer numeric identifiers and
aggregates over addresses or application data.

## Data classification

| Data | Default policy |
| --- | --- |
| Packet payloads and TLS material | prohibited |
| Credentials, tokens, cookies, and headers | prohibited |
| Process command lines and environment | prohibited unless separately approved |
| IP addresses and ports | omit or pseudonymize before retention |
| TCP socket queue tuples | local/remote IP and port, TCP state, and queued byte counts; bounded by `--max-tcp-socket-queues`; set to `0` to omit tuples while keeping aggregates |
| Hostnames and interface names | potentially identifying; redact for sharing |
| Process, socket, cgroup, and namespace IDs | collect only when required; treat as sensitive metadata |
| Kernel, driver, and counter values | permitted, subject to environment review |

## Collection principles

- Minimize: collect only evidence required by a diagnostic hypothesis.
- Bound: enforce duration, sample, cardinality, and output-size limits.
- Disclose: record collector scope and unavailable visibility.
- Separate: keep contact/customer identity apart from technical artifacts.
- Expire: assign a deletion date when an artifact is accepted.
- Verify: let contributors review narratives derived from their data.

## Redaction procedure

Before an artifact leaves its source environment:

1. Replace hostname, interface aliases, IP addresses, and service identifiers
   with stable per-artifact pseudonyms when relationships matter.
2. Remove free-form command output not required for the investigation.
3. Confirm that no packet payload, environment variable, credential, key, or
   application request content remains.
4. Preserve units, timestamps relative to capture start, counter scope, and
   kernel/driver versions needed for interpretation.
5. Document every transformation so the evidentiary limits are clear.

## Retention and access

- Raw external artifacts should have the shortest practical review window.
- Retain only the sanitized derivative after review.
- Restrict access to people performing the documented investigation.
- Honor deletion requests and record deletion completion.
- Do not publish an artifact or narrative without explicit permission.

## Future implementation requirements

Before per-flow collection ships, define address hashing, key management,
cardinality limits, namespace handling, and a user-visible field inventory.
Privacy review is a release gate for every newly collected field.
