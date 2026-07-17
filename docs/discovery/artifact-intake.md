# Incident artifact intake

Use this checklist only after the contributor approves the privacy policy.
Prefer counters and configuration over packet captures. Never request payloads,
credentials, private keys, or unrestricted support bundles.

## Context questionnaire

- Incident identifier and approximate UTC interval
- Linux distribution and kernel version
- Bare metal, dedicated VM, or other environment
- Workload role and TCP protocol
- Affected interface and NIC driver
- Symptom metric and baseline comparison
- Known changes preceding the incident
- Confirmed cause, suspected cause, or unresolved
- Commands used and which result first changed the investigation
- Time to detection and time to resolution

## Preferred artifacts

- Sanitized netdiag recording
- `uname -a` with hostname removed
- `ip -details link show` with addresses and names redacted as needed
- `ethtool -i` and selected `ethtool -S` counters
- `tc -s qdisc show`
- Relevant `/proc/net/snmp`, `/proc/softirqs`, and `/proc/interrupts` excerpts
- Workload latency histogram and request-rate series
- Exact diagnostic commands with timestamps

## Intake procedure

1. Assign a random incident identifier; do not use a customer or hostname.
2. Ask the contributor to sanitize data before transfer.
3. Review again on receipt and quarantine questionable fields.
4. Record provenance, consent, permitted uses, and deletion date.
5. Store the sanitized copy separately from contact information.
6. Write a narrative and ask the contributor to verify factual accuracy.
7. Delete rejected and raw artifacts after the agreed review window.

## Quality bar

An artifact is useful only if its time interval, counter scope, collection
method, and known gaps are understood. A large bundle without provenance is
not stronger evidence than a small, well-scoped capture.
