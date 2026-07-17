# Engineer interview guide

Target participants: Linux performance engineers, SREs, network engineers,
and engineers responsible for proxies, databases, or storage systems.

The interview is evidence gathering, not a product demonstration. Ask for a
specific recent incident before discussing netdiag.

## Opening

- What systems are you responsible for?
- Which Linux and NIC environments are common?
- How often do TCP tail-latency incidents require host-level investigation?

## Incident reconstruction

- Tell me about the most recent relevant incident from first alert to closure.
- What exactly regressed, over what interval, and against which baseline?
- Which commands or dashboards did you inspect, in order?
- What hypotheses did you reject, and what evidence rejected them?
- Which observation first narrowed the problem to application, TCP, kernel,
  qdisc, driver, or NIC?
- What was the confirmed cause? If unresolved, where did visibility stop?
- How long did detection, diagnosis, mitigation, and verification take?

## Existing workflow

- Which tools are always available during an incident?
- What requires root, kernel changes, or prior deployment?
- Which data is too expensive, high-cardinality, or sensitive to retain?
- Which counters have misled you because their scope was unclear?
- How do virtualization, offloads, namespaces, or containers change trust in
  the evidence?

## Capture acceptance

- Would you run a bounded local recorder in staging? Under what conditions?
- What CPU, memory, and disk budget is acceptable?
- Which fields must never be collected?
- How should partial visibility and failed collectors be presented?
- What output would let a non-specialist take the next correct action?

## Closing

- Request a sanitized artifact only with explicit consent.
- Ask permission for a factual follow-up, not an open-ended commitment.
- Record disagreements and negative feedback without reinterpretation.

## Interview record

Store participant role and environment category, not identity, in the research
notes. Separate contact details from technical notes. Mark every conclusion as
direct observation, participant interpretation, or researcher inference.
