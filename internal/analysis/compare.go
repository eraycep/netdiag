package analysis

import (
	"fmt"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

type Comparison struct {
	VisibilityDifferences []VisibilityDifference
	IncidentOnlyFindings  []Finding
	SharedFindings        []Finding
	BaselineOnlyFindings  []Finding
	KeyDeltaChanges       []KeyDeltaChange
}

type VisibilityDifference struct {
	Collector string
	Baseline  model.CollectorStatus
	Incident  model.CollectorStatus
}

type KeyDeltaChange struct {
	Name            string
	BaselineDisplay string
	IncidentDisplay string
}

func Compare(baseline, incident model.Recording) (Comparison, error) {
	baselineFindings, err := Analyze(baseline)
	if err != nil {
		return Comparison{}, fmt.Errorf("analyze baseline: %w", err)
	}
	incidentFindings, err := Analyze(incident)
	if err != nil {
		return Comparison{}, fmt.Errorf("analyze incident: %w", err)
	}

	return Comparison{
		VisibilityDifferences: compareVisibility(baseline.Collectors, incident.Collectors),
		IncidentOnlyFindings:  findingDifference(incidentFindings, baselineFindings),
		SharedFindings:        sharedFindings(baselineFindings, incidentFindings),
		BaselineOnlyFindings:  findingDifference(baselineFindings, incidentFindings),
		KeyDeltaChanges:       compareKeyDeltas(baseline, incident),
	}, nil
}

func RenderComparison(baselinePath, incidentPath string, c Comparison) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Comparison: %s -> %s\n\n", baselinePath, incidentPath)

	b.WriteString("Visibility differences:\n")
	if len(c.VisibilityDifferences) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, diff := range c.VisibilityDifferences {
			fmt.Fprintf(&b, "- %s: %s -> %s\n", diff.Collector, diff.Baseline, diff.Incident)
		}
	}
	b.WriteByte('\n')

	renderFindingList(&b, "Incident-only findings", c.IncidentOnlyFindings)
	renderFindingList(&b, "Shared findings", c.SharedFindings)
	renderFindingList(&b, "Baseline-only findings", c.BaselineOnlyFindings)

	b.WriteString("Key delta changes:\n")
	if len(c.KeyDeltaChanges) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, change := range c.KeyDeltaChanges {
			fmt.Fprintf(&b, "- %s: %s -> %s\n", change.Name, change.BaselineDisplay, change.IncidentDisplay)
		}
	}

	return b.String()
}

func renderFindingList(b *strings.Builder, title string, findings []Finding) {
	fmt.Fprintf(b, "%s:\n", title)
	if len(findings) == 0 {
		b.WriteString("- none\n\n")
		return
	}
	for _, finding := range findings {
		fmt.Fprintf(b, "- %s\n", finding.Summary)
	}
	b.WriteByte('\n')
}

func compareVisibility(baseline, incident []model.CollectorManifest) []VisibilityDifference {
	baselineByName := make(map[string]model.CollectorStatus, len(baseline))
	for _, collector := range baseline {
		baselineByName[collector.CollectorName] = collector.Status
	}

	var differences []VisibilityDifference
	seen := make(map[string]struct{}, len(incident))
	for _, collector := range incident {
		seen[collector.CollectorName] = struct{}{}
		baselineStatus, ok := baselineByName[collector.CollectorName]
		if !ok {
			baselineStatus = model.CollectorUnavailable
		}
		if baselineStatus != collector.Status {
			differences = append(differences, VisibilityDifference{
				Collector: collector.CollectorName,
				Baseline:  baselineStatus,
				Incident:  collector.Status,
			})
		}
	}
	for _, collector := range baseline {
		if _, ok := seen[collector.CollectorName]; ok {
			continue
		}
		differences = append(differences, VisibilityDifference{
			Collector: collector.CollectorName,
			Baseline:  collector.Status,
			Incident:  model.CollectorUnavailable,
		})
	}
	return differences
}

func findingDifference(left, right []Finding) []Finding {
	rightSummaries := findingSummarySet(right)
	var result []Finding
	for _, finding := range left {
		if finding.Severity == "info" {
			continue
		}
		if _, ok := rightSummaries[finding.Summary]; !ok {
			result = append(result, finding)
		}
	}
	return result
}

func sharedFindings(baseline, incident []Finding) []Finding {
	incidentSummaries := findingSummarySet(incident)
	var result []Finding
	for _, finding := range baseline {
		if finding.Severity == "info" {
			continue
		}
		if _, ok := incidentSummaries[finding.Summary]; ok {
			result = append(result, finding)
		}
	}
	return result
}

func findingSummarySet(findings []Finding) map[string]struct{} {
	result := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		result[finding.Summary] = struct{}{}
	}
	return result
}

func compareKeyDeltas(baseline, incident model.Recording) []KeyDeltaChange {
	baselineReceiveCPU := receiveCPUDeltaDisplay(baseline)
	incidentReceiveCPU := receiveCPUDeltaDisplay(incident)

	return []KeyDeltaChange{
		{Name: "TCP retransmits", BaselineDisplay: tcpRetransmitDeltaDisplay(baseline), IncidentDisplay: tcpRetransmitDeltaDisplay(incident)},
		{Name: "top NET_RX softirq CPU", BaselineDisplay: baselineReceiveCPU.softirq, IncidentDisplay: incidentReceiveCPU.softirq},
		{Name: "top NET_RX CPU busy", BaselineDisplay: baselineReceiveCPU.busy, IncidentDisplay: incidentReceiveCPU.busy},
		{Name: "qdisc drops", BaselineDisplay: uintDeltaDisplay(qdiscDropsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(qdiscDropsDelta(incident))},
		{Name: "qdisc overlimits", BaselineDisplay: uintDeltaDisplay(qdiscOverlimitsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(qdiscOverlimitsDelta(incident))},
		{Name: "interface drops", BaselineDisplay: uintDeltaDisplay(interfaceDropsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(interfaceDropsDelta(incident))},
		{Name: "interface errors", BaselineDisplay: uintDeltaDisplay(interfaceErrorsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(interfaceErrorsDelta(incident))},
	}
}

type receiveCPUDisplay struct {
	softirq string
	busy    string
}

func receiveCPUDeltaDisplay(r model.Recording) receiveCPUDisplay {
	result := receiveCPUDisplay{
		softirq: "unavailable",
		busy:    "unavailable",
	}
	if len(r.Samples) < 2 {
		return result
	}

	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	softIRQDeltas, total, ok := softIRQNetRXDeltas(first.SoftIRQ, last.SoftIRQ)
	if !ok || total == 0 {
		return result
	}
	topCPU, topDelta, ok := largestCPUDelta(softIRQDeltas)
	if !ok {
		return result
	}
	result.softirq = fmt.Sprintf("CPU%d %.1f%% of %d", topCPU, float64(topDelta)/float64(total)*100, total)

	busyDeltas, ok := cpuBusyDeltas(first.CPU, last.CPU)
	if !ok {
		return result
	}
	busy, ok := busyDeltas[topCPU]
	if !ok || busy.total == 0 {
		return result
	}
	result.busy = fmt.Sprintf("CPU%d %.1f%%", topCPU, float64(busy.busy)/float64(busy.total)*100)

	return result
}

func tcpRetransmitDeltaDisplay(r model.Recording) string {
	if len(r.Samples) < 2 {
		return "0/0 outbound segments (0.00%)"
	}
	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	retransmits := delta(last.TCP.Retransmits, first.TCP.Retransmits)
	out := delta(last.TCP.OutSegments, first.TCP.OutSegments)
	if out == 0 {
		return fmt.Sprintf("%d/0 outbound segments (0.00%%)", retransmits)
	}
	return fmt.Sprintf("%d/%d outbound segments (%.2f%%)", retransmits, out, float64(retransmits)/float64(out)*100)
}

func uintDeltaDisplay(value uint64) string {
	return fmt.Sprintf("%d", value)
}

func qdiscDropsDelta(r model.Recording) uint64 {
	var total uint64
	for _, d := range qdiscDeltaValues(r, func(q model.QdiscLineStats) uint64 { return q.Drops }) {
		total += d
	}
	return total
}

func qdiscOverlimitsDelta(r model.Recording) uint64 {
	var total uint64
	for _, d := range qdiscDeltaValues(r, func(q model.QdiscLineStats) uint64 { return q.Overlimits }) {
		total += d
	}
	return total
}

func qdiscDeltaValues(r model.Recording, value func(model.QdiscLineStats) uint64) []uint64 {
	if len(r.Samples) < 2 {
		return nil
	}
	first, last := r.Samples[0].Qdisc, r.Samples[len(r.Samples)-1].Qdisc
	if len(first.Qdiscs) == 0 || len(last.Qdiscs) == 0 {
		return nil
	}
	firstByKey := make(map[string]model.QdiscLineStats, len(first.Qdiscs))
	for _, qdisc := range first.Qdiscs {
		firstByKey[qdiscKey(qdisc)] = qdisc
	}
	var deltas []uint64
	for _, current := range last.Qdiscs {
		previous, ok := firstByKey[qdiscKey(current)]
		if !ok {
			continue
		}
		deltas = append(deltas, delta(value(current), value(previous)))
	}
	return deltas
}

func interfaceDropsDelta(r model.Recording) uint64 {
	if len(r.Samples) < 2 {
		return 0
	}
	first, last := r.Samples[0].Interface, r.Samples[len(r.Samples)-1].Interface
	if first == nil || last == nil {
		return 0
	}
	return delta(last.RXDropped, first.RXDropped) + delta(last.TXDropped, first.TXDropped)
}

func interfaceErrorsDelta(r model.Recording) uint64 {
	if len(r.Samples) < 2 {
		return 0
	}
	first, last := r.Samples[0].Interface, r.Samples[len(r.Samples)-1].Interface
	if first == nil || last == nil {
		return 0
	}
	return delta(last.RXErrors, first.RXErrors) + delta(last.TXErrors, first.TXErrors)
}
