package analysis

import (
	"fmt"
	"sort"
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
	retransmitFlows := retransmitFlowDeltaDisplay(baseline, incident)
	socketQueues := tcpSocketQueueDeltaDisplay(baseline, incident)
	baselineTCPRTT, baselineTCPRTTOK := highestTCPRTTDisplay(baseline)
	incidentTCPRTT, incidentTCPRTTOK := highestTCPRTTDisplay(incident)

	changes := []KeyDeltaChange{
		{Name: "TCP retransmits", BaselineDisplay: tcpRetransmitDeltaDisplay(baseline), IncidentDisplay: tcpRetransmitDeltaDisplay(incident)},
		{Name: "TCP receive queue", BaselineDisplay: tcpReceiveQueueDisplay(baseline), IncidentDisplay: tcpReceiveQueueDisplay(incident)},
		{Name: "TCP transmit queue", BaselineDisplay: tcpTransmitQueueDisplay(baseline), IncidentDisplay: tcpTransmitQueueDisplay(incident)},
		{Name: "top TCP socket queues", BaselineDisplay: socketQueues.baseline, IncidentDisplay: socketQueues.incident},
		{Name: "top eBPF retransmit flows", BaselineDisplay: retransmitFlows.baseline, IncidentDisplay: retransmitFlows.incident},
		{Name: "top NET_RX softirq CPU", BaselineDisplay: baselineReceiveCPU.softirq, IncidentDisplay: incidentReceiveCPU.softirq},
		{Name: "top NET_RX CPU busy", BaselineDisplay: baselineReceiveCPU.busy, IncidentDisplay: incidentReceiveCPU.busy},
		{Name: "process runtime", BaselineDisplay: processRuntimeDisplay(baseline), IncidentDisplay: processRuntimeDisplay(incident)},
		{Name: "process runqueue wait", BaselineDisplay: processRunqueueWaitDisplay(baseline), IncidentDisplay: processRunqueueWaitDisplay(incident)},
		{Name: "process timeslices", BaselineDisplay: processTimeslicesDisplay(baseline), IncidentDisplay: processTimeslicesDisplay(incident)},
		{Name: "qdisc drops", BaselineDisplay: uintDeltaDisplay(qdiscDropsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(qdiscDropsDelta(incident))},
		{Name: "qdisc overlimits", BaselineDisplay: uintDeltaDisplay(qdiscOverlimitsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(qdiscOverlimitsDelta(incident))},
		{Name: "interface drops", BaselineDisplay: uintDeltaDisplay(interfaceDropsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(interfaceDropsDelta(incident))},
		{Name: "interface errors", BaselineDisplay: uintDeltaDisplay(interfaceErrorsDelta(baseline)), IncidentDisplay: uintDeltaDisplay(interfaceErrorsDelta(incident))},
	}

	if baselineTCPRTTOK || incidentTCPRTTOK {
		changes = append(changes, KeyDeltaChange{
			Name:            "highest TCP RTT",
			BaselineDisplay: baselineTCPRTT,
			IncidentDisplay: incidentTCPRTT,
		})
	}

	baselineFeatureErrors := ebpfFeatureErrorsDisplay(baseline)
	incidentFeatureErrors := ebpfFeatureErrorsDisplay(incident)
	if baselineFeatureErrors != "none" || incidentFeatureErrors != "none" {
		changes = append(changes, KeyDeltaChange{
			Name:            "eBPF feature errors",
			BaselineDisplay: baselineFeatureErrors,
			IncidentDisplay: incidentFeatureErrors,
		})
	}

	return changes
}

type retransmitFlowComparisonDisplay struct {
	baseline string
	incident string
}

type tcpSocketQueueComparisonDisplay struct {
	baseline string
	incident string
}

func tcpSocketQueueDeltaDisplay(baseline, incident model.Recording) tcpSocketQueueComparisonDisplay {
	return tcpSocketQueueComparisonDisplay{
		baseline: tcpSocketQueueSideDisplay("baseline", lastTCPSocketStats(baseline), 3),
		incident: tcpSocketQueueSideDisplay("incident", lastTCPSocketStats(incident), 3),
	}
}

func lastTCPSocketStats(r model.Recording) model.TCPSocketStats {
	if len(r.Samples) == 0 {
		return model.TCPSocketStats{}
	}
	peak := r.Samples[0].TCPSockets
	for _, sample := range r.Samples[1:] {
		if tcpSocketQueuedBytes(sample.TCPSockets) > tcpSocketQueuedBytes(peak) {
			peak = sample.TCPSockets
		}
	}
	return peak
}

func tcpSocketQueuedBytes(stats model.TCPSocketStats) uint64 {
	total := stats.RXQueue + stats.TXQueue
	if total > 0 {
		return total
	}
	for _, queue := range stats.TopQueues {
		total += queue.RXQueue + queue.TXQueue
	}
	return total
}

func tcpSocketQueueSideDisplay(label string, stats model.TCPSocketStats, limit int) string {
	if limit > len(stats.TopQueues) {
		limit = len(stats.TopQueues)
	}

	parts := make([]string, 0, limit+1)
	for _, queue := range stats.TopQueues[:limit] {
		parts = append(parts, fmt.Sprintf(
			"%s %s:%d -> %s:%d state %s rx=%dB tx=%dB",
			queue.Protocol,
			queue.LocalAddress,
			queue.LocalPort,
			queue.RemoteAddress,
			queue.RemotePort,
			queue.State,
			queue.RXQueue,
			queue.TXQueue,
		))
	}

	display := "none"
	if len(parts) > 0 {
		display = strings.Join(parts, "; ")
	}
	if stats.TopQueuesTruncated {
		total := stats.SocketQueueCount
		if total == 0 {
			total = len(stats.TopQueues)
		}
		display += fmt.Sprintf("; %s TCP socket queue list truncated: showing %d of %d sockets with queued bytes", label, len(stats.TopQueues), total)
	}
	return display
}

type retransmitFlowKey struct {
	sourceAddress      string
	destinationAddress string
	sourcePort         uint16
	destinationPort    uint16
}

func retransmitFlowDeltaDisplay(baseline, incident model.Recording) retransmitFlowComparisonDisplay {
	baselineStats, baselineOK := lastEBPFStats(baseline)
	incidentStats, incidentOK := lastEBPFStats(incident)

	keys := retransmitFlowComparisonKeys(baselineStats, baselineOK, incidentStats, incidentOK, 3)

	return retransmitFlowComparisonDisplay{
		baseline: retransmitFlowSideDisplay("baseline", baselineStats, baselineOK, keys),
		incident: retransmitFlowSideDisplay("incident", incidentStats, incidentOK, keys),
	}
}

func lastEBPFStats(r model.Recording) (*model.EBPFStats, bool) {
	if len(r.Samples) == 0 {
		return nil, false
	}
	stats := r.Samples[len(r.Samples)-1].EBPF
	if stats == nil {
		return nil, false
	}
	return stats, true
}

func ebpfFeatureErrorsDisplay(r model.Recording) string {
	stats, ok := lastEBPFStats(r)
	if !ok || stats == nil || len(stats.FeatureErrors) == 0 {
		return "none"
	}

	errors := append([]model.EBPFFeatureError(nil), stats.FeatureErrors...)
	sort.Slice(errors, func(i, j int) bool {
		if errors[i].Name != errors[j].Name {
			return errors[i].Name < errors[j].Name
		}
		return errors[i].Error < errors[j].Error
	})

	parts := make([]string, 0, len(errors))
	for _, featureError := range errors {
		if featureError.Name == "" || featureError.Error == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", featureError.Name, featureError.Error))
	}
	if len(parts) == 0 {
		return "none"
	}

	return strings.Join(parts, "; ")
}

func retransmitFlowComparisonKeys(baseline *model.EBPFStats, baselineOK bool, incident *model.EBPFStats, incidentOK bool, limit int) []retransmitFlowKey {
	if limit <= 0 {
		return nil
	}
	incidentFlows := sortedRetransmitFlowsForCompare(incident, incidentOK)
	if len(incidentFlows) > 0 {
		return retransmitFlowKeys(incidentFlows, limit)
	}
	baselineFlows := sortedRetransmitFlowsForCompare(baseline, baselineOK)
	return retransmitFlowKeys(baselineFlows, limit)
}

func sortedRetransmitFlowsForCompare(stats *model.EBPFStats, ok bool) []model.TCPRetransmitFlow {
	if !ok || stats == nil || len(stats.TCPRetransmitFlows) == 0 {
		return nil
	}
	flows := append([]model.TCPRetransmitFlow(nil), stats.TCPRetransmitFlows...)
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Retransmits != flows[j].Retransmits {
			return flows[i].Retransmits > flows[j].Retransmits
		}
		return retransmitFlowKeyLess(retransmitFlowKeyFromFlow(flows[i]), retransmitFlowKeyFromFlow(flows[j]))
	})
	return flows
}

func retransmitFlowKeys(flows []model.TCPRetransmitFlow, limit int) []retransmitFlowKey {
	if len(flows) < limit {
		limit = len(flows)
	}
	keys := make([]retransmitFlowKey, 0, limit)
	seen := make(map[retransmitFlowKey]struct{}, limit)
	for _, flow := range flows {
		key := retransmitFlowKeyFromFlow(flow)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
		if len(keys) == limit {
			break
		}
	}
	return keys
}

func retransmitFlowSideDisplay(label string, stats *model.EBPFStats, ok bool, keys []retransmitFlowKey) string {
	if !ok || stats == nil {
		return "unavailable"
	}

	counts := retransmitFlowCountByKey(stats.TCPRetransmitFlows)
	var parts []string
	for _, key := range keys {
		count, ok := counts[key]
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s had %d retransmits", formatRetransmitFlowKey(key), count))
	}
	display := "none"
	if len(parts) > 0 {
		display = strings.Join(parts, "; ")
	}
	if stats.TCPRetransmitFlowsTruncated {
		total := stats.TCPRetransmitFlowCount
		if total == 0 {
			total = len(stats.TCPRetransmitFlows)
		}
		display += fmt.Sprintf("; %s eBPF flow list truncated: showing %d of %d observed flow entries", label, len(stats.TCPRetransmitFlows), total)
	}
	if stats.TCPRetransmitFlowsOmittedReason != "" {
		display += fmt.Sprintf("; %s eBPF flow details omitted: %s", label, stats.TCPRetransmitFlowsOmittedReason)
	}
	return display
}

func retransmitFlowCountByKey(flows []model.TCPRetransmitFlow) map[retransmitFlowKey]uint64 {
	counts := make(map[retransmitFlowKey]uint64, len(flows))
	for _, flow := range flows {
		counts[retransmitFlowKeyFromFlow(flow)] += flow.Retransmits
	}
	return counts
}

func retransmitFlowKeyFromFlow(flow model.TCPRetransmitFlow) retransmitFlowKey {
	return retransmitFlowKey{
		sourceAddress:      flow.SourceAddress,
		destinationAddress: flow.DestinationAddress,
		sourcePort:         flow.SourcePort,
		destinationPort:    flow.DestinationPort,
	}
}

func retransmitFlowKeyLess(left, right retransmitFlowKey) bool {
	if left.sourceAddress != right.sourceAddress {
		return left.sourceAddress < right.sourceAddress
	}
	if left.sourcePort != right.sourcePort {
		return left.sourcePort < right.sourcePort
	}
	if left.destinationAddress != right.destinationAddress {
		return left.destinationAddress < right.destinationAddress
	}
	return left.destinationPort < right.destinationPort
}

func formatRetransmitFlowKey(key retransmitFlowKey) string {
	return fmt.Sprintf("%s:%d -> %s:%d", key.sourceAddress, key.sourcePort, key.destinationAddress, key.destinationPort)
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

func tcpReceiveQueueDisplay(r model.Recording) string {
	if len(r.Samples) == 0 {
		return "unavailable"
	}
	_, peak, ok := peakTCPSocketQueueSample(r.Samples, "rx")
	if !ok {
		return "unavailable"
	}
	return fmt.Sprintf("%d B, %d sockets non-zero", peak.TCPSockets.RXQueue, peak.TCPSockets.NonZeroRXSockets)
}

func tcpTransmitQueueDisplay(r model.Recording) string {
	if len(r.Samples) == 0 {
		return "unavailable"
	}
	_, peak, ok := peakTCPSocketQueueSample(r.Samples, "tx")
	if !ok {
		return "unavailable"
	}
	return fmt.Sprintf("%d B, %d sockets non-zero", peak.TCPSockets.TXQueue, peak.TCPSockets.NonZeroTXSockets)
}

func highestTCPRTTDisplay(r model.Recording) (string, bool) {
	highest := 0.0
	found := false
	for _, sample := range r.Samples {
		if sample.TCPInfo == nil {
			continue
		}
		for _, socket := range sample.TCPInfo.Sockets {
			if !found || socket.RTTMillis > highest {
				highest = socket.RTTMillis
				found = true
			}
		}
	}
	if !found {
		return "unavailable", false
	}
	return fmt.Sprintf("%.1f ms", highest), true
}

func lastProcessStats(r model.Recording) (*model.ProcessStats, bool) {
	if len(r.Samples) == 0 {
		return nil, false
	}

	stats := r.Samples[len(r.Samples)-1].Process
	if stats == nil {
		return nil, false
	}

	return stats, true
}

func processRuntimeDisplay(r model.Recording) string {
	stats, ok := lastProcessStats(r)
	if !ok {
		return "unavailable"
	}

	return fmt.Sprintf("%d ns", stats.RuntimeNanos)
}

func processRunqueueWaitDisplay(r model.Recording) string {
	stats, ok := lastProcessStats(r)
	if !ok {
		return "unavailable"
	}

	return fmt.Sprintf("%d ns", stats.RunqueueWaitNanos)
}

func processTimeslicesDisplay(r model.Recording) string {
	stats, ok := lastProcessStats(r)
	if !ok {
		return "unavailable"
	}

	return fmt.Sprintf("%d", stats.Timeslices)
}
