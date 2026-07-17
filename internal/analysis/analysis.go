package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/eray/netdiag/internal/model"
)

type Finding struct {
	Severity   string
	Confidence string
	Summary    string
	Evidence   []string
	NextStep   string
}

func Analyze(r model.Recording) ([]Finding, error) {
	if r.Version < 1 || r.Version > model.FormatVersion {
		return nil, fmt.Errorf("unsupported recording version %d", r.Version)
	}
	if len(r.Samples) < 2 {
		return nil, fmt.Errorf("recording needs at least two samples")
	}
	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	seconds, err := recordingDurationSeconds(r)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	resets := detectCounterResets(r.Samples, r.Version >= 3)
	if len(resets.evidence) > 0 {
		findings = append(findings, Finding{
			Severity:   "warning",
			Confidence: "confirmed",
			Summary:    "One or more cumulative counters reset during the capture",
			Evidence:   resets.evidence,
			NextStep:   "Check for a host reboot, interface reset, or collector restart, then analyze each uninterrupted interval separately.",
		})
	}
	out := delta(last.TCP.OutSegments, first.TCP.OutSegments)
	retrans := delta(last.TCP.Retransmits, first.TCP.Retransmits)
	if !resets.tcp && out > 0 {
		ratio := float64(retrans) / float64(out)
		if ratio >= 0.01 {
			evidence := []string{fmt.Sprintf("%d retransmitted of %d outbound TCP segments (%.2f%%)", retrans, out, ratio*100)}
			if !resets.ebpf && first.EBPF != nil && last.EBPF != nil {
				events := delta(last.EBPF.TCPRetransmitEvents, first.EBPF.TCPRetransmitEvents)
				evidence = append(evidence, fmt.Sprintf("eBPF observed %d tcp_retransmit_skb tracepoint events", events))
			}
			findings = append(findings, Finding{
				Severity: "warning", Confidence: "strong correlation",
				Summary:  "TCP retransmissions were elevated during the capture",
				Evidence: evidence,
				NextStep: "Check packet loss, ECN/congestion signals, peer health, and interface error counters.",
			})
		}
	}
	if !resets.iface && first.Interface != nil && last.Interface != nil {
		drops := delta(last.Interface.RXDropped, first.Interface.RXDropped) + delta(last.Interface.TXDropped, first.Interface.TXDropped)
		errors := delta(last.Interface.RXErrors, first.Interface.RXErrors) + delta(last.Interface.TXErrors, first.Interface.TXErrors)
		if drops+errors > 0 {
			findings = append(findings, Finding{
				Severity: "warning", Confidence: "confirmed",
				Summary:  "The selected interface recorded packet drops or errors",
				Evidence: []string{fmt.Sprintf("%d drops and %d errors over %.1f seconds", drops, errors, seconds)},
				NextStep: "Inspect per-queue ethtool counters and qdisc statistics; host counters do not identify the dropping layer.",
			})
		}
	}
	if !resets.softirq {
		if finding, ok := analyzeReceiveCPUConcentration(first, last); ok {
			findings = append(findings, finding)
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{
			Severity: "info", Confidence: "unknown",
			Summary:  "No counter-level network anomaly was detected",
			Evidence: []string{fmt.Sprintf("analyzed %d samples across %.1f seconds", len(r.Samples), seconds)},
			NextStep: "Use per-flow and scheduler instrumentation before excluding kernel or application latency.",
		})
	}
	return findings, nil
}

const (
	minNetRXSoftIRQDelta          = uint64(1000)
	receiveConcentrationThreshold = 0.80
	cpuBusyThreshold              = 0.70
)

func analyzeReceiveCPUConcentration(first, last model.Sample) (Finding, bool) {
	softirqDeltas, totalNetRX, ok := softIRQNetRXDeltas(first.SoftIRQ, last.SoftIRQ)
	if !ok || totalNetRX < minNetRXSoftIRQDelta {
		return Finding{}, false
	}

	cpuDeltas, ok := cpuBusyDeltas(first.CPU, last.CPU)
	if !ok {
		return Finding{}, false
	}

	topCPU, topNetRX, ok := largestCPUDelta(softirqDeltas)
	if !ok {
		return Finding{}, false
	}
	share := float64(topNetRX) / float64(totalNetRX)
	if share < receiveConcentrationThreshold {
		return Finding{}, false
	}

	busy, ok := cpuDeltas[topCPU]
	if !ok || busy.total == 0 {
		return Finding{}, false
	}
	busyRatio := float64(busy.busy) / float64(busy.total)
	if busyRatio < cpuBusyThreshold {
		return Finding{}, false
	}

	evidence := []string{
		fmt.Sprintf("CPU%d handled %.1f%% of NET_RX softirq work", topCPU, share*100),
		fmt.Sprintf("CPU%d was %.1f%% busy during the capture", topCPU, busyRatio*100),
	}
	if irqDelta := irqCountDeltaForCPU(first.IRQ, last.IRQ, topCPU); irqDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("IRQ counts also increased on CPU%d by %d", topCPU, irqDelta))
	}

	return Finding{
		Severity:   "warning",
		Confidence: "strong correlation",
		Summary:    "Network receive processing was concentrated on a busy CPU",
		Evidence:   evidence,
		NextStep:   "Check RSS/IRQ affinity and whether application workers or CPU-intensive tasks share the same CPU.",
	}, true
}

func softIRQNetRXDeltas(first, last model.SoftIRQStats) (map[int]uint64, uint64, bool) {
	if len(first.CPUs) == 0 || len(last.CPUs) == 0 {
		return nil, 0, false
	}
	firstByCPU := make(map[int]model.SoftIRQCPUStats, len(first.CPUs))
	for _, cpu := range first.CPUs {
		if _, exists := firstByCPU[cpu.CPU]; exists {
			return nil, 0, false
		}
		firstByCPU[cpu.CPU] = cpu
	}
	if len(firstByCPU) != len(last.CPUs) {
		return nil, 0, false
	}

	deltas := make(map[int]uint64, len(last.CPUs))
	var total uint64
	for _, current := range last.CPUs {
		previous, ok := firstByCPU[current.CPU]
		if !ok || current.NetRX < previous.NetRX {
			return nil, 0, false
		}
		d := current.NetRX - previous.NetRX
		deltas[current.CPU] = d
		total += d
	}
	return deltas, total, true
}

type cpuBusyDelta struct {
	busy  uint64
	total uint64
}

func cpuBusyDeltas(first, last model.CPUStats) (map[int]cpuBusyDelta, bool) {
	if len(first.CPUs) == 0 || len(last.CPUs) == 0 {
		return nil, false
	}
	firstByCPU := make(map[int]model.CPUTimeStats, len(first.CPUs))
	for _, cpu := range first.CPUs {
		if _, exists := firstByCPU[cpu.CPU]; exists {
			return nil, false
		}
		firstByCPU[cpu.CPU] = cpu
	}
	if len(firstByCPU) != len(last.CPUs) {
		return nil, false
	}

	deltas := make(map[int]cpuBusyDelta, len(last.CPUs))
	for _, current := range last.CPUs {
		previous, ok := firstByCPU[current.CPU]
		if !ok {
			return nil, false
		}
		total, idle, iowait, ok := cpuTimeDeltas(previous, current)
		if !ok || total == 0 || total < idle+iowait {
			return nil, false
		}
		deltas[current.CPU] = cpuBusyDelta{
			busy:  total - idle - iowait,
			total: total,
		}
	}
	return deltas, true
}

func cpuTimeDeltas(previous, current model.CPUTimeStats) (total, idle, iowait uint64, ok bool) {
	fields := []struct {
		previous uint64
		current  uint64
	}{
		{previous.User, current.User},
		{previous.Nice, current.Nice},
		{previous.System, current.System},
		{previous.Idle, current.Idle},
		{previous.IOWait, current.IOWait},
		{previous.IRQ, current.IRQ},
		{previous.SoftIRQ, current.SoftIRQ},
		{previous.Steal, current.Steal},
	}
	for i, field := range fields {
		if field.current < field.previous {
			return 0, 0, 0, false
		}
		d := field.current - field.previous
		total += d
		switch i {
		case 3:
			idle = d
		case 4:
			iowait = d
		}
	}
	return total, idle, iowait, true
}

func largestCPUDelta(deltas map[int]uint64) (int, uint64, bool) {
	var topCPU int
	var topDelta uint64
	var found bool
	for cpu, d := range deltas {
		if !found || d > topDelta {
			topCPU = cpu
			topDelta = d
			found = true
		}
	}
	return topCPU, topDelta, found
}

func irqCountDeltaForCPU(first, last model.IRQStats, cpu int) uint64 {
	if len(first.IRQs) == 0 || len(last.IRQs) == 0 {
		return 0
	}
	firstByIRQ := make(map[string]model.IRQLineStats, len(first.IRQs))
	for _, irq := range first.IRQs {
		firstByIRQ[irq.IRQ] = irq
	}

	var total uint64
	for _, current := range last.IRQs {
		previous, ok := firstByIRQ[current.IRQ]
		if !ok {
			continue
		}
		currentIndex, ok := indexCPU(current.CPUs, cpu)
		if !ok || currentIndex >= len(current.Counts) {
			continue
		}
		previousIndex, ok := indexCPU(previous.CPUs, cpu)
		if !ok || previousIndex >= len(previous.Counts) {
			continue
		}
		total += delta(current.Counts[currentIndex], previous.Counts[previousIndex])
	}
	return total
}

func indexCPU(cpus []int, cpu int) (int, bool) {
	for i, candidate := range cpus {
		if candidate == cpu {
			return i, true
		}
	}
	return 0, false
}

func Render(findings []Finding) string {
	var b strings.Builder
	for i, f := range findings {
		fmt.Fprintf(&b, "Finding %d: %s\nConfidence: %s\nSeverity: %s\n", i+1, f.Summary, f.Confidence, f.Severity)
		for _, evidence := range f.Evidence {
			fmt.Fprintf(&b, "Evidence: %s\n", evidence)
		}
		fmt.Fprintf(&b, "Next step: %s\n", f.NextStep)
		if i != len(findings)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func delta(new, old uint64) uint64 {
	if new < old {
		return 0
	}
	return new - old
}

type counterResetState struct {
	tcp      bool
	softirq  bool
	iface    bool
	ebpf     bool
	evidence []string
}

func detectCounterResets(samples []model.Sample, useElapsed bool) counterResetState {
	var result counterResetState
	for i := 1; i < len(samples); i++ {
		previous, current := samples[i-1], samples[i]
		start, end := previous.Timestamp.Format(time.RFC3339Nano), current.Timestamp.Format(time.RFC3339Nano)
		if useElapsed {
			start = "elapsed " + time.Duration(previous.ElapsedNanos).String()
			end = "elapsed " + time.Duration(current.ElapsedNanos).String()
		}
		record := func(group string, reset bool) {
			if reset {
				result.evidence = append(result.evidence, fmt.Sprintf("%s counter decreased between %s and %s", group, start, end))
			}
		}

		tcpReset := decreased(current.TCP.InSegments, previous.TCP.InSegments) ||
			decreased(current.TCP.OutSegments, previous.TCP.OutSegments) ||
			decreased(current.TCP.Retransmits, previous.TCP.Retransmits) ||
			decreased(current.TCP.InErrors, previous.TCP.InErrors)
		result.tcp = result.tcp || tcpReset
		record("TCP", tcpReset)

		softirqReset, softirqEvidence := softIRQCounterResetEvidence(previous.SoftIRQ, current.SoftIRQ, start, end)
		result.softirq = result.softirq || softirqReset
		result.evidence = append(result.evidence, softirqEvidence...)

		if previous.Interface != nil && current.Interface != nil {
			interfaceReset := decreased(current.Interface.RXPackets, previous.Interface.RXPackets) ||
				decreased(current.Interface.TXPackets, previous.Interface.TXPackets) ||
				decreased(current.Interface.RXBytes, previous.Interface.RXBytes) ||
				decreased(current.Interface.TXBytes, previous.Interface.TXBytes) ||
				decreased(current.Interface.RXDropped, previous.Interface.RXDropped) ||
				decreased(current.Interface.TXDropped, previous.Interface.TXDropped) ||
				decreased(current.Interface.RXErrors, previous.Interface.RXErrors) ||
				decreased(current.Interface.TXErrors, previous.Interface.TXErrors)
			result.iface = result.iface || interfaceReset
			record("interface", interfaceReset)
		}

		if previous.EBPF != nil && current.EBPF != nil {
			ebpfReset := decreased(current.EBPF.TCPRetransmitEvents, previous.EBPF.TCPRetransmitEvents)
			result.ebpf = result.ebpf || ebpfReset
			record("eBPF TCP retransmit", ebpfReset)
		}
	}
	return result
}

func softIRQCounterResetEvidence(previous, current model.SoftIRQStats, start, end string) (bool, []string) {
	if len(previous.CPUs) > 0 && len(current.CPUs) > 0 {
		previousByCPU := make(map[int]model.SoftIRQCPUStats, len(previous.CPUs))
		for _, cpu := range previous.CPUs {
			previousByCPU[cpu.CPU] = cpu
		}
		if len(previousByCPU) != len(previous.CPUs) || len(previousByCPU) != len(current.CPUs) {
			return false, nil
		}

		var evidence []string
		for _, currentCPU := range current.CPUs {
			previousCPU, ok := previousByCPU[currentCPU.CPU]
			if !ok {
				return false, nil
			}
			if decreased(currentCPU.NetRX, previousCPU.NetRX) || decreased(currentCPU.NetTX, previousCPU.NetTX) {
				evidence = append(evidence, fmt.Sprintf("softirq CPU%d counter decreased between %s and %s", currentCPU.CPU, start, end))
			}
		}
		return len(evidence) > 0, evidence
	}

	reset := decreased(current.NetRX, previous.NetRX) ||
		decreased(current.NetTX, previous.NetTX)
	if reset {
		return true, []string{fmt.Sprintf("softirq counter decreased between %s and %s", start, end)}
	}
	return false, nil
}

func recordingDurationSeconds(r model.Recording) (float64, error) {
	if r.Version >= 3 {
		if r.Samples[0].ElapsedNanos < 0 {
			return 0, fmt.Errorf("recording has an invalid elapsed time range")
		}
		for i := 1; i < len(r.Samples); i++ {
			if r.Samples[i].ElapsedNanos <= r.Samples[i-1].ElapsedNanos {
				return 0, fmt.Errorf("recording has a non-increasing elapsed time at sample %d", i)
			}
		}
		nanos := r.Samples[len(r.Samples)-1].ElapsedNanos - r.Samples[0].ElapsedNanos
		return float64(nanos) / float64(time.Second), nil
	}

	seconds := r.Samples[len(r.Samples)-1].Timestamp.Sub(r.Samples[0].Timestamp).Seconds()
	if seconds <= 0 {
		return 0, fmt.Errorf("recording has an invalid time range")
	}
	return seconds, nil
}

func decreased(current, previous uint64) bool {
	return current < previous
}
