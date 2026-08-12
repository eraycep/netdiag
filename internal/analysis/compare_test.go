package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/eray/netdiag/internal/model"
)

func TestCompareFindingsVisibilityAndKeyDeltas(t *testing.T) {
	baseline := comparisonRecording(0, 0, model.CollectorEnabled)
	incident := comparisonRecording(694, 882, model.CollectorUnavailable)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	if len(comparison.VisibilityDifferences) != 1 {
		t.Fatalf("visibility differences = %+v, want one", comparison.VisibilityDifferences)
	}
	diff := comparison.VisibilityDifferences[0]
	if diff.Collector != "tc_qdisc" || diff.Baseline != model.CollectorEnabled || diff.Incident != model.CollectorUnavailable {
		t.Fatalf("unexpected visibility diff: %+v", diff)
	}

	incidentOnly := findingSummaries(comparison.IncidentOnlyFindings)
	for _, want := range []string{
		"TCP retransmissions were elevated during the capture",
		"The selected interface qdisc recorded drops or overlimits",
	} {
		if !containsString(incidentOnly, want) {
			t.Fatalf("incident-only findings = %+v, missing %q", incidentOnly, want)
		}
	}
	if len(comparison.SharedFindings) != 0 {
		t.Fatalf("shared findings = %+v, want none", comparison.SharedFindings)
	}
	if len(comparison.BaselineOnlyFindings) != 0 {
		t.Fatalf("baseline-only findings = %+v, want none", comparison.BaselineOnlyFindings)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	for _, want := range []string{
		"Comparison: baseline.json -> incident.json",
		"- tc_qdisc: enabled -> unavailable",
		"- TCP retransmits: 0/1000 outbound segments (0.00%) -> 694/1000 outbound segments (69.40%)",
		"- qdisc drops: 0 -> 882",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
		}
	}
}

func TestCompareTCPDeltaDisplayHandlesZeroOutboundSegments(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{Retransmits: 1}},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{Retransmits: 3}},
	}}

	if got, want := tcpRetransmitDeltaDisplay(r), "2/0 outbound segments (0.00%)"; got != want {
		t.Fatalf("display = %q, want %q", got, want)
	}
}

func TestCompareReportsReceiveCPUSignalChanges(t *testing.T) {
	baseline := receiveCPUComparisonRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 100}, {CPU: 1, NetRX: 100}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 200}, {CPU: 1, NetRX: 1000}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 200, 1800), cpuTime(1, 600, 1400)},
	)
	incident := receiveCPUComparisonRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 100}, {CPU: 1, NetRX: 100}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 200}, {CPU: 1, NetRX: 2000}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 200, 1800), cpuTime(1, 900, 1100)},
	)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	for _, want := range []string{
		"- top NET_RX softirq CPU: CPU1 90.0% of 1000 -> CPU1 95.0% of 2000",
		"- top NET_RX CPU busy: CPU1 50.0% -> CPU1 80.0%",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
		}
	}
}

func TestCompareReportsTCPReceiveQueueSignalChanges(t *testing.T) {
	baseline := tcpSocketQueueComparisonRecording(0, 0, 0, 0)
	incident := tcpSocketQueueComparisonRecording(71680, 2, 0, 0)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- TCP receive queue: 0 B, 0 sockets non-zero -> 71680 B, 2 sockets non-zero"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsTCPTransmitQueueSignalChanges(t *testing.T) {
	baseline := tcpSocketQueueComparisonRecording(0, 0, 0, 0)
	incident := tcpSocketQueueComparisonRecording(0, 0, 32768, 1)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- TCP transmit queue: 0 B, 0 sockets non-zero -> 32768 B, 1 sockets non-zero"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsProcessSchedstatSignalChanges(t *testing.T) {
	baseline := processComparisonRecording(&model.ProcessStats{
		RuntimeNanos:      1000000,
		RunqueueWaitNanos: 200000,
		Timeslices:        10,
	})
	incident := processComparisonRecording(&model.ProcessStats{
		RuntimeNanos:      2500000,
		RunqueueWaitNanos: 1800000,
		Timeslices:        25,
	})

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	for _, want := range []string{
		"- process runtime: 1000000 ns -> 2500000 ns",
		"- process runqueue wait: 200000 ns -> 1800000 ns",
		"- process timeslices: 10 -> 25",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
		}
	}
}

func TestCompareReportsProcessSchedstatUnavailable(t *testing.T) {
	baseline := processComparisonRecording(nil)
	incident := processComparisonRecording(nil)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- process runtime: unavailable -> unavailable"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsIncidentOnlyRetransmitFlow(t *testing.T) {
	baseline := comparisonFlowRecording(nil, false, 0)
	incident := comparisonFlowRecording([]model.TCPRetransmitFlow{
		{
			SourceAddress:      "127.0.0.1",
			DestinationAddress: "127.0.0.1",
			SourcePort:         43946,
			DestinationPort:    40981,
			Retransmits:        4,
		},
	}, false, 1)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- top eBPF retransmit flows: none -> 127.0.0.1:43946 -> 127.0.0.1:40981 had 4 retransmits"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsSharedRetransmitFlowDelta(t *testing.T) {
	baseline := comparisonFlowRecording([]model.TCPRetransmitFlow{
		{
			SourceAddress:      "10.0.0.2",
			DestinationAddress: "10.0.0.1",
			SourcePort:         53000,
			DestinationPort:    443,
			Retransmits:        1,
		},
	}, false, 1)
	incident := comparisonFlowRecording([]model.TCPRetransmitFlow{
		{
			SourceAddress:      "10.0.0.2",
			DestinationAddress: "10.0.0.1",
			SourcePort:         53000,
			DestinationPort:    443,
			Retransmits:        7,
		},
	}, false, 1)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- top eBPF retransmit flows: 10.0.0.2:53000 -> 10.0.0.1:443 had 1 retransmits -> 10.0.0.2:53000 -> 10.0.0.1:443 had 7 retransmits"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsRetransmitFlowTruncation(t *testing.T) {
	baseline := comparisonFlowRecording(nil, false, 0)
	incident := comparisonFlowRecording([]model.TCPRetransmitFlow{
		{SourceAddress: "10.0.0.2", DestinationAddress: "10.0.0.1", SourcePort: 53000, DestinationPort: 443, Retransmits: 7},
		{SourceAddress: "10.0.0.3", DestinationAddress: "10.0.0.1", SourcePort: 53001, DestinationPort: 443, Retransmits: 5},
		{SourceAddress: "10.0.0.4", DestinationAddress: "10.0.0.1", SourcePort: 53002, DestinationPort: 443, Retransmits: 3},
	}, true, 128)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "incident eBPF flow list truncated: showing 3 of 128 observed flow entries"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsRetransmitFlowOmissionReason(t *testing.T) {
	baseline := comparisonFlowRecording(nil, false, 0)
	incident := comparisonFlowRecording(nil, true, 12)
	incident.Samples[len(incident.Samples)-1].EBPF.TCPRetransmitFlowsOmittedReason = "recording eBPF flow sample budget exhausted"

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	for _, want := range []string{
		"incident eBPF flow list truncated: showing 0 of 12 observed flow entries",
		"incident eBPF flow details omitted: recording eBPF flow sample budget exhausted",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
		}
	}
}

func TestCompareRetransmitFlowDisplayUnavailableAndNone(t *testing.T) {
	baseline := comparisonNoEBPFRecording()
	incident := comparisonFlowRecording(nil, false, 0)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- top eBPF retransmit flows: unavailable -> none"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsIncidentOnlyEBPFFeatureErrors(t *testing.T) {
	baseline := comparisonFeatureErrorRecording(nil)
	incident := comparisonFeatureErrorRecording([]model.EBPFFeatureError{
		{Name: model.EBPFFeatureTCPRetransmitIPv4Flows, Error: "iterate tcp retransmit flow map: permission denied"},
	})

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- eBPF feature errors: none -> tcp_retransmit_ipv4_flows: iterate tcp retransmit flow map: permission denied"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareReportsBothSideEBPFFeatureErrors(t *testing.T) {
	baseline := comparisonFeatureErrorRecording([]model.EBPFFeatureError{
		{Name: model.EBPFFeatureTCPRetransmitIPv4Flows, Error: "baseline map read failed"},
	})
	incident := comparisonFeatureErrorRecording([]model.EBPFFeatureError{
		{Name: model.EBPFFeatureTCPRetransmitIPv4Flows, Error: "incident map read failed"},
	})

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	want := "- eBPF feature errors: tcp_retransmit_ipv4_flows: baseline map read failed -> tcp_retransmit_ipv4_flows: incident map read failed"
	if !strings.Contains(rendered, want) {
		t.Fatalf("rendered comparison missing %q:\n%s", want, rendered)
	}
}

func TestCompareOmitsEBPFFeatureErrorsWhenBothSidesClean(t *testing.T) {
	baseline := comparisonFeatureErrorRecording(nil)
	incident := comparisonFeatureErrorRecording(nil)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	rendered := RenderComparison("baseline.json", "incident.json", comparison)
	if strings.Contains(rendered, "eBPF feature errors") {
		t.Fatalf("rendered comparison unexpectedly included eBPF feature errors:\n%s", rendered)
	}
}

func TestReceiveCPUDeltaDisplayHandlesMissingCPUStats(t *testing.T) {
	r := receiveCPUComparisonRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 100}, {CPU: 1, NetRX: 100}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 200}, {CPU: 1, NetRX: 1000}},
		nil,
		nil,
	)

	got := receiveCPUDeltaDisplay(r)
	if got.softirq != "CPU1 90.0% of 1000" {
		t.Fatalf("softirq display = %q, want CPU1 90.0%% of 1000", got.softirq)
	}
	if got.busy != "unavailable" {
		t.Fatalf("busy display = %q, want unavailable", got.busy)
	}
}

func TestCompareClassifiesSharedAndBaselineOnlyFindings(t *testing.T) {
	baseline := comparisonRecording(100, 10, model.CollectorEnabled)
	incident := comparisonRecording(200, 0, model.CollectorEnabled)

	comparison, err := Compare(baseline, incident)
	if err != nil {
		t.Fatal(err)
	}

	shared := findingSummaries(comparison.SharedFindings)
	if !containsString(shared, "TCP retransmissions were elevated during the capture") {
		t.Fatalf("shared findings = %+v, want retransmission finding", shared)
	}

	baselineOnly := findingSummaries(comparison.BaselineOnlyFindings)
	if !containsString(baselineOnly, "The selected interface qdisc recorded drops or overlimits") {
		t.Fatalf("baseline-only findings = %+v, want qdisc finding", baselineOnly)
	}
}

func receiveCPUComparisonRecording(firstSoftIRQ, lastSoftIRQ []model.SoftIRQCPUStats, firstCPU, lastCPU []model.CPUTimeStats) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			SoftIRQ:      model.SoftIRQStats{CPUs: firstSoftIRQ},
			CPU:          model.CPUStats{CPUs: firstCPU},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			SoftIRQ:      model.SoftIRQStats{CPUs: lastSoftIRQ},
			CPU:          model.CPUStats{CPUs: lastCPU},
		},
	}}
}

func tcpSocketQueueComparisonRecording(rxQueue, nonZeroRXSockets, txQueue, nonZeroTXSockets uint64) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCPSockets: model.TCPSocketStats{
				RXQueue:          rxQueue,
				NonZeroRXSockets: nonZeroRXSockets,
				TXQueue:          txQueue,
				NonZeroTXSockets: nonZeroTXSockets,
			},
		},
	}}
}

func processComparisonRecording(process *model.ProcessStats) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			Process:      process,
		},
	}}
}

func comparisonFlowRecording(flows []model.TCPRetransmitFlow, truncated bool, flowCount int) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			EBPF:         &model.EBPFStats{},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			EBPF: &model.EBPFStats{
				TCPRetransmitFlows:          flows,
				TCPRetransmitFlowsTruncated: truncated,
				TCPRetransmitFlowCount:      flowCount,
			},
		},
	}}
}

func comparisonNoEBPFRecording() model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second)},
	}}
}

func comparisonFeatureErrorRecording(featureErrors []model.EBPFFeatureError) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			EBPF:         &model.EBPFStats{},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			EBPF:         &model.EBPFStats{FeatureErrors: featureErrors},
		},
	}}
}

func comparisonRecording(retransDelta, qdiscDropDelta uint64, qdiscStatus model.CollectorStatus) model.Recording {
	now := time.Now()
	return model.Recording{
		Version: model.FormatVersion,
		Collectors: []model.CollectorManifest{
			{CollectorName: "proc_tcp", Status: model.CollectorEnabled},
			{CollectorName: "tc_qdisc", Status: qdiscStatus},
		},
		Samples: []model.Sample{
			{
				Timestamp:    now,
				ElapsedNanos: int64(time.Second),
				TCP:          model.TCPStats{OutSegments: 1000, Retransmits: 10},
				Qdisc: model.QdiscStats{Qdiscs: []model.QdiscLineStats{
					{Interface: "eth0", Kind: "netem", Handle: "1", Parent: "root"},
				}},
			},
			{
				Timestamp:    now.Add(time.Second),
				ElapsedNanos: int64(2 * time.Second),
				TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 10 + retransDelta},
				Qdisc: model.QdiscStats{Qdiscs: []model.QdiscLineStats{
					{Interface: "eth0", Kind: "netem", Handle: "1", Parent: "root", Drops: qdiscDropDelta},
				}},
			},
		},
	}
}

func findingSummaries(findings []Finding) []string {
	summaries := make([]string, len(findings))
	for i, finding := range findings {
		summaries[i] = finding.Summary
	}
	return summaries
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
