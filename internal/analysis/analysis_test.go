package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/eray/netdiag/internal/model"
)

func TestAnalyzeRetransmissions(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 5}},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 2000, Retransmits: 40}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 35}},
	}}
	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(findings[0].Summary, "retransmissions") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	if findings[0].Confidence != "strong correlation" {
		t.Fatalf("unexpected confidence: %s", findings[0].Confidence)
	}
	if got := strings.Join(findings[0].Evidence, " "); !strings.Contains(got, "eBPF observed 30") {
		t.Fatalf("missing eBPF evidence: %s", got)
	}
}

func TestAnalyzeRetransmissionsWithEnabledEBPFFeatureMetadata(t *testing.T) {
	r := retransmissionRecordingWithFeatures([]model.EBPFFeatureStatus{
		{
			Name:            model.EBPFFeatureTCPRetransmitEvents,
			Status:          model.CollectorEnabled,
			VisibilityScope: "host-wide TCP retransmission events",
		},
		{
			Name:            model.EBPFFeatureTCPRetransmitIPv4Flows,
			Status:          model.CollectorEnabled,
			VisibilityScope: "bounded IPv4 TCP retransmission flow counters",
		},
	})

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(evidence, "eBPF observed 30 tcp_retransmit_skb tracepoint events") {
		t.Fatalf("missing eBPF event evidence: %s", evidence)
	}
	if strings.Contains(evidence, "unavailable") || strings.Contains(evidence, "disabled") {
		t.Fatalf("unexpected feature visibility gap evidence: %s", evidence)
	}
}

func TestAnalyzeRetransmissionsReportsUnavailableEBPFFeatures(t *testing.T) {
	now := time.Now()
	r := model.Recording{
		Version: model.FormatVersion,
		EBPFFeatures: []model.EBPFFeatureStatus{
			{
				Name:            model.EBPFFeatureTCPRetransmitEvents,
				Status:          model.CollectorUnavailable,
				VisibilityScope: "host-wide TCP retransmission events",
				Reason:          "load tcp retransmit programs: permission denied",
			},
			{
				Name:            model.EBPFFeatureTCPRetransmitIPv4Flows,
				Status:          model.CollectorUnavailable,
				VisibilityScope: "bounded IPv4 TCP retransmission flow counters",
				Reason:          "load tcp retransmit programs: permission denied",
			},
		},
		Samples: []model.Sample{
			{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}},
			{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 2000, Retransmits: 40}},
		},
	}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"eBPF tcp_retransmit_events unavailable: load tcp retransmit programs: permission denied",
		"eBPF tcp_retransmit_ipv4_flows unavailable: load tcp retransmit programs: permission denied",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing feature visibility evidence %q: %s", want, evidence)
		}
	}
	if strings.Contains(evidence, "eBPF observed") {
		t.Fatalf("unexpected eBPF event evidence when eBPF samples are absent: %s", evidence)
	}
}

func TestAnalyzeRetransmissionsReportsDisabledEBPFFeatures(t *testing.T) {
	now := time.Now()
	r := model.Recording{
		Version: model.FormatVersion,
		EBPFFeatures: []model.EBPFFeatureStatus{
			{
				Name:            model.EBPFFeatureTCPRetransmitEvents,
				Status:          model.CollectorDisabled,
				VisibilityScope: "host-wide TCP retransmission events",
			},
			{
				Name:            model.EBPFFeatureTCPRetransmitIPv4Flows,
				Status:          model.CollectorDisabled,
				VisibilityScope: "bounded IPv4 TCP retransmission flow counters",
			},
		},
		Samples: []model.Sample{
			{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}},
			{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 2000, Retransmits: 40}},
		},
	}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"eBPF tcp_retransmit_events disabled",
		"eBPF tcp_retransmit_ipv4_flows disabled",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing feature visibility evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeRetransmissionsIncludesTopEBPFFlows(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 5}},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 40},
			EBPF: &model.EBPFStats{
				TCPRetransmitEvents: 35,
				TCPRetransmitFlows: []model.TCPRetransmitFlow{
					{SourceAddress: "127.0.0.1", DestinationAddress: "127.0.0.1", SourcePort: 43946, DestinationPort: 40981, Retransmits: 4},
					{SourceAddress: "10.0.0.2", DestinationAddress: "10.0.0.1", SourcePort: 53000, DestinationPort: 443, Retransmits: 2},
				},
				TCPRetransmitFlowCount: 2,
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"Top retransmitting IPv4 flow: 127.0.0.1:43946 -> 127.0.0.1:40981 had 4 retransmits",
		"Top retransmitting IPv4 flow: 10.0.0.2:53000 -> 10.0.0.1:443 had 2 retransmits",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing flow evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeRetransmissionsIncludesFlowTruncationEvidence(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 5}},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 40},
			EBPF: &model.EBPFStats{
				TCPRetransmitEvents: 35,
				TCPRetransmitFlows: []model.TCPRetransmitFlow{
					{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 1000, DestinationPort: 80, Retransmits: 9},
					{SourceAddress: "10.0.0.2", DestinationAddress: "10.0.0.3", SourcePort: 1001, DestinationPort: 80, Retransmits: 8},
					{SourceAddress: "10.0.0.3", DestinationAddress: "10.0.0.4", SourcePort: 1002, DestinationPort: 80, Retransmits: 7},
				},
				TCPRetransmitFlowCount:      12,
				TCPRetransmitFlowsTruncated: true,
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(evidence, "eBPF flow list truncated: showing 3 of 12 observed flow entries") {
		t.Fatalf("missing truncation evidence: %s", evidence)
	}
}

func TestAnalyzeRetransmissionsIncludesFlowOmissionReason(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 5}},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 40},
			EBPF: &model.EBPFStats{
				TCPRetransmitEvents:             35,
				TCPRetransmitFlowCount:          12,
				TCPRetransmitFlowsTruncated:     true,
				TCPRetransmitFlowsOmittedReason: "recording eBPF flow sample budget exhausted",
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"eBPF flow list truncated: showing 0 of 12 observed flow entries",
		"eBPF flow details omitted: recording eBPF flow sample budget exhausted",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing flow omission evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeRetransmissionsIncludesEBPFFeatureErrors(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}, EBPF: &model.EBPFStats{TCPRetransmitEvents: 5}},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 40},
			EBPF: &model.EBPFStats{
				TCPRetransmitEvents: 35,
				FeatureErrors: []model.EBPFFeatureError{
					{Name: model.EBPFFeatureTCPRetransmitIPv4Flows, Error: "iterate tcp retransmit flow map: permission denied"},
				},
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	want := "eBPF tcp_retransmit_ipv4_flows sample error: iterate tcp retransmit flow map: permission denied"
	if !strings.Contains(evidence, want) {
		t.Fatalf("missing eBPF feature error evidence %q: %s", want, evidence)
	}
}

func TestAnalyzeReportsTCPSocketReceiveQueueGrowth(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			TCPSockets:   model.TCPSocketStats{RXQueue: 1024},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCPSockets: model.TCPSocketStats{
				RXQueue:          1024 + 70*1024,
				MaxRXQueue:       48 * 1024,
				NonZeroRXSockets: 2,
				TopQueues: []model.TCPSocketQueue{
					{
						Protocol:      "tcp4",
						LocalAddress:  "127.0.0.1",
						LocalPort:     8080,
						RemoteAddress: "127.0.0.1",
						RemotePort:    50000,
						State:         "01",
						RXQueue:       48 * 1024,
					},
				},
				TopQueuesTruncated: true,
				SocketQueueCount:   4,
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	if findings[0].Summary != "TCP socket receive queues grew during the capture" {
		t.Fatalf("finding summary = %q", findings[0].Summary)
	}
	if findings[0].Severity != "warning" || findings[0].Confidence != "possible" {
		t.Fatalf("finding severity/confidence = %s/%s", findings[0].Severity, findings[0].Confidence)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"TCP receive queues increased by 71680 bytes",
		"2 sockets had non-zero receive queues at peak",
		"largest observed receive queue was 49152 bytes",
		"Top TCP socket receive queue: tcp4 127.0.0.1:8080 -> 127.0.0.1:50000 state 01 had 49152 bytes queued",
		"TCP socket queue list truncated: showing 1 of 4 sockets with queued bytes",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing socket queue evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeReportsTransientTCPSocketReceiveQueueGrowth(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCPSockets: model.TCPSocketStats{
				RXQueue:          128 * 1024,
				MaxRXQueue:       128 * 1024,
				NonZeroRXSockets: 1,
				TopQueues: []model.TCPSocketQueue{
					{Protocol: "tcp4", LocalAddress: "127.0.0.1", LocalPort: 8080, RemoteAddress: "127.0.0.1", RemotePort: 50000, State: "01", RXQueue: 128 * 1024},
				},
				SocketQueueCount: 1,
			},
		},
		{Timestamp: now.Add(2 * time.Second), ElapsedNanos: int64(3 * time.Second)},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	if findings[0].Summary != "TCP socket receive queues grew during the capture" {
		t.Fatalf("finding summary = %q", findings[0].Summary)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"TCP receive queues increased by 131072 bytes",
		"Top TCP socket receive queue: tcp4 127.0.0.1:8080 -> 127.0.0.1:50000 state 01 had 131072 bytes queued",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing transient socket queue evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeIgnoresSmallTCPSocketReceiveQueueGrowth(t *testing.T) {
	r := tcpSocketQueueRecording(1024, 1024+32*1024, 1, 0, 0, 0)
	assertNoTCPSocketQueueFinding(t, r)
}

func TestAnalyzeIgnoresDecreasedTCPSocketReceiveQueue(t *testing.T) {
	r := tcpSocketQueueRecording(128*1024, 64*1024, 1, 0, 0, 0)
	assertNoTCPSocketQueueFinding(t, r)
}

func TestAnalyzeReportsTCPSocketTransmitQueueGrowth(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			TCPSockets:   model.TCPSocketStats{TXQueue: 2048},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCPSockets: model.TCPSocketStats{
				TXQueue:          2048 + 80*1024,
				MaxTXQueue:       64 * 1024,
				NonZeroTXSockets: 1,
				TopQueues: []model.TCPSocketQueue{
					{
						Protocol:      "tcp4",
						LocalAddress:  "127.0.0.1",
						LocalPort:     8080,
						RemoteAddress: "127.0.0.1",
						RemotePort:    50000,
						State:         "01",
						TXQueue:       64 * 1024,
					},
				},
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	if findings[0].Summary != "TCP socket transmit queues grew during the capture" {
		t.Fatalf("finding summary = %q", findings[0].Summary)
	}
	if findings[0].Severity != "warning" || findings[0].Confidence != "possible" {
		t.Fatalf("finding severity/confidence = %s/%s", findings[0].Severity, findings[0].Confidence)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"TCP transmit queues increased by 81920 bytes",
		"1 sockets had non-zero transmit queues at peak",
		"largest observed transmit queue was 65536 bytes",
		"Top TCP socket transmit queue: tcp4 127.0.0.1:8080 -> 127.0.0.1:50000 state 01 had 65536 bytes queued",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing socket queue evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeIgnoresSmallTCPSocketTransmitQueueGrowth(t *testing.T) {
	r := tcpSocketQueueRecording(0, 0, 0, 1024, 1024+32*1024, 1)
	assertNoTCPSocketQueueFinding(t, r)
}

func TestAnalyzeIgnoresDecreasedTCPSocketTransmitQueue(t *testing.T) {
	r := tcpSocketQueueRecording(0, 0, 0, 128*1024, 64*1024, 1)
	assertNoTCPSocketQueueFinding(t, r)
}

func TestAnalyzeReportsProcessRunqueueWaitGrowth(t *testing.T) {
	r := processSchedstatRecording(
		model.ProcessStats{PID: 123, RuntimeNanos: uint64(100 * time.Millisecond), RunqueueWaitNanos: uint64(5 * time.Millisecond), Timeslices: 10},
		model.ProcessStats{PID: 123, RuntimeNanos: uint64(175 * time.Millisecond), RunqueueWaitNanos: uint64(20 * time.Millisecond), Timeslices: 13},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}

	if findings[0].Summary != "Selected process accumulated runqueue wait time" {
		t.Fatalf("finding summary = %q", findings[0].Summary)
	}
	if findings[0].Severity != "warning" || findings[0].Confidence != "possible" {
		t.Fatalf("finding severity/confidence = %s/%s", findings[0].Severity, findings[0].Confidence)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	for _, want := range []string{
		"process 123 runqueue wait increased by 15.0 ms",
		"process 123 ran for 75.0 ms across 3 timeslices",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing process schedstat evidence %q: %s", want, evidence)
		}
	}
}

func TestAnalyzeIgnoresSmallProcessRunqueueWaitGrowth(t *testing.T) {
	r := processSchedstatRecording(
		model.ProcessStats{PID: 123, RuntimeNanos: uint64(100 * time.Millisecond), RunqueueWaitNanos: uint64(5 * time.Millisecond), Timeslices: 10},
		model.ProcessStats{PID: 123, RuntimeNanos: uint64(175 * time.Millisecond), RunqueueWaitNanos: uint64(9 * time.Millisecond), Timeslices: 13},
	)
	assertNoProcessSchedstatFinding(t, r)
}

func TestAnalyzeIgnoresMissingProcessSchedstat(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second)},
	}}
	assertNoProcessSchedstatFinding(t, r)
}

func TestAnalyzeRejectsShortRecording(t *testing.T) {
	_, err := Analyze(model.Recording{Version: model.FormatVersion, Samples: []model.Sample{{}}})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestAnalyzeReportsCounterResets(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			TCP:          model.TCPStats{InSegments: 100, OutSegments: 100, Retransmits: 10, InErrors: 2},
			SoftIRQ:      model.SoftIRQStats{NetRX: 100, NetTX: 100},
			Interface:    &model.InterfaceStats{RXPackets: 100, TXPackets: 100},
			EBPF:         &model.EBPFStats{TCPRetransmitEvents: 10},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCP:          model.TCPStats{InSegments: 1, OutSegments: 1, Retransmits: 1, InErrors: 0},
			SoftIRQ:      model.SoftIRQStats{NetRX: 1, NetTX: 1},
			Interface:    &model.InterfaceStats{RXPackets: 1, TXPackets: 1},
			EBPF:         &model.EBPFStats{TCPRetransmitEvents: 1},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(findings[0].Summary, "counters reset") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(evidence, "elapsed 1s") || !strings.Contains(evidence, "elapsed 2s") {
		t.Errorf("reset evidence does not use elapsed time: %s", evidence)
	}
	for _, group := range []string{"TCP", "softirq", "interface", "eBPF"} {
		if !strings.Contains(evidence, group) {
			t.Errorf("missing %s reset evidence: %s", group, evidence)
		}
	}
}

func TestAnalyzeDetectsResetBetweenIntermediateSamples(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 100}},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 10}},
		{Timestamp: now.Add(2 * time.Second), ElapsedNanos: int64(3 * time.Second), TCP: model.TCPStats{OutSegments: 200}},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(findings[0].Summary, "counters reset") {
		t.Fatalf("intermediate reset was not reported: %+v", findings)
	}
}

func TestAnalyzeReportsPerCPUSoftIRQReset(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			SoftIRQ: model.SoftIRQStats{
				NetRX: 30,
				NetTX: 30,
				CPUs: []model.SoftIRQCPUStats{
					{CPU: 0, NetRX: 10, NetTX: 10},
					{CPU: 1, NetRX: 20, NetTX: 20},
				},
			},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			SoftIRQ: model.SoftIRQStats{
				NetRX: 17,
				NetTX: 17,
				CPUs: []model.SoftIRQCPUStats{
					{CPU: 0, NetRX: 11, NetTX: 11},
					{CPU: 1, NetRX: 6, NetTX: 6},
				},
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(evidence, "softirq CPU1 counter decreased") {
		t.Fatalf("missing per-CPU softirq reset evidence: %s", evidence)
	}
}

func TestAnalyzeDoesNotTreatSoftIRQCPUSetChangeAsReset(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			SoftIRQ: model.SoftIRQStats{
				NetRX: 300,
				NetTX: 300,
				CPUs: []model.SoftIRQCPUStats{
					{CPU: 0, NetRX: 100, NetTX: 100},
					{CPU: 1, NetRX: 200, NetTX: 200},
				},
			},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			SoftIRQ: model.SoftIRQStats{
				NetRX: 60,
				NetTX: 60,
				CPUs: []model.SoftIRQCPUStats{
					{CPU: 0, NetRX: 50, NetTX: 50},
					{CPU: 2, NetRX: 10, NetTX: 10},
				},
			},
		},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if strings.Contains(evidence, "softirq") || strings.Contains(findings[0].Summary, "counters reset") {
		t.Fatalf("CPU set change was treated as a reset: %+v", findings)
	}
}

func TestAnalyzeReportsReceiveCPUConcentration(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{
			{CPU: 0, NetRX: 1000},
			{CPU: 1, NetRX: 1000},
			{CPU: 2, NetRX: 1000},
		},
		[]model.SoftIRQCPUStats{
			{CPU: 0, NetRX: 1050},
			{CPU: 1, NetRX: 1050},
			{CPU: 2, NetRX: 2900},
		},
		[]model.CPUTimeStats{
			cpuTime(0, 100, 900),
			cpuTime(1, 100, 900),
			cpuTime(2, 100, 900),
		},
		[]model.CPUTimeStats{
			cpuTime(0, 300, 1700),
			cpuTime(1, 300, 1700),
			cpuTime(2, 900, 1100),
		},
	)
	r.Samples[0].IRQ = model.IRQStats{IRQs: []model.IRQLineStats{
		{IRQ: "32", CPUs: []int{0, 1, 2}, Counts: []uint64{10, 20, 30}},
	}}
	r.Samples[1].IRQ = model.IRQStats{IRQs: []model.IRQLineStats{
		{IRQ: "32", CPUs: []int{0, 1, 2}, Counts: []uint64{10, 20, 130}},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	var found *Finding
	for i := range findings {
		if findings[i].Summary == "Network receive processing was concentrated on a busy CPU" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("missing receive CPU concentration finding: %+v", findings)
	}
	evidence := strings.Join(found.Evidence, " ")
	for _, want := range []string{"CPU2 handled 95.0%", "CPU2 was 80.0%", "IRQ counts also increased on CPU2 by 100"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing evidence %q in %q", want, evidence)
		}
	}
}

func TestAnalyzeDoesNotReportReceiveCPUConcentrationBelowSoftIRQThreshold(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1000}, {CPU: 1, NetRX: 1000}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1010}, {CPU: 1, NetRX: 1900}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 300, 1700), cpuTime(1, 900, 1100)},
	)

	assertNoReceiveCPUConcentration(t, r)
}

func TestAnalyzeDoesNotReportReceiveCPUConcentrationWhenCPUIsMostlyIdle(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1000}, {CPU: 1, NetRX: 1000}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1100}, {CPU: 1, NetRX: 2900}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 300, 1700), cpuTime(1, 300, 1700)},
	)

	assertNoReceiveCPUConcentration(t, r)
}

func TestAnalyzeDoesNotReportReceiveCPUConcentrationWhenCPUSetChanged(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1000}, {CPU: 1, NetRX: 1000}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1100}, {CPU: 1, NetRX: 2900}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 300, 1700), cpuTime(2, 900, 1100)},
	)

	assertNoReceiveCPUConcentration(t, r)
}

func TestAnalyzeDoesNotReportReceiveCPUConcentrationWhenSoftIRQSetChanged(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1000}, {CPU: 1, NetRX: 1000}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1100}, {CPU: 2, NetRX: 2900}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900), cpuTime(2, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 300, 1700), cpuTime(1, 300, 1700), cpuTime(2, 900, 1100)},
	)

	assertNoReceiveCPUConcentration(t, r)
}

func TestAnalyzeDoesNotReportReceiveCPUConcentrationWhenSoftIRQResetDetected(t *testing.T) {
	r := concentrationRecording(
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1000}, {CPU: 1, NetRX: 3000}},
		[]model.SoftIRQCPUStats{{CPU: 0, NetRX: 1100}, {CPU: 1, NetRX: 2900}},
		[]model.CPUTimeStats{cpuTime(0, 100, 900), cpuTime(1, 100, 900)},
		[]model.CPUTimeStats{cpuTime(0, 300, 1700), cpuTime(1, 900, 1100)},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(findings[0].Summary, "counters reset") || !strings.Contains(evidence, "softirq CPU1") {
		t.Fatalf("expected softirq reset finding: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Summary == "Network receive processing was concentrated on a busy CPU" {
			t.Fatalf("unexpected receive CPU concentration finding with softirq reset: %+v", findings)
		}
	}
}

func TestAnalyzeReportsQdiscDrops(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 1000, 100, 0, 0, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 2000, 200, 882, 0, 0, 1),
		},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	var found *Finding
	for i := range findings {
		if findings[i].Summary == "The selected interface qdisc recorded drops or overlimits" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("missing qdisc finding: %+v", findings)
	}
	evidence := strings.Join(found.Evidence, " ")
	for _, want := range []string{"qdisc netem on eth0 recorded 882 drops and 0 overlimits", "qdisc backlog ended at 1 packets"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("missing evidence %q in %q", want, evidence)
		}
	}
}

func TestAnalyzeReportsQdiscOverlimits(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "htb", "1", "root", 1000, 100, 0, 2, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "htb", "1", "root", 2000, 200, 0, 7, 0, 0),
		},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if findings[0].Summary != "The selected interface qdisc recorded drops or overlimits" ||
		!strings.Contains(evidence, "0 drops and 5 overlimits") {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestAnalyzeDoesNotReportQdiscFindingWhenCountersDoNotIncrease(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 1000, 100, 0, 0, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 2000, 200, 0, 0, 0, 0),
		},
	)

	assertNoQdiscFinding(t, r)
}

func TestAnalyzeReportsQdiscCounterReset(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 2000, 200, 10, 0, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 1000, 100, 1, 0, 0, 0),
		},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	evidence := strings.Join(findings[0].Evidence, " ")
	if !strings.Contains(findings[0].Summary, "counters reset") || !strings.Contains(evidence, "qdisc netem on eth0 counter decreased") {
		t.Fatalf("expected qdisc reset finding: %+v", findings)
	}
}

func TestAnalyzeSuppressesQdiscFindingWhenQdiscResetDetected(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 2000, 200, 10, 0, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 1000, 100, 20, 0, 0, 0),
		},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Summary == "The selected interface qdisc recorded drops or overlimits" {
			t.Fatalf("unexpected qdisc finding with reset: %+v", findings)
		}
	}
}

func TestAnalyzeSuppressesQdiscFindingWhenQdiscSetChanged(t *testing.T) {
	r := qdiscRecording(
		[]model.QdiscLineStats{
			qdiscLine("eth0", "fq_codel", "0", "root", 1000, 100, 0, 0, 0, 0),
		},
		[]model.QdiscLineStats{
			qdiscLine("eth0", "netem", "8001", "root", 2000, 200, 10, 0, 0, 0),
		},
	)

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Summary, "qdisc") || strings.Contains(strings.Join(finding.Evidence, " "), "qdisc") {
			t.Fatalf("qdisc set change produced qdisc finding/reset: %+v", findings)
		}
	}
}

func TestAnalyzeUsesElapsedTimeWhenWallClockMovesBackward(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second)},
		{Timestamp: now.Add(-time.Hour), ElapsedNanos: int64(2 * time.Second)},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if evidence := strings.Join(findings[0].Evidence, " "); !strings.Contains(evidence, "across 1.0 seconds") {
		t.Fatalf("duration did not use elapsed time: %s", evidence)
	}
}

func concentrationRecording(firstSoftIRQ, lastSoftIRQ []model.SoftIRQCPUStats, firstCPU, lastCPU []model.CPUTimeStats) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			SoftIRQ: model.SoftIRQStats{
				CPUs: firstSoftIRQ,
			},
			CPU: model.CPUStats{
				CPUs: firstCPU,
			},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			SoftIRQ: model.SoftIRQStats{
				CPUs: lastSoftIRQ,
			},
			CPU: model.CPUStats{
				CPUs: lastCPU,
			},
		},
	}}
}

func cpuTime(cpu int, busy, idle uint64) model.CPUTimeStats {
	return model.CPUTimeStats{CPU: cpu, User: busy, Idle: idle}
}

func assertNoReceiveCPUConcentration(t *testing.T, r model.Recording) {
	t.Helper()
	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Summary == "Network receive processing was concentrated on a busy CPU" {
			t.Fatalf("unexpected receive CPU concentration finding: %+v", findings)
		}
	}
}

func qdiscRecording(firstQdiscs, lastQdiscs []model.QdiscLineStats) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			Qdisc:        model.QdiscStats{Qdiscs: firstQdiscs},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			Qdisc:        model.QdiscStats{Qdiscs: lastQdiscs},
		},
	}}
}

func qdiscLine(iface, kind, handle, parent string, bytes, packets, drops, overlimits, requeues, backlogPackets uint64) model.QdiscLineStats {
	return model.QdiscLineStats{
		Interface:      iface,
		Kind:           kind,
		Handle:         handle,
		Parent:         parent,
		Bytes:          bytes,
		Packets:        packets,
		Drops:          drops,
		Overlimits:     overlimits,
		Requeues:       requeues,
		BacklogPackets: backlogPackets,
	}
}

func assertNoQdiscFinding(t *testing.T, r model.Recording) {
	t.Helper()
	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Summary == "The selected interface qdisc recorded drops or overlimits" {
			t.Fatalf("unexpected qdisc finding: %+v", findings)
		}
	}
}

func tcpSocketQueueRecording(firstRXQueue, lastRXQueue, lastNonZeroRXSockets, firstTXQueue, lastTXQueue, lastNonZeroTXSockets uint64) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			TCPSockets: model.TCPSocketStats{
				RXQueue: firstRXQueue,
				TXQueue: firstTXQueue,
			},
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			TCPSockets: model.TCPSocketStats{
				RXQueue:          lastRXQueue,
				NonZeroRXSockets: lastNonZeroRXSockets,
				TXQueue:          lastTXQueue,
				NonZeroTXSockets: lastNonZeroTXSockets,
			},
		},
	}}
}

func assertNoTCPSocketQueueFinding(t *testing.T, r model.Recording) {
	t.Helper()
	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Summary == "TCP socket receive queues grew during the capture" ||
			finding.Summary == "TCP socket transmit queues grew during the capture" {
			t.Fatalf("unexpected TCP socket queue finding: %+v", findings)
		}
	}
}

func processSchedstatRecording(firstProcess, lastProcess model.ProcessStats) model.Recording {
	now := time.Now()
	return model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{
			Timestamp:    now,
			ElapsedNanos: int64(time.Second),
			Process:      &firstProcess,
		},
		{
			Timestamp:    now.Add(time.Second),
			ElapsedNanos: int64(2 * time.Second),
			Process:      &lastProcess,
		},
	}}
}

func assertNoProcessSchedstatFinding(t *testing.T, r model.Recording) {
	t.Helper()
	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Summary == "Selected process accumulated runqueue wait time" {
			t.Fatalf("unexpected process schedstat finding: %+v", findings)
		}
	}
}

func retransmissionRecordingWithFeatures(features []model.EBPFFeatureStatus) model.Recording {
	now := time.Now()
	return model.Recording{
		Version:      model.FormatVersion,
		EBPFFeatures: features,
		Samples: []model.Sample{
			{
				Timestamp:    now,
				ElapsedNanos: int64(time.Second),
				TCP:          model.TCPStats{OutSegments: 1000, Retransmits: 10},
				EBPF:         &model.EBPFStats{TCPRetransmitEvents: 5},
			},
			{
				Timestamp:    now.Add(time.Second),
				ElapsedNanos: int64(2 * time.Second),
				TCP:          model.TCPStats{OutSegments: 2000, Retransmits: 40},
				EBPF:         &model.EBPFStats{TCPRetransmitEvents: 35},
			},
		},
	}
}

func TestAnalyzeIgnoresForwardWallClockJump(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), Interface: &model.InterfaceStats{}},
		{Timestamp: now.Add(24 * time.Hour), ElapsedNanos: int64(3 * time.Second), Interface: &model.InterfaceStats{RXDropped: 1}},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if evidence := strings.Join(findings[0].Evidence, " "); !strings.Contains(evidence, "over 2.0 seconds") {
		t.Fatalf("duration did not use elapsed time: %s", evidence)
	}
}

func TestAnalyzeRejectsInvalidElapsedTime(t *testing.T) {
	tests := []struct {
		name    string
		elapsed []int64
	}{
		{name: "equal", elapsed: []int64{1, 1}},
		{name: "decreasing", elapsed: []int64{2, 1}},
		{name: "intermediate decrease", elapsed: []int64{1, 3, 2, 4}},
		{name: "negative start", elapsed: []int64{-1, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples := make([]model.Sample, len(tt.elapsed))
			for i, elapsed := range tt.elapsed {
				samples[i] = model.Sample{Timestamp: time.Now().Add(time.Duration(i) * time.Second), ElapsedNanos: elapsed}
			}
			if _, err := Analyze(model.Recording{Version: model.FormatVersion, Samples: samples}); err == nil {
				t.Fatal("expected invalid elapsed time error")
			}
		})
	}
}

func TestAnalyzeLegacyRecordingUsesWallClockTime(t *testing.T) {
	now := time.Now()
	r := model.Recording{Version: 2, Samples: []model.Sample{
		{Timestamp: now},
		{Timestamp: now.Add(2 * time.Second)},
	}}

	findings, err := Analyze(r)
	if err != nil {
		t.Fatal(err)
	}
	if evidence := strings.Join(findings[0].Evidence, " "); !strings.Contains(evidence, "across 2.0 seconds") {
		t.Fatalf("legacy duration did not use wall time: %s", evidence)
	}
}
