package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectorManifestJSONOmitsEmptyFailureReason(t *testing.T) {
	manifest := CollectorManifest{
		CollectorName:   "proc_tcp",
		Status:          CollectorEnabled,
		VisibilityScope: "host-wide TCP counters",
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "failure_reason") {
		t.Fatalf("empty failure reason was serialized: %s", data)
	}
}

func TestCollectorManifestJSONRoundTrip(t *testing.T) {
	want := CollectorManifest{
		CollectorName:   "ebpf_tcp_retransmit",
		Status:          CollectorUnavailable,
		VisibilityScope: "host-wide TCP retransmission events",
		FailureReason:   "permission denied",
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got CollectorManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestEBPFStatsJSONIncludesRetransmitFlows(t *testing.T) {
	want := EBPFStats{
		TCPRetransmitEvents:         9,
		TCPRetransmitFlowCount:      2,
		TCPRetransmitFlowsTruncated: true,
		TCPRetransmitFlows: []TCPRetransmitFlow{
			{
				SourceAddress:      "127.0.0.1",
				DestinationAddress: "127.0.0.2",
				SourcePort:         43210,
				DestinationPort:    8080,
				Retransmits:        3,
			},
		},
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"tcp_retransmit_events",
		"tcp_retransmit_flow_count",
		"tcp_retransmit_flows",
		"tcp_retransmit_flows_truncated",
		"source_address",
		"destination_address",
		"source_port",
		"destination_port",
		"retransmits",
	} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("serialized eBPF stats missing %q: %s", field, data)
		}
	}

	var got EBPFStats
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.TCPRetransmitEvents != want.TCPRetransmitEvents ||
		got.TCPRetransmitFlowCount != want.TCPRetransmitFlowCount ||
		got.TCPRetransmitFlowsTruncated != want.TCPRetransmitFlowsTruncated ||
		len(got.TCPRetransmitFlows) != 1 ||
		got.TCPRetransmitFlows[0] != want.TCPRetransmitFlows[0] {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestEBPFFeatureStatusJSONOmitsEmptyReason(t *testing.T) {
	feature := EBPFFeatureStatus{
		Name:            "tcp_retransmit_events",
		Status:          CollectorEnabled,
		VisibilityScope: "host-wide TCP retransmission events",
	}

	data, err := json.Marshal(feature)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "reason") {
		t.Fatalf("empty feature reason was serialized: %s", data)
	}
	if !strings.Contains(string(data), `"status":"enabled"`) {
		t.Fatalf("feature status was not serialized as collector status: %s", data)
	}
}

func TestRecordingJSONIncludesEBPFFeatures(t *testing.T) {
	recording := Recording{
		Version: FormatVersion,
		EBPFFeatures: []EBPFFeatureStatus{
			{
				Name:            "tcp_retransmit_ipv4_flows",
				Status:          CollectorUnavailable,
				VisibilityScope: "bounded IPv4 TCP retransmission flow counters",
				Reason:          "permission denied",
			},
		},
	}

	data, err := json.Marshal(recording)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"ebpf_features",
		"tcp_retransmit_ipv4_flows",
		"unavailable",
		"permission denied",
	} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("serialized recording missing %q: %s", field, data)
		}
	}

	var got Recording
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.EBPFFeatures) != 1 || got.EBPFFeatures[0] != recording.EBPFFeatures[0] {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got.EBPFFeatures, recording.EBPFFeatures)
	}
}
