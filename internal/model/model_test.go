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
		TCPRetransmitEvents: 9,
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
		"tcp_retransmit_flows",
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
		len(got.TCPRetransmitFlows) != 1 ||
		got.TCPRetransmitFlows[0] != want.TCPRetransmitFlows[0] {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}
