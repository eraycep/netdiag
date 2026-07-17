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
