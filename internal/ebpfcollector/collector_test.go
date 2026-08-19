package ebpfcollector

import (
	"reflect"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestRetransmitFlowFromBPFConvertsAddressesAndPorts(t *testing.T) {
	got := retransmitFlowFromBPF(
		tcpRetransmitFlowKeyIpv4{
			Saddr: 0x0100007f,
			Daddr: 0x0200007f,
			Sport: 43210,
			Dport: 12345,
		},
		tcpRetransmitNetdiagFlowStats{Retransmits: 7},
	)

	want := model.TCPRetransmitFlow{
		SourceAddress:      "127.0.0.1",
		DestinationAddress: "127.0.0.2",
		SourcePort:         43210,
		DestinationPort:    12345,
		Retransmits:        7,
	}
	if got != want {
		t.Fatalf("flow = %+v, want %+v", got, want)
	}
}

func TestSortRetransmitFlowsDeterministic(t *testing.T) {
	flows := []model.TCPRetransmitFlow{
		{SourceAddress: "10.0.0.2", DestinationAddress: "10.0.0.1", SourcePort: 2000, DestinationPort: 80, Retransmits: 3},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 3000, DestinationPort: 80, Retransmits: 3},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 443, Retransmits: 3},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 80, Retransmits: 5},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 80, Retransmits: 3},
	}

	sortRetransmitFlows(flows)

	want := []model.TCPRetransmitFlow{
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 80, Retransmits: 5},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 80, Retransmits: 3},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 2000, DestinationPort: 443, Retransmits: 3},
		{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", SourcePort: 3000, DestinationPort: 80, Retransmits: 3},
		{SourceAddress: "10.0.0.2", DestinationAddress: "10.0.0.1", SourcePort: 2000, DestinationPort: 80, Retransmits: 3},
	}
	if !reflect.DeepEqual(flows, want) {
		t.Fatalf("sorted flows = %+v, want %+v", flows, want)
	}
}

func TestLimitRetransmitFlows(t *testing.T) {
	flows := []model.TCPRetransmitFlow{
		{SourceAddress: "10.0.0.1", Retransmits: 3},
		{SourceAddress: "10.0.0.2", Retransmits: 2},
		{SourceAddress: "10.0.0.3", Retransmits: 1},
	}

	tests := []struct {
		name          string
		max           int
		wantFlows     []model.TCPRetransmitFlow
		wantCount     int
		wantTruncated bool
	}{
		{
			name:          "zero omits flows but reports truncation",
			max:           0,
			wantFlows:     nil,
			wantCount:     3,
			wantTruncated: true,
		},
		{
			name:          "larger than length returns all",
			max:           10,
			wantFlows:     flows,
			wantCount:     3,
			wantTruncated: false,
		},
		{
			name:          "smaller than length truncates",
			max:           2,
			wantFlows:     flows[:2],
			wantCount:     3,
			wantTruncated: true,
		},
		{
			name:          "exact length returns all",
			max:           3,
			wantFlows:     flows,
			wantCount:     3,
			wantTruncated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlows, gotCount, gotTruncated := limitRetransmitFlows(flows, tt.max)
			if !reflect.DeepEqual(gotFlows, tt.wantFlows) || gotCount != tt.wantCount || gotTruncated != tt.wantTruncated {
				t.Fatalf("limit = (%+v, %d, %v), want (%+v, %d, %v)", gotFlows, gotCount, gotTruncated, tt.wantFlows, tt.wantCount, tt.wantTruncated)
			}
		})
	}
}

func TestLimitRetransmitFlowsZeroEmptyInput(t *testing.T) {
	gotFlows, gotCount, gotTruncated := limitRetransmitFlows(nil, 0)
	if gotFlows != nil || gotCount != 0 || gotTruncated {
		t.Fatalf("limit empty = (%+v, %d, %v), want (nil, 0, false)", gotFlows, gotCount, gotTruncated)
	}
}

func TestFeatureStatusHelpersReturnFreshStatuses(t *testing.T) {
	enabled := EnabledFeatures()
	unavailable := UnavailableFeatures("permission denied")
	disabled := DisabledFeatures()

	if len(enabled) != 2 || len(unavailable) != 2 || len(disabled) != 2 {
		t.Fatalf("feature counts = enabled %d unavailable %d disabled %d, want all 2", len(enabled), len(unavailable), len(disabled))
	}

	for _, feature := range enabled {
		if feature.Status != model.CollectorEnabled || feature.Reason != "" {
			t.Fatalf("enabled feature = %+v, want enabled without reason", feature)
		}
		if feature.Name == "" || feature.VisibilityScope == "" {
			t.Fatalf("enabled feature missing identity or scope: %+v", feature)
		}
	}
	for _, feature := range unavailable {
		if feature.Status != model.CollectorUnavailable || feature.Reason != "permission denied" {
			t.Fatalf("unavailable feature = %+v, want unavailable with reason", feature)
		}
	}
	for _, feature := range disabled {
		if feature.Status != model.CollectorDisabled || feature.Reason != "" {
			t.Fatalf("disabled feature = %+v, want disabled without reason", feature)
		}
	}

	enabled[0].Status = model.CollectorUnavailable
	if got := EnabledFeatures()[0].Status; got != model.CollectorEnabled {
		t.Fatalf("feature helper leaked mutable state: got %q, want %q", got, model.CollectorEnabled)
	}
}

func TestCollectorFeaturesReturnsEnabledFeatureStatuses(t *testing.T) {
	var collector Collector

	features := collector.Features()

	if len(features) != 2 {
		t.Fatalf("feature count = %d, want 2", len(features))
	}

	wantNames := map[string]struct{}{
		model.EBPFFeatureTCPRetransmitEvents:    {},
		model.EBPFFeatureTCPRetransmitIPv4Flows: {},
	}
	for _, feature := range features {
		if _, ok := wantNames[feature.Name]; !ok {
			t.Fatalf("unexpected feature name: %+v", feature)
		}
		if feature.Status != model.CollectorEnabled {
			t.Fatalf("feature %s status = %q, want %q", feature.Name, feature.Status, model.CollectorEnabled)
		}
		if feature.Reason != "" {
			t.Fatalf("feature %s reason = %q, want empty", feature.Name, feature.Reason)
		}
		if feature.VisibilityScope == "" {
			t.Fatalf("feature %s has empty visibility scope", feature.Name)
		}
		delete(wantNames, feature.Name)
	}
	if len(wantNames) != 0 {
		t.Fatalf("missing feature names: %+v", wantNames)
	}

	features[0].Status = model.CollectorUnavailable
	if got := collector.Features()[0].Status; got != model.CollectorEnabled {
		t.Fatalf("collector features leaked mutable state: got %q, want %q", got, model.CollectorEnabled)
	}
}
