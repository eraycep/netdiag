package ebpfcollector

import (
	"reflect"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestRetransmitFlowFromBPFConvertsAddressesAndPorts(t *testing.T) {
	got := retransmitFlowFromBPF(
		tcpRetransmitFlow4Key{
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
