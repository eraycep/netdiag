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
