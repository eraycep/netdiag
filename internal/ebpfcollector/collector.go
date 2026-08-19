package ebpfcollector

import (
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/eray/netdiag/internal/model"
)

// Collector counts kernel TCP retransmit tracepoint events. It deliberately
// keeps no packet payloads or process identifiers.
type Collector struct {
	objects tcpRetransmitObjects
	link    link.Link
}

var featureDefinitions = []model.EBPFFeatureStatus{
	{
		Name:            model.EBPFFeatureTCPRetransmitEvents,
		VisibilityScope: "host-wide TCP retransmission events",
	},
	{
		Name:            model.EBPFFeatureTCPRetransmitIPv4Flows,
		VisibilityScope: "bounded IPv4 TCP retransmission flow counters",
	},
}

func New() (*Collector, error) {
	var objects tcpRetransmitObjects
	if err := loadTcpRetransmitObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("load tcp retransmit programs: %w", err)
	}

	tracepoint, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objects.CountTcpRetransmit, nil)
	if err != nil {
		objects.Close()
		return nil, fmt.Errorf("attach tcp_retransmit_skb tracepoint: %w", err)
	}

	return &Collector{objects: objects, link: tracepoint}, nil
}

func (c *Collector) Sample(maxFlows int) (model.EBPFStats, error) {
	if c == nil {
		return model.EBPFStats{}, errors.New("eBPF collector is not initialized")
	}
	var key uint32
	var count uint64
	if err := c.objects.RetransmitCount.Lookup(&key, &count); err != nil {
		return model.EBPFStats{}, fmt.Errorf("read retransmit counter: %w", err)
	}
	if maxFlows < 0 {
		return model.EBPFStats{}, errors.New("max flows must be non-negative")
	}

	flows, err := c.TCPRetransmitFlows()
	if err != nil {
		// Per-flow attribution is best-effort. Keep the host-wide eBPF signal
		// available if the flow map cannot be read, and make the degraded
		// per-flow feature visible in the sample.
		return model.EBPFStats{
			TCPRetransmitEvents: count,
			FeatureErrors: []model.EBPFFeatureError{
				{Name: model.EBPFFeatureTCPRetransmitIPv4Flows, Error: err.Error()},
			},
		}, nil
	}
	limitedFlows, flowCount, truncated := limitRetransmitFlows(flows, maxFlows)

	return model.EBPFStats{TCPRetransmitEvents: count, TCPRetransmitFlows: limitedFlows, TCPRetransmitFlowsTruncated: truncated, TCPRetransmitFlowCount: flowCount}, nil
}

func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.link.Close(), c.objects.Close())
}

func (c *Collector) Features() []model.EBPFFeatureStatus {
	return EnabledFeatures()
}

func ipv4String(addr uint32) string {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

func retransmitFlowFromBPF(key tcpRetransmitFlowKeyIpv4, value tcpRetransmitNetdiagFlowStats) model.TCPRetransmitFlow {
	return model.TCPRetransmitFlow{
		SourceAddress:      ipv4String(key.Saddr),
		DestinationAddress: ipv4String(key.Daddr),
		SourcePort:         key.Sport,
		DestinationPort:    key.Dport,
		Retransmits:        value.Retransmits,
	}
}

func (c *Collector) TCPRetransmitFlows() ([]model.TCPRetransmitFlow, error) {
	iter := c.objects.TcpRetransmitFlowsIpv4.Iterate()

	var key tcpRetransmitFlowKeyIpv4
	var value tcpRetransmitNetdiagFlowStats
	var flows []model.TCPRetransmitFlow

	for iter.Next(&key, &value) {
		flows = append(flows, retransmitFlowFromBPF(key, value))
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate tcp retransmit flow map: %w", err)
	}

	sortRetransmitFlows(flows)

	return flows, nil
}

func sortRetransmitFlows(flows []model.TCPRetransmitFlow) {
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Retransmits != flows[j].Retransmits {
			return flows[i].Retransmits > flows[j].Retransmits
		}
		if flows[i].SourceAddress != flows[j].SourceAddress {
			return flows[i].SourceAddress < flows[j].SourceAddress
		}
		if flows[i].DestinationAddress != flows[j].DestinationAddress {
			return flows[i].DestinationAddress < flows[j].DestinationAddress
		}
		if flows[i].SourcePort != flows[j].SourcePort {
			return flows[i].SourcePort < flows[j].SourcePort
		}
		return flows[i].DestinationPort < flows[j].DestinationPort
	})
}

func limitRetransmitFlows(flows []model.TCPRetransmitFlow, max int) ([]model.TCPRetransmitFlow, int, bool) {
	count := len(flows)
	if max >= count {
		return flows, count, false
	}
	if max == 0 {
		return nil, count, count > 0
	}
	return flows[:max], count, true
}

func EnabledFeatures() []model.EBPFFeatureStatus {
	return featuresWithStatus(model.CollectorEnabled, "")
}

func UnavailableFeatures(reason string) []model.EBPFFeatureStatus {
	return featuresWithStatus(model.CollectorUnavailable, reason)
}

func DisabledFeatures() []model.EBPFFeatureStatus {
	return featuresWithStatus(model.CollectorDisabled, "")
}

func featuresWithStatus(status model.CollectorStatus, reason string) []model.EBPFFeatureStatus {
	features := make([]model.EBPFFeatureStatus, len(featureDefinitions))
	for i, feature := range featureDefinitions {
		feature.Status = status
		feature.Reason = reason
		features[i] = feature
	}
	return features
}
