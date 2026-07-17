package ebpfcollector

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/eray/netdiag/internal/model"
)

// Collector counts kernel TCP retransmit tracepoint events. It deliberately
// keeps no packet payloads, addresses, ports, or process identifiers.
type Collector struct {
	objects tcpRetransmitObjects
	link    link.Link
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

func (c *Collector) Sample() (model.EBPFStats, error) {
	if c == nil {
		return model.EBPFStats{}, errors.New("eBPF collector is not initialized")
	}
	var key uint32
	var count uint64
	if err := c.objects.RetransmitCount.Lookup(&key, &count); err != nil {
		return model.EBPFStats{}, fmt.Errorf("read retransmit counter: %w", err)
	}
	return model.EBPFStats{TCPRetransmitEvents: count}, nil
}

func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.link.Close(), c.objects.Close())
}
