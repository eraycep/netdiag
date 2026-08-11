package model

import "time"

const FormatVersion = 12

const (
	EBPFFeatureTCPRetransmitEvents    = "tcp_retransmit_events"
	EBPFFeatureTCPRetransmitIPv4Flows = "tcp_retransmit_ipv4_flows"
)

type CollectorStatus string

const (
	CollectorEnabled     CollectorStatus = "enabled"
	CollectorUnavailable CollectorStatus = "unavailable"
	CollectorDisabled    CollectorStatus = "disabled"
)

type Recording struct {
	Version      int                 `json:"version"`
	StartedAt    time.Time           `json:"started_at"`
	EndedAt      time.Time           `json:"ended_at"`
	Host         Host                `json:"host"`
	Interface    string              `json:"interface,omitempty"`
	PID          int                 `json:"pid,omitempty"`
	Samples      []Sample            `json:"samples"`
	Collectors   []CollectorManifest `json:"collectors"`
	EBPFFeatures []EBPFFeatureStatus `json:"ebpf_features,omitempty"`
}

type Host struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
}

type Sample struct {
	Timestamp    time.Time       `json:"timestamp"`
	TCP          TCPStats        `json:"tcp"`
	TCPSockets   TCPSocketStats  `json:"tcp_sockets"`
	SoftIRQ      SoftIRQStats    `json:"softirq"`
	Interface    *InterfaceStats `json:"interface,omitempty"`
	EBPF         *EBPFStats      `json:"ebpf,omitempty"`
	ElapsedNanos int64           `json:"elapsed_ns"`
	IRQ          IRQStats        `json:"irq"`
	Qdisc        QdiscStats      `json:"qdisc"`
	CPU          CPUStats        `json:"cpu"`
	Process      *ProcessStats   `json:"process,omitempty"`
}

type TCPStats struct {
	InSegments  uint64 `json:"in_segments"`
	OutSegments uint64 `json:"out_segments"`
	Retransmits uint64 `json:"retransmits"`
	InErrors    uint64 `json:"in_errors"`
}

type TCPSocketStats struct {
	Sockets          uint64 `json:"sockets"`
	Established      uint64 `json:"established"`
	TXQueue          uint64 `json:"tx_queue"`
	RXQueue          uint64 `json:"rx_queue"`
	MaxTXQueue       uint64 `json:"max_tx_queue"`
	MaxRXQueue       uint64 `json:"max_rx_queue"`
	NonZeroTXSockets uint64 `json:"nonzero_tx_sockets"`
	NonZeroRXSockets uint64 `json:"nonzero_rx_sockets"`
}

type IRQStats struct {
	IRQs []IRQLineStats `json:"irqs"`
}

type IRQLineStats struct {
	IRQ      string   `json:"irq"`
	Name     string   `json:"name"`
	Counts   []uint64 `json:"counts"`
	CPUs     []int    `json:"cpus"`
	Affinity []int    `json:"affinity,omitempty"`
}

type SoftIRQStats struct {
	NetRX uint64            `json:"net_rx"`
	NetTX uint64            `json:"net_tx"`
	CPUs  []SoftIRQCPUStats `json:"cpus"`
}

type SoftIRQCPUStats struct {
	CPU   int    `json:"cpu"`
	NetRX uint64 `json:"net_rx"`
	NetTX uint64 `json:"net_tx"`
}

type QdiscStats struct {
	Qdiscs []QdiscLineStats `json:"qdiscs"`
}

type QdiscLineStats struct {
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	Handle    string `json:"handle,omitempty"`
	Parent    string `json:"parent,omitempty"`

	Bytes          uint64 `json:"bytes"`
	Packets        uint64 `json:"packets"`
	Drops          uint64 `json:"drops"`
	Overlimits     uint64 `json:"overlimits"`
	Requeues       uint64 `json:"requeues"`
	BacklogBytes   uint64 `json:"backlog_bytes"`
	BacklogPackets uint64 `json:"backlog_packets"`
}

type CPUStats struct {
	CPUs         []CPUTimeStats    `json:"cpus"`
	ProcsRunning uint64            `json:"procs_running"`
	Pressure     *CPUPressureStats `json:"pressure,omitempty"`
}

type CPUTimeStats struct {
	CPU     int    `json:"cpu"`
	User    uint64 `json:"user"`
	Nice    uint64 `json:"nice"`
	System  uint64 `json:"system"`
	Idle    uint64 `json:"idle"`
	IOWait  uint64 `json:"iowait"`
	IRQ     uint64 `json:"irq"`
	SoftIRQ uint64 `json:"softirq"`
	Steal   uint64 `json:"steal"`
}

type ProcessStats struct {
	PID               int    `json:"pid"`
	RuntimeNanos      uint64 `json:"runtime_ns"`
	RunqueueWaitNanos uint64 `json:"runqueue_wait_ns"`
	Timeslices        uint64 `json:"timeslices"`
}

type CPUPressureStats struct {
	SomeAvg10  float64 `json:"some_avg10"`
	SomeAvg60  float64 `json:"some_avg60"`
	SomeAvg300 float64 `json:"some_avg300"`
	SomeTotal  uint64  `json:"some_total"`
	FullAvg10  float64 `json:"full_avg10"`
	FullAvg60  float64 `json:"full_avg60"`
	FullAvg300 float64 `json:"full_avg300"`
	FullTotal  uint64  `json:"full_total"`
}

type InterfaceStats struct {
	RXPackets uint64 `json:"rx_packets"`
	TXPackets uint64 `json:"tx_packets"`
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
	RXDropped uint64 `json:"rx_dropped"`
	TXDropped uint64 `json:"tx_dropped"`
	RXErrors  uint64 `json:"rx_errors"`
	TXErrors  uint64 `json:"tx_errors"`
}

type EBPFStats struct {
	TCPRetransmitEvents         uint64              `json:"tcp_retransmit_events"`
	TCPRetransmitFlows          []TCPRetransmitFlow `json:"tcp_retransmit_flows,omitempty"`
	TCPRetransmitFlowsTruncated bool                `json:"tcp_retransmit_flows_truncated,omitempty"`
	TCPRetransmitFlowCount      int                 `json:"tcp_retransmit_flow_count,omitempty"`
	FeatureErrors               []EBPFFeatureError  `json:"feature_errors,omitempty"`
}

type EBPFFeatureError struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

type EBPFFeatureStatus struct {
	Name            string          `json:"name"`
	Status          CollectorStatus `json:"status"`
	Reason          string          `json:"reason,omitempty"`
	VisibilityScope string          `json:"visibility_scope"`
}

type TCPRetransmitFlow struct {
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	Retransmits        uint64 `json:"retransmits"`
}

type CollectorManifest struct {
	CollectorName   string          `json:"collector_name"`
	Status          CollectorStatus `json:"status"`
	VisibilityScope string          `json:"visibility_scope"`
	FailureReason   string          `json:"failure_reason,omitempty"`
}
