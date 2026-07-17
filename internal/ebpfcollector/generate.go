package ebpfcollector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpfcollector tcpRetransmit ../../bpf/tcp_retransmit.bpf.c -- -O2 -g -Wall
