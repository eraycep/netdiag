package collect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestParseTCPSocketStats(t *testing.T) {
	raw := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1",
		"   1: 0100007F:1F91 0100007F:C350 01 00000010:00000020 00:00000000 00000000 1000 0 2",
		"   2: 0100007F:1F92 0100007F:C351 01 00000001:00000000 00:00000000 00000000 1000 0 3",
	}, "\n")

	var got model.TCPSocketStats
	if err := parseTCPSocketStats(strings.NewReader(raw), &got, "tcp4"); err != nil {
		t.Fatal(err)
	}
	limitTCPSocketQueues(&got, 0)

	want := model.TCPSocketStats{
		Sockets:            3,
		Established:        2,
		TXQueue:            17,
		RXQueue:            32,
		MaxTXQueue:         16,
		MaxRXQueue:         32,
		NonZeroTXSockets:   2,
		NonZeroRXSockets:   1,
		TopQueuesTruncated: true,
		SocketQueueCount:   2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestParseTCPSocketStatsTopQueues(t *testing.T) {
	raw := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:1F90 0100007F:C350 01 00000010:00000020 00:00000000 00000000 1000 0 1",
		"   1: 0200007F:1F91 0100007F:C351 01 00000080:00000001 00:00000000 00000000 1000 0 2",
		"   2: 0300007F:1F92 0100007F:C352 01 00000001:00000000 00:00000000 00000000 1000 0 3",
	}, "\n")

	var got model.TCPSocketStats
	if err := parseTCPSocketStats(strings.NewReader(raw), &got, "tcp4"); err != nil {
		t.Fatal(err)
	}
	limitTCPSocketQueues(&got, 2)

	want := []model.TCPSocketQueue{
		{
			Protocol:      "tcp4",
			LocalAddress:  "127.0.0.2",
			LocalPort:     8081,
			RemoteAddress: "127.0.0.1",
			RemotePort:    50001,
			State:         "01",
			TXQueue:       128,
			RXQueue:       1,
		},
		{
			Protocol:      "tcp4",
			LocalAddress:  "127.0.0.1",
			LocalPort:     8080,
			RemoteAddress: "127.0.0.1",
			RemotePort:    50000,
			State:         "01",
			TXQueue:       16,
			RXQueue:       32,
		},
	}
	if !reflect.DeepEqual(got.TopQueues, want) {
		t.Fatalf("top queues = %+v, want %+v", got.TopQueues, want)
	}
	if !got.TopQueuesTruncated || got.SocketQueueCount != 3 {
		t.Fatalf("truncation = (%v, %d), want (true, 3)", got.TopQueuesTruncated, got.SocketQueueCount)
	}
}

func TestParseTCPSocketStatsMalformedLine(t *testing.T) {
	raw := "sl local_address rem_address st tx_queue:rx_queue\n0: 0100007F:1F90 00000000:0000 01"
	var got model.TCPSocketStats
	err := parseTCPSocketStats(strings.NewReader(raw), &got, "tcp4")
	if err == nil || !strings.Contains(err.Error(), "want at least 5") {
		t.Fatalf("error = %v, want malformed line error", err)
	}
}

func TestParseTCPSocketStatsInvalidQueue(t *testing.T) {
	raw := "sl local_address rem_address st tx_queue:rx_queue\n0: 0100007F:1F90 00000000:0000 01 bad"
	var got model.TCPSocketStats
	err := parseTCPSocketStats(strings.NewReader(raw), &got, "tcp4")
	if err == nil || !strings.Contains(err.Error(), "invalid queue field") {
		t.Fatalf("error = %v, want invalid queue error", err)
	}
}

func TestParseTCPSocketStatsInvalidEndpoint(t *testing.T) {
	raw := "sl local_address rem_address st tx_queue:rx_queue\n0: bad 00000000:0000 01 00000001:00000000"
	var got model.TCPSocketStats
	err := parseTCPSocketStats(strings.NewReader(raw), &got, "tcp4")
	if err == nil || !strings.Contains(err.Error(), "local address") {
		t.Fatalf("error = %v, want local address error", err)
	}
}

func TestParseTCPEndpointIPv4(t *testing.T) {
	addr, port, err := parseTCPEndpoint("0100007F:1F90", "tcp4")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1" || port != 8080 {
		t.Fatalf("endpoint = %s:%d, want 127.0.0.1:8080", addr, port)
	}
}

func TestParseTCPEndpointIPv6(t *testing.T) {
	addr, port, err := parseTCPEndpoint("00000000000000000000000001000000:1F90", "tcp6")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "::1" || port != 8080 {
		t.Fatalf("endpoint = %s:%d, want ::1:8080", addr, port)
	}
}

func TestParseTCPQueueField(t *testing.T) {
	txQueue, rxQueue, err := parseTCPQueueField("0000000A:0000000F")
	if err != nil {
		t.Fatal(err)
	}
	if txQueue != 10 || rxQueue != 15 {
		t.Fatalf("queues = (%d, %d), want (10, 15)", txQueue, rxQueue)
	}
}
