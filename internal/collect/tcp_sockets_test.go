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
	if err := parseTCPSocketStats(strings.NewReader(raw), &got); err != nil {
		t.Fatal(err)
	}

	want := model.TCPSocketStats{
		Sockets:          3,
		Established:      2,
		TXQueue:          17,
		RXQueue:          32,
		MaxTXQueue:       16,
		MaxRXQueue:       32,
		NonZeroTXSockets: 2,
		NonZeroRXSockets: 1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestParseTCPSocketStatsMalformedLine(t *testing.T) {
	raw := "sl local_address rem_address st tx_queue:rx_queue\n0: 0100007F:1F90 00000000:0000 01"
	var got model.TCPSocketStats
	err := parseTCPSocketStats(strings.NewReader(raw), &got)
	if err == nil || !strings.Contains(err.Error(), "want at least 5") {
		t.Fatalf("error = %v, want malformed line error", err)
	}
}

func TestParseTCPSocketStatsInvalidQueue(t *testing.T) {
	raw := "sl local_address rem_address st tx_queue:rx_queue\n0: 0100007F:1F90 00000000:0000 01 bad"
	var got model.TCPSocketStats
	err := parseTCPSocketStats(strings.NewReader(raw), &got)
	if err == nil || !strings.Contains(err.Error(), "invalid queue field") {
		t.Fatalf("error = %v, want invalid queue error", err)
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
