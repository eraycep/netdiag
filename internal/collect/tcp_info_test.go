package collect

import "testing"

func TestParseTCPInfo(t *testing.T) {
	raw := []byte(`State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 127.0.0.1:8080 127.0.0.1:50000
	 cubic wscale:7,7 rto:204 rtt:0.029/0.014 ato:40 mss:65483 pmtu:65535 rcvmss:536 advmss:65483 cwnd:10 bytes_acked:123 bytes_received:456 retrans:0/3
LISTEN 0 4096 127.0.0.1:8082 0.0.0.0:*
ESTAB 0 0 [::1]:8081 [::1]:50001
	 cubic rtt:1.5/0.25 cwnd:20 bytes_acked:1000 bytes_received:2000
`)

	stats, err := parseTCPInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Sockets) != 2 {
		t.Fatalf("socket count = %d, want 2", len(stats.Sockets))
	}

	first := stats.Sockets[0]
	if first.Protocol != "tcp4" || first.LocalAddress != "127.0.0.1" || first.LocalPort != 8080 ||
		first.RemoteAddress != "127.0.0.1" || first.RemotePort != 50000 || first.State != "ESTAB" {
		t.Fatalf("first socket endpoint mismatch: %+v", first)
	}
	if first.RTTMillis != 0.029 || first.RTTVarMillis != 0.014 || first.CongestionWnd != 10 ||
		first.BytesAcked != 123 || first.BytesReceived != 456 || first.Retransmission != "0/3" {
		t.Fatalf("first socket metrics mismatch: %+v", first)
	}

	second := stats.Sockets[1]
	if second.Protocol != "tcp6" || second.LocalAddress != "::1" || second.LocalPort != 8081 ||
		second.RemoteAddress != "::1" || second.RemotePort != 50001 {
		t.Fatalf("second socket endpoint mismatch: %+v", second)
	}
	if second.RTTMillis != 1.5 || second.RTTVarMillis != 0.25 || second.CongestionWnd != 20 ||
		second.BytesAcked != 1000 || second.BytesReceived != 2000 {
		t.Fatalf("second socket metrics mismatch: %+v", second)
	}
}

func TestLimitTCPInfoSockets(t *testing.T) {
	stats, err := parseTCPInfo([]byte(`State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 127.0.0.1:1000 127.0.0.1:2000
	 cubic rtt:1/0.1 cwnd:10
ESTAB 0 0 127.0.0.1:1001 127.0.0.1:2001
	 cubic rtt:5/0.1 cwnd:10
ESTAB 0 0 127.0.0.1:1002 127.0.0.1:2002
	 cubic rtt:3/0.1 cwnd:10
`))
	if err != nil {
		t.Fatal(err)
	}

	limitTCPInfoSockets(&stats, 2)

	if stats.Count != 3 {
		t.Fatalf("count = %d, want 3", stats.Count)
	}
	if !stats.Truncated {
		t.Fatal("stats were not marked truncated")
	}
	if len(stats.Sockets) != 2 {
		t.Fatalf("serialized sockets = %d, want 2", len(stats.Sockets))
	}
	if stats.Sockets[0].RTTMillis != 5 || stats.Sockets[1].RTTMillis != 3 {
		t.Fatalf("sockets were not sorted by RTT before truncation: %+v", stats.Sockets)
	}
}

func TestLimitTCPInfoSocketsCanOmitAllTuples(t *testing.T) {
	stats, err := parseTCPInfo([]byte(`State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 127.0.0.1:1000 127.0.0.1:2000
	 cubic rtt:1/0.1 cwnd:10
`))
	if err != nil {
		t.Fatal(err)
	}

	limitTCPInfoSockets(&stats, 0)

	if stats.Count != 1 {
		t.Fatalf("count = %d, want 1", stats.Count)
	}
	if !stats.Truncated {
		t.Fatal("stats were not marked truncated")
	}
	if len(stats.Sockets) != 0 {
		t.Fatalf("serialized sockets = %d, want 0", len(stats.Sockets))
	}
}

func TestParseSSEndpoint(t *testing.T) {
	tests := []struct {
		raw         string
		wantAddress string
		wantPort    uint16
	}{
		{raw: "127.0.0.1:8080", wantAddress: "127.0.0.1", wantPort: 8080},
		{raw: "[::1]:8081", wantAddress: "::1", wantPort: 8081},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			address, port, err := parseSSEndpoint(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if address != tt.wantAddress || port != tt.wantPort {
				t.Fatalf("endpoint = %s:%d, want %s:%d", address, port, tt.wantAddress, tt.wantPort)
			}
		})
	}
}

func TestParseTCPInfoRejectsMalformedEstablishedLine(t *testing.T) {
	_, err := parseTCPInfo([]byte("ESTAB 0 0 127.0.0.1:8080\n"))
	if err == nil {
		t.Fatal("expected malformed established line error")
	}
}
