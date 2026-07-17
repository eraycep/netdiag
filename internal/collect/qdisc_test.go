package collect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestParseQdiscStats(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		raw     string
		want    model.QdiscStats
		wantErr string
	}{
		{
			name:  "fq_codel single qdisc",
			iface: "eth0",
			raw: strings.Join([]string{
				"qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64",
				" Sent 12345 bytes 67 pkt (dropped 2, overlimits 3 requeues 4)",
				" backlog 100b 5p requeues 4",
			}, "\n"),
			want: model.QdiscStats{Qdiscs: []model.QdiscLineStats{
				{
					Interface:      "eth0",
					Kind:           "fq_codel",
					Handle:         "0",
					Parent:         "root",
					Bytes:          12345,
					Packets:        67,
					Drops:          2,
					Overlimits:     3,
					Requeues:       4,
					BacklogBytes:   100,
					BacklogPackets: 5,
				},
			}},
		},
		{
			name:  "noqueue qdisc",
			iface: "lo",
			raw: strings.Join([]string{
				"qdisc noqueue 0: root refcnt 2",
				" Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)",
				" backlog 0b 0p requeues 0",
			}, "\n"),
			want: model.QdiscStats{Qdiscs: []model.QdiscLineStats{
				{Interface: "lo", Kind: "noqueue", Handle: "0", Parent: "root"},
			}},
		},
		{
			name:  "multiple qdiscs",
			iface: "eth0",
			raw: strings.Join([]string{
				"qdisc htb 1: root refcnt 2 r2q 10 default 1 direct_packets_stat 0",
				" Sent 100 bytes 10 pkt (dropped 1, overlimits 2 requeues 3)",
				" backlog 0b 0p requeues 3",
				"qdisc fq_codel 10: parent 1:1 limit 10240p flows 1024 quantum 1514",
				" Sent 200 bytes 20 pkt (dropped 4, overlimits 5 requeues 6)",
				" backlog 300b 7p requeues 6",
			}, "\n"),
			want: model.QdiscStats{Qdiscs: []model.QdiscLineStats{
				{Interface: "eth0", Kind: "htb", Handle: "1", Parent: "root", Bytes: 100, Packets: 10, Drops: 1, Overlimits: 2, Requeues: 3},
				{Interface: "eth0", Kind: "fq_codel", Handle: "10", Parent: "1:1", Bytes: 200, Packets: 20, Drops: 4, Overlimits: 5, Requeues: 6, BacklogBytes: 300, BacklogPackets: 7},
			}},
		},
		{name: "empty input", iface: "eth0", raw: "", want: model.QdiscStats{}},
		{name: "malformed header", iface: "eth0", raw: "qdisc", wantErr: "malformed qdisc header"},
		{name: "sent before header", iface: "eth0", raw: "Sent 1 bytes 2 pkt (dropped 3, overlimits 4 requeues 5)", wantErr: "Sent line before qdisc header"},
		{
			name:  "malformed sent line",
			iface: "eth0",
			raw: strings.Join([]string{
				"qdisc fq_codel 0: root refcnt 2",
				" Sent nope",
			}, "\n"),
			wantErr: "malformed qdisc Sent line",
		},
		{
			name:  "malformed backlog line",
			iface: "eth0",
			raw: strings.Join([]string{
				"qdisc fq_codel 0: root refcnt 2",
				" backlog nope",
			}, "\n"),
			wantErr: "malformed qdisc backlog line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseQdiscStats(tt.iface, tt.raw)
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadQdiscRejectsInvalidInterfaceName(t *testing.T) {
	_, err := Collector{}.readQdisc("../eth0")
	assertErrorContains(t, err, "invalid interface name")
}

func TestReadQdiscReturnsEmptyWithoutInterface(t *testing.T) {
	got, err := Collector{}.readQdisc("")
	assertErrorContains(t, err, "")
	if !reflect.DeepEqual(got, model.QdiscStats{}) {
		t.Fatalf("got %+v, want empty stats", got)
	}
}

func TestReadQdiscUsesCommandOutput(t *testing.T) {
	oldCommand := qdiscCommand
	defer func() { qdiscCommand = oldCommand }()

	var gotIface string
	qdiscCommand = func(_ context.Context, iface string) ([]byte, error) {
		gotIface = iface
		return []byte(strings.Join([]string{
			"qdisc fq_codel 0: root refcnt 2",
			" Sent 10 bytes 2 pkt (dropped 1, overlimits 0 requeues 0)",
			" backlog 0b 0p requeues 0",
		}, "\n")), nil
	}

	got, err := Collector{}.readQdisc("eth0")
	assertErrorContains(t, err, "")
	if gotIface != "eth0" {
		t.Fatalf("command iface = %q, want eth0", gotIface)
	}
	want := model.QdiscStats{Qdiscs: []model.QdiscLineStats{
		{Interface: "eth0", Kind: "fq_codel", Handle: "0", Parent: "root", Bytes: 10, Packets: 2, Drops: 1},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestReadQdiscReturnsCommandError(t *testing.T) {
	oldCommand := qdiscCommand
	defer func() { qdiscCommand = oldCommand }()

	qdiscCommand = func(_ context.Context, _ string) ([]byte, error) {
		return []byte("netlink denied"), errors.New("exit status 1")
	}

	_, err := Collector{}.readQdisc("eth0")
	assertErrorContains(t, err, "tc command failed")
	assertErrorContains(t, err, "netlink denied")
}
