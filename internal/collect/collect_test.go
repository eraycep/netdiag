package collect

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestReadTCPFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    model.TCPStats
		wantErr string
	}{
		{
			name:    "valid",
			fixture: "valid",
			want:    model.TCPStats{InSegments: 101, OutSegments: 202, Retransmits: 7, InErrors: 3},
		},
		{name: "header value mismatch", fixture: "snmp-mismatched", wantErr: "malformed Tcp section"},
		{name: "invalid number", fixture: "snmp-invalid-number", wantErr: "parse TCP counter RetransSegs"},
		{name: "missing required field", fixture: "snmp-missing-field", wantErr: "missing InErrs"},
		{name: "missing section", fixture: "snmp-missing-section", wantErr: "Tcp section not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := Collector{ProcRoot: fixtureProcRoot(tt.fixture)}
			got, err := collector.readTCP()
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadSoftIRQsFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    model.SoftIRQStats
		wantErr string
	}{
		{name: "valid", fixture: "valid", want: model.SoftIRQStats{
			NetRX: 60,
			NetTX: 15,
			CPUs: []model.SoftIRQCPUStats{
				{CPU: 0, NetRX: 10, NetTX: 4},
				{CPU: 1, NetRX: 20, NetTX: 5},
				{CPU: 2, NetRX: 30, NetTX: 6},
			},
		}},
		{name: "sparse CPU header", fixture: "softirqs-sparse-cpu", want: model.SoftIRQStats{
			NetRX: 40,
			NetTX: 10,
			CPUs: []model.SoftIRQCPUStats{
				{CPU: 0, NetRX: 10, NetTX: 4},
				{CPU: 2, NetRX: 30, NetTX: 6},
			},
		}},
		{name: "invalid number", fixture: "softirqs-invalid-number", wantErr: "parse softirq counter"},
		{name: "missing row", fixture: "softirqs-missing-row", wantErr: "NET_RX and NET_TX rows are required"},
		{name: "missing header", fixture: "softirqs-missing-header", wantErr: "invalid CPU header field"},
		{name: "mismatched row", fixture: "softirqs-mismatched-row", wantErr: "has 1 counters for 2 CPUs"},
		{name: "duplicate row", fixture: "softirqs-duplicate-row", wantErr: "duplicate NET_RX row"},
		{name: "invalid CPU header", fixture: "softirqs-invalid-cpu", wantErr: "invalid CPU header field"},
		{name: "duplicate CPU header", fixture: "softirqs-duplicate-cpu", wantErr: "duplicate CPU0 header field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := Collector{ProcRoot: fixtureProcRoot(tt.fixture)}
			got, err := collector.readSoftIRQs()
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadInterfaceFixtures(t *testing.T) {
	want := model.InterfaceStats{
		RXPackets: 100, TXPackets: 200, RXBytes: 1000, TXBytes: 2000,
		RXDropped: 3, TXDropped: 4, RXErrors: 5, TXErrors: 6,
	}
	tests := []struct {
		name    string
		fixture string
		iface   string
		wantErr string
	}{
		{name: "valid", fixture: "valid", iface: "eth0"},
		{name: "invalid number", fixture: "interface-invalid-number", iface: "eth0", wantErr: "parse rx_packets counter"},
		{name: "missing counter", fixture: "interface-missing-counter", iface: "eth0", wantErr: "read tx_errors counter"},
		{name: "missing interface", fixture: "valid", iface: "eth9", wantErr: "read rx_packets counter"},
		{name: "path traversal", fixture: "valid", iface: "../eth0", wantErr: "invalid interface name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := Collector{SysRoot: filepath.Join("testdata", tt.fixture, "sys")}
			got, err := collector.readInterface(tt.iface)
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestReadInterruptsFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		sysRoot string
		iface   string
		want    model.IRQStats
		wantErr string
	}{
		{
			name:    "valid",
			fixture: "interrupts-valid",
			iface:   "eth0",
			want: model.IRQStats{IRQs: []model.IRQLineStats{
				{
					IRQ:      "32",
					Name:     "IR-PCI-MSI 524288-edge eth0-TxRx-0",
					Counts:   []uint64{10, 20, 30},
					CPUs:     []int{0, 1, 2},
					Affinity: []int{0, 2},
				},
				{
					IRQ:      "33",
					Name:     "IR-PCI-MSI 524289-edge eth0-TxRx-1",
					Counts:   []uint64{1, 2, 3},
					CPUs:     []int{0, 1, 2},
					Affinity: []int{1},
				},
			}},
		},
		{
			name:    "matched by sysfs MSI IRQ",
			fixture: "interrupts-msi-sysfs",
			sysRoot: filepath.Join("testdata", "interrupts-msi-sysfs", "sys"),
			iface:   "eth0",
			want: model.IRQStats{IRQs: []model.IRQLineStats{
				{
					IRQ:      "40",
					Name:     "IR-PCI-MSIX-0000:04:00.0 0-edge mlx5_comp0",
					Counts:   []uint64{7, 8},
					CPUs:     []int{0, 1},
					Affinity: []int{0, 1},
				},
			}},
		},
		{
			name:    "sparse CPU header",
			fixture: "interrupts-sparse-cpu",
			iface:   "eth0",
			want: model.IRQStats{IRQs: []model.IRQLineStats{
				{
					IRQ:      "32",
					Name:     "IR-PCI-MSI 524288-edge eth0-TxRx-0",
					Counts:   []uint64{10, 30},
					CPUs:     []int{0, 2},
					Affinity: []int{0, 2},
				},
			}},
		},
		{name: "empty iface", fixture: "interrupts-valid", iface: "", want: model.IRQStats{}},
		{name: "path traversal iface", fixture: "interrupts-valid", iface: "../eth0", wantErr: "invalid interface name"},
		{name: "invalid counter", fixture: "interrupts-invalid-counter", iface: "eth0", wantErr: "parse interrupt counter for IRQ 32 CPU1"},
		{name: "invalid affinity", fixture: "interrupts-invalid-affinity", iface: "eth0", wantErr: "parse interrupt affinity for IRQ 32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := Collector{ProcRoot: fixtureProcRoot(tt.fixture), SysRoot: tt.sysRoot}
			got, err := collector.readInterrupts(tt.iface)
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseCPUList(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []int
		wantErr string
	}{
		{name: "single", raw: "0", want: []int{0}},
		{name: "range", raw: "0-3", want: []int{0, 1, 2, 3}},
		{name: "mixed", raw: "0,2,4-6", want: []int{0, 2, 4, 5, 6}},
		{name: "dedupe", raw: "0,0-2,2", want: []int{0, 1, 2}},
		{name: "empty", raw: "", wantErr: "empty CPU list"},
		{name: "bad token", raw: "x", wantErr: "invalid CPU"},
		{name: "bad range", raw: "1-2-3", wantErr: "invalid CPU range"},
		{name: "descending range", raw: "4-2", wantErr: "invalid descending CPU range"},
		{name: "empty part", raw: "0,,2", wantErr: "invalid CPU list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCPUList(tt.raw)
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func fixtureProcRoot(name string) string {
	return filepath.Join("testdata", name, "proc")
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
