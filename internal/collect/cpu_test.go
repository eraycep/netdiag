package collect

import (
	"reflect"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestReadCPUStatFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    model.CPUStats
		wantErr string
	}{
		{
			name:    "valid",
			fixture: "cpu-valid",
			want: model.CPUStats{
				CPUs: []model.CPUTimeStats{
					{CPU: 0, User: 10, Nice: 1, System: 20, Idle: 100, IOWait: 2, IRQ: 3, SoftIRQ: 4, Steal: 5},
					{CPU: 1, User: 11, Nice: 0, System: 21, Idle: 101, IOWait: 0, IRQ: 1, SoftIRQ: 6, Steal: 0},
				},
				ProcsRunning: 3,
			},
		},
		{
			name:    "sparse CPU ids",
			fixture: "cpu-sparse",
			want: model.CPUStats{
				CPUs: []model.CPUTimeStats{
					{CPU: 0, User: 10, System: 20, Idle: 100, IRQ: 3, SoftIRQ: 4},
					{CPU: 2, User: 12, System: 22, Idle: 102, IRQ: 1, SoftIRQ: 7},
				},
				ProcsRunning: 1,
			},
		},
		{name: "invalid CPU label", fixture: "cpu-invalid-label", wantErr: "no per-CPU rows found"},
		{name: "duplicate CPU", fixture: "cpu-duplicate", wantErr: "duplicate cpu0 row"},
		{name: "invalid numeric field", fixture: "cpu-invalid-number", wantErr: "parse /proc/stat cpu0 field 2"},
		{name: "missing required field", fixture: "cpu-missing-field", wantErr: "want at least 7"},
		{name: "missing procs_running", fixture: "cpu-missing-procs-running", wantErr: "procs_running row is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Collector{ProcRoot: fixtureProcRoot(tt.fixture)}.readCPUStat()
			assertErrorContains(t, err, tt.wantErr)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadCPUWithOptionalPressure(t *testing.T) {
	got, err := Collector{ProcRoot: fixtureProcRoot("cpu-valid")}.readCPU()
	assertErrorContains(t, err, "")
	if got.Pressure == nil {
		t.Fatal("expected CPU pressure stats")
	}
	if got.Pressure.SomeTotal != 12345 || got.Pressure.FullTotal != 7 {
		t.Fatalf("unexpected pressure stats: %+v", got.Pressure)
	}
}

func TestReadCPUAllowsMissingPressure(t *testing.T) {
	got, err := Collector{ProcRoot: fixtureProcRoot("cpu-no-pressure")}.readCPU()
	assertErrorContains(t, err, "")
	if got.Pressure != nil {
		t.Fatalf("pressure = %+v, want nil", got.Pressure)
	}
	if len(got.CPUs) != 1 {
		t.Fatalf("cpu count = %d, want 1", len(got.CPUs))
	}
}

func TestReadCPURejectsMalformedPressure(t *testing.T) {
	_, err := Collector{ProcRoot: fixtureProcRoot("cpu-malformed-pressure")}.readCPU()
	assertErrorContains(t, err, "malformed /proc/pressure/cpu")
}

func TestParseCPUPressure(t *testing.T) {
	got, err := parseCPUPressure("some avg10=0.10 avg60=0.20 avg300=0.30 total=123\nfull avg10=1.10 avg60=1.20 avg300=1.30 total=456\n")
	assertErrorContains(t, err, "")
	want := &model.CPUPressureStats{
		SomeAvg10: 0.10, SomeAvg60: 0.20, SomeAvg300: 0.30, SomeTotal: 123,
		FullAvg10: 1.10, FullAvg60: 1.20, FullAvg300: 1.30, FullTotal: 456,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseCPUPressureRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "missing full", raw: "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "some and full rows are required"},
		{name: "unknown row", raw: "other avg10=0.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "unknown pressure class"},
		{name: "missing field", raw: "some avg10=0.00 avg60=0.00 avg300=0.00\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "malformed /proc/pressure/cpu line"},
		{name: "invalid float", raw: "some avg10=x avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "parse CPU pressure avg10"},
		{name: "invalid total", raw: "some avg10=0.00 avg60=0.00 avg300=0.00 total=x\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "parse CPU pressure total"},
		{name: "duplicate field", raw: "some avg10=0.00 avg10=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n", wantErr: "duplicate CPU pressure field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCPUPressure(tt.raw)
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}
