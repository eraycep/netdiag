package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eray/netdiag/internal/model"
)

func TestParseProcessSchedstat(t *testing.T) {
	got, err := parseProcessSchedstat("100 200 3\n")
	if err != nil {
		t.Fatal(err)
	}
	want := model.ProcessStats{RuntimeNanos: 100, RunqueueWaitNanos: 200, Timeslices: 3}
	if got != want {
		t.Fatalf("schedstat = %+v, want %+v", got, want)
	}
}

func TestParseProcessSchedstatRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "missing field", raw: "100 200", wantErr: "expected 3 fields"},
		{name: "invalid runtime", raw: "x 200 3", wantErr: "parse runtime"},
		{name: "invalid runqueue wait", raw: "100 x 3", wantErr: "parse runqueue wait"},
		{name: "invalid timeslices", raw: "100 200 x", wantErr: "parse timeslices"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseProcessSchedstat(tt.raw)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadProcessSchedstat(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "123"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "123", "schedstat"), []byte("10 20 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Collector{ProcRoot: root}.ReadProcessSchedstat(123)
	if err != nil {
		t.Fatal(err)
	}
	want := model.ProcessStats{PID: 123, RuntimeNanos: 10, RunqueueWaitNanos: 20, Timeslices: 2}
	if got != want {
		t.Fatalf("schedstat = %+v, want %+v", got, want)
	}
}

func TestReadProcessSchedstatRejectsInvalidPID(t *testing.T) {
	_, err := Collector{ProcRoot: t.TempDir()}.ReadProcessSchedstat(0)
	if err == nil || !strings.Contains(err.Error(), "invalid pid") {
		t.Fatalf("error = %v, want invalid pid error", err)
	}
}
