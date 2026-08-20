package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eray/netdiag/internal/ebpfcollector"
	"github.com/eray/netdiag/internal/model"
)

func TestAtomicWriteRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	recording := model.Recording{
		Version:   model.FormatVersion,
		StartedAt: time.Unix(10, 0).UTC(),
		EndedAt:   time.Unix(11, 0).UTC(),
		Samples:   []model.Sample{},
	}

	if err := atomicWriteRecording(path, recording); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("recording does not end with a newline")
	}
	var decoded model.Recording
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("recording is not valid JSON: %v", err)
	}
	if decoded.Version != model.FormatVersion {
		t.Fatalf("version = %d, want %d", decoded.Version, model.FormatVersion)
	}
	assertFileMode(t, path, 0o600)
}

func TestAtomicWriteRecordingReplacesExistingFileWithRestrictedPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.json")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	recording := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{}}
	if err := atomicWriteRecording(path, recording); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "old contents") {
		t.Fatal("existing destination was not replaced")
	}
	assertFileMode(t, path, 0o600)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "capture.json" {
		t.Fatalf("unexpected files after atomic replacement: %+v", entries)
	}
}

func TestRecordStopsAtMaximumSampleCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{
		"--duration=30s",
		"--interval=10s",
		"--max-samples=1",
		"--ebpf=false",
		"--output=" + path,
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}
	if len(recording.Samples) != 1 {
		t.Fatalf("sample count = %d, want 1", len(recording.Samples))
	}
	if recording.EndedAt.IsZero() {
		t.Fatal("recording has no end time")
	}
	if !strings.Contains(string(data), `"elapsed_ns"`) {
		t.Fatal("recording does not contain elapsed time")
	}
	if recording.Samples[0].ElapsedNanos < 0 {
		t.Fatalf("elapsed time = %d, want a nonnegative value", recording.Samples[0].ElapsedNanos)
	}
	if len(recording.EBPFFeatures) != 3 {
		t.Fatalf("eBPF feature count = %d, want 3", len(recording.EBPFFeatures))
	}
	for _, feature := range recording.EBPFFeatures {
		if feature.Status != model.CollectorDisabled {
			t.Fatalf("eBPF feature %s status = %q, want %q", feature.Name, feature.Status, model.CollectorDisabled)
		}
		if feature.VisibilityScope == "" {
			t.Fatalf("eBPF feature %s has no visibility scope", feature.Name)
		}
	}
}

func TestRecordSerializesUnavailableEBPFFeatures(t *testing.T) {
	oldNewEBPFCollector := newEBPFCollector
	newEBPFCollector = func() (*ebpfcollector.Collector, error) {
		return nil, errors.New("load tcp retransmit programs: permission denied")
	}
	t.Cleanup(func() {
		newEBPFCollector = oldNewEBPFCollector
	})

	path := filepath.Join(t.TempDir(), "capture.json")
	stderr := captureStderr(t, func() {
		err := record([]string{
			"--duration=30s",
			"--interval=10s",
			"--max-samples=1",
			"--output=" + path,
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stderr, "eBPF unavailable") {
		t.Fatalf("stderr missing eBPF unavailable warning: %s", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}

	assertCollectorStatus(t, recording.Collectors, "ebpf_tcp_retransmit", model.CollectorUnavailable)
	if len(recording.EBPFFeatures) != 3 {
		t.Fatalf("eBPF feature count = %d, want 3", len(recording.EBPFFeatures))
	}
	for _, feature := range recording.EBPFFeatures {
		if feature.Status != model.CollectorUnavailable {
			t.Fatalf("eBPF feature %s status = %q, want %q", feature.Name, feature.Status, model.CollectorUnavailable)
		}
		if feature.Reason != "load tcp retransmit programs: permission denied" {
			t.Fatalf("eBPF feature %s reason = %q", feature.Name, feature.Reason)
		}
		if feature.VisibilityScope == "" {
			t.Fatalf("eBPF feature %s has no visibility scope", feature.Name)
		}
	}
}

func TestRecordElapsedTimeIncreases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{
		"--duration=30s",
		"--interval=1ms",
		"--max-samples=2",
		"--ebpf=false",
		"--output=" + path,
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}
	if len(recording.Samples) != 2 {
		t.Fatalf("sample count = %d, want 2", len(recording.Samples))
	}
	if recording.Samples[1].ElapsedNanos <= recording.Samples[0].ElapsedNanos {
		t.Fatalf("elapsed times are not increasing: %d, %d", recording.Samples[0].ElapsedNanos, recording.Samples[1].ElapsedNanos)
	}
}

func TestRecordSerializesProcessSchedstat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{
		"--duration=30s",
		"--interval=10s",
		"--max-samples=1",
		"--ebpf=false",
		"--pid", fmt.Sprint(os.Getpid()),
		"--output=" + path,
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}
	if recording.PID != os.Getpid() {
		t.Fatalf("recording pid = %d, want %d", recording.PID, os.Getpid())
	}
	if len(recording.Samples) != 1 || recording.Samples[0].Process == nil {
		t.Fatalf("recording did not include process schedstat: %+v", recording.Samples)
	}
	if recording.Samples[0].Process.PID != os.Getpid() {
		t.Fatalf("sample process pid = %d, want %d", recording.Samples[0].Process.PID, os.Getpid())
	}
	assertCollectorStatus(t, recording.Collectors, "proc_pid_schedstat", model.CollectorEnabled)
}

func TestRecordRejectsInvalidMaximumSampleCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--max-samples=0", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "max samples must be positive") {
		t.Fatalf("error = %v, want maximum sample validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestRecordRejectsInvalidMaximumEBPFFlowCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--max-ebpf-flows=-1", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "max ebpf flows must be non-negative") {
		t.Fatalf("error = %v, want maximum eBPF flow validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestRecordRejectsInvalidMaximumEBPFFlowSampleCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--max-ebpf-flow-samples=-2", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "max ebpf flow samples must be -1 or greater") {
		t.Fatalf("error = %v, want maximum eBPF flow sample validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestRecordRejectsInvalidMaximumTCPSocketQueueCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--max-tcp-socket-queues=-1", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "max tcp socket queues must be 0 or greater") {
		t.Fatalf("error = %v, want maximum TCP socket queue validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestRecordRejectsInvalidMaximumTCPInfoSocketCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--max-tcp-info-sockets=-1", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "max tcp info sockets must be 0 or greater") {
		t.Fatalf("error = %v, want maximum TCP info socket validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestEBPFFlowSampleBudget(t *testing.T) {
	budget := newEBPFFlowSampleBudget(1)

	maxFlows, omitted := budget.maxFlows(128)
	if maxFlows != 128 || omitted {
		t.Fatalf("first budget decision = (%d, %v), want (128, false)", maxFlows, omitted)
	}
	stats := budget.apply(model.EBPFStats{
		TCPRetransmitFlowCount: 1,
		TCPRetransmitFlows:     []model.TCPRetransmitFlow{{SourceAddress: "127.0.0.1"}},
	}, omitted)
	if stats.TCPRetransmitFlowsOmittedReason != "" {
		t.Fatalf("first sample omission reason = %q, want empty", stats.TCPRetransmitFlowsOmittedReason)
	}

	maxFlows, omitted = budget.maxFlows(128)
	if maxFlows != 0 || !omitted {
		t.Fatalf("exhausted budget decision = (%d, %v), want (0, true)", maxFlows, omitted)
	}
	stats = budget.apply(model.EBPFStats{
		TCPRetransmitFlowCount:      3,
		TCPRetransmitFlowsTruncated: true,
	}, omitted)
	if stats.TCPRetransmitFlowsOmittedReason != "recording eBPF flow sample budget exhausted" {
		t.Fatalf("exhausted sample omission reason = %q", stats.TCPRetransmitFlowsOmittedReason)
	}
}

func TestEBPFFlowSampleBudgetDoesNotConsumeEmptySamples(t *testing.T) {
	budget := newEBPFFlowSampleBudget(1)

	_, omitted := budget.maxFlows(128)
	stats := budget.apply(model.EBPFStats{}, omitted)
	if stats.TCPRetransmitFlowsOmittedReason != "" {
		t.Fatalf("empty sample omission reason = %q, want empty", stats.TCPRetransmitFlowsOmittedReason)
	}

	maxFlows, omitted := budget.maxFlows(128)
	if maxFlows != 128 || omitted {
		t.Fatalf("budget after empty sample = (%d, %v), want (128, false)", maxFlows, omitted)
	}
}

func TestEBPFFlowSampleBudgetDoesNotOverridePerSampleZeroLimit(t *testing.T) {
	budget := newEBPFFlowSampleBudget(0)

	maxFlows, omitted := budget.maxFlows(0)
	if maxFlows != 0 || omitted {
		t.Fatalf("zero per-sample flow limit = (%d, %v), want (0, false)", maxFlows, omitted)
	}
}

func TestRecordRejectsInvalidPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	err := record([]string{"--pid=-1", "--ebpf=false", "--output=" + path})
	if err == nil || !strings.Contains(err.Error(), "pid must be non-negative") {
		t.Fatalf("error = %v, want pid validation error", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("output was created for invalid configuration: %v", statErr)
	}
}

func TestRecordContinuesWhenQdiscUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "capture.json")

	stderr := captureStderr(t, func() {
		err := record([]string{
			"--duration=30s",
			"--interval=1ms",
			"--max-samples=2",
			"--ebpf=false",
			"--interface=lo",
			"--output=" + path,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	if count := strings.Count(stderr, "qdisc unavailable"); count != 1 {
		t.Fatalf("qdisc warning count = %d, want 1; stderr: %s", count, stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}
	if len(recording.Samples) != 2 {
		t.Fatalf("sample count = %d, want 2", len(recording.Samples))
	}
	assertCollectorStatus(t, recording.Collectors, "tc_qdisc", model.CollectorUnavailable)
}

func TestRecordContinuesWhenTCPInfoUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "capture.json")

	stderr := captureStderr(t, func() {
		err := record([]string{
			"--duration=30s",
			"--interval=1ms",
			"--max-samples=2",
			"--ebpf=false",
			"--tcp-info",
			"--output=" + path,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	if count := strings.Count(stderr, "TCP info unavailable"); count != 1 {
		t.Fatalf("TCP info warning count = %d, want 1; stderr: %s", count, stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recording model.Recording
	if err := json.Unmarshal(data, &recording); err != nil {
		t.Fatal(err)
	}
	if len(recording.Samples) != 2 {
		t.Fatalf("sample count = %d, want 2", len(recording.Samples))
	}
	assertCollectorStatus(t, recording.Collectors, "ss_tcp_info", model.CollectorUnavailable)
}

func TestCompareCommand(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	incidentPath := filepath.Join(dir, "incident.json")

	now := time.Now()
	baseline := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 2000, Retransmits: 10}},
	}}
	incident := model.Recording{Version: model.FormatVersion, Samples: []model.Sample{
		{Timestamp: now, ElapsedNanos: int64(time.Second), TCP: model.TCPStats{OutSegments: 1000, Retransmits: 10}},
		{Timestamp: now.Add(time.Second), ElapsedNanos: int64(2 * time.Second), TCP: model.TCPStats{OutSegments: 2000, Retransmits: 40}},
	}}
	writeTestRecording(t, baselinePath, baseline)
	writeTestRecording(t, incidentPath, incident)

	stdout := captureStdout(t, func() {
		if err := compare([]string{baselinePath, incidentPath}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"Comparison:",
		"Incident-only findings:",
		"TCP retransmissions were elevated during the capture",
		"TCP retransmits: 0/1000 outbound segments (0.00%) -> 30/1000 outbound segments (3.00%)",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("compare output missing %q:\n%s", want, stdout)
		}
	}
}

func TestBuildCollectorManifest(t *testing.T) {
	tests := []struct {
		name            string
		iface           string
		pid             int
		useEBPF         bool
		useTCPInfo      bool
		interfaceStatus model.CollectorStatus
		processStatus   model.CollectorStatus
		ebpfStatus      model.CollectorStatus
		tcpInfoStatus   model.CollectorStatus
	}{
		{name: "optional collectors enabled", iface: "eth0", useEBPF: true, useTCPInfo: true, interfaceStatus: model.CollectorEnabled, processStatus: model.CollectorDisabled, ebpfStatus: model.CollectorEnabled, tcpInfoStatus: model.CollectorEnabled},
		{name: "process collector enabled", pid: 123, interfaceStatus: model.CollectorDisabled, processStatus: model.CollectorEnabled, ebpfStatus: model.CollectorDisabled, tcpInfoStatus: model.CollectorDisabled},
		{name: "optional collectors disabled", interfaceStatus: model.CollectorDisabled, processStatus: model.CollectorDisabled, ebpfStatus: model.CollectorDisabled, tcpInfoStatus: model.CollectorDisabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := buildCollectorManifest(tt.iface, tt.pid, tt.useEBPF, tt.useTCPInfo)
			if len(manifest) != 10 {
				t.Fatalf("got %d collectors, want 10", len(manifest))
			}
			assertCollectorStatus(t, manifest, "proc_tcp", model.CollectorEnabled)
			assertCollectorStatus(t, manifest, "proc_tcp_sockets", model.CollectorEnabled)
			assertCollectorStatus(t, manifest, "proc_softirq", model.CollectorEnabled)
			assertCollectorStatus(t, manifest, "proc_cpu", model.CollectorEnabled)
			assertCollectorStatus(t, manifest, "proc_pid_schedstat", tt.processStatus)
			assertCollectorStatus(t, manifest, "interface_stats", tt.interfaceStatus)
			assertCollectorStatus(t, manifest, "proc_interrupts", tt.interfaceStatus)
			assertCollectorStatus(t, manifest, "tc_qdisc", tt.interfaceStatus)
			assertCollectorStatus(t, manifest, "ebpf_tcp_retransmit", tt.ebpfStatus)
			assertCollectorStatus(t, manifest, "ss_tcp_info", tt.tcpInfoStatus)
		})
	}
}

func TestUpdateCollectorStatus(t *testing.T) {
	manifest := buildCollectorManifest("", 0, true, false)
	if err := updateCollectorStatus(manifest, "ebpf_tcp_retransmit", model.CollectorUnavailable, "permission denied"); err != nil {
		t.Fatal(err)
	}

	for _, collector := range manifest {
		if collector.CollectorName == "ebpf_tcp_retransmit" {
			if collector.Status != model.CollectorUnavailable || collector.FailureReason != "permission denied" {
				t.Fatalf("collector was not updated: %+v", collector)
			}
			return
		}
	}
	t.Fatal("eBPF collector missing")
}

func TestUpdateCollectorStatusRejectsUnknownCollector(t *testing.T) {
	manifest := buildCollectorManifest("", 0, false, false)
	if err := updateCollectorStatus(manifest, "missing", model.CollectorUnavailable, "failed"); err == nil {
		t.Fatal("expected an error")
	}
}

func assertCollectorStatus(t *testing.T, manifest []model.CollectorManifest, name string, want model.CollectorStatus) {
	t.Helper()
	for _, collector := range manifest {
		if collector.CollectorName == name {
			if collector.Status != want {
				t.Fatalf("collector %s status = %q, want %q", name, collector.Status, want)
			}
			if collector.VisibilityScope == "" {
				t.Fatalf("collector %s has no visibility scope", name)
			}
			return
		}
	}
	t.Fatalf("collector %s missing", name)
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("file mode = %04o, want %04o", got, want)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = write
	defer func() {
		os.Stderr = oldStderr
	}()

	fn()

	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeTestRecording(t *testing.T, path string, recording model.Recording) {
	t.Helper()
	data, err := json.Marshal(recording)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
