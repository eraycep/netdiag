package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/renameio/v2"

	"github.com/eray/netdiag/internal/analysis"
	"github.com/eray/netdiag/internal/collect"
	"github.com/eray/netdiag/internal/ebpfcollector"
	"github.com/eray/netdiag/internal/model"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netdiag:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "record":
		return record(args[1:])
	case "analyze":
		return analyze(args[1:])
	case "compare":
		return compare(args[1:])
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() error {
	fmt.Println("usage:\n  netdiag record [options]\n  netdiag analyze <capture.json>\n  netdiag compare <baseline.json> <incident.json>")
	return nil
}

func record(args []string) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	duration := fs.Duration("duration", 30*time.Second, "capture duration")
	interval := fs.Duration("interval", time.Second, "sample interval")
	iface := fs.String("interface", "", "network interface to monitor")
	output := fs.String("output", "capture.json", "output recording")
	useEBPF := fs.Bool("ebpf", true, "collect TCP retransmit tracepoint events when permitted")
	maxSamples := fs.Int("max-samples", 3600, "maximum samples")
	maxEBPFFlows := fs.Int("max-ebpf-flows", 128, "maximum eBPF per-flow entries to store per sample")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *duration <= 0 || *interval <= 0 {
		return errors.New("duration and interval must be positive")
	}

	hostname, _ := os.Hostname()
	kernel := "unknown"
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}

	captureStart := time.Now()

	r := model.Recording{Version: model.FormatVersion, StartedAt: captureStart.UTC(),
		Interface: *iface, Host: model.Host{Hostname: hostname, Kernel: kernel},
		Collectors: buildCollectorManifest(*iface, *useEBPF)}
	if *useEBPF {
		r.EBPFFeatures = ebpfcollector.UnavailableFeatures("collector was not initialized")
	} else {
		r.EBPFFeatures = ebpfcollector.DisabledFeatures()
	}

	c := collect.New()

	if *maxSamples < 1 {
		return errors.New("max samples must be positive")
	}

	if *maxEBPFFlows < 0 {
		return errors.New("max ebpf flows must be non-negative")
	}

	var bpfCollector *ebpfcollector.Collector
	if *useEBPF {
		var err error
		bpfCollector, err = ebpfcollector.New()
		if err != nil {
			if updateErr := updateCollectorStatus(r.Collectors, "ebpf_tcp_retransmit", model.CollectorUnavailable, err.Error()); updateErr != nil {
				return updateErr
			}
			r.EBPFFeatures = ebpfcollector.UnavailableFeatures(err.Error())
			fmt.Fprintf(os.Stderr, "netdiag: eBPF unavailable; continuing with host counters: %v\n", err)
		} else {
			r.EBPFFeatures = ebpfcollector.EnabledFeatures()
			defer bpfCollector.Close()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	deadline := time.NewTimer(*duration)
	defer deadline.Stop()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	irqCollectorActive := *iface != ""
	qdiscCollectorActive := *iface != ""

	for {
		sample, err := c.Sample(*iface)
		if err != nil {
			return err
		}

		if irqCollectorActive {
			irq, err := c.ReadInterrupts(*iface)
			if err != nil {
				irqCollectorActive = false
				if updateErr := updateCollectorStatus(r.Collectors, "proc_interrupts", model.CollectorUnavailable, err.Error()); updateErr != nil {
					return updateErr
				}
				fmt.Fprintf(os.Stderr, "netdiag: irq unavailable; continuing without irq counters: %v\n", err)
			} else {
				sample.IRQ = irq
			}
		}

		if qdiscCollectorActive {
			qdisc, err := c.ReadQdisc(*iface)
			if err != nil {
				qdiscCollectorActive = false
				if updateErr := updateCollectorStatus(r.Collectors, "tc_qdisc", model.CollectorUnavailable, err.Error()); updateErr != nil {
					return updateErr
				}
				fmt.Fprintf(os.Stderr, "netdiag: qdisc unavailable; continuing without qdisc counters: %v\n", err)
			} else {
				sample.Qdisc = qdisc
			}
		}

		sampledAt := time.Now()

		if bpfCollector != nil {
			stats, err := bpfCollector.Sample(*maxEBPFFlows)
			if err != nil {
				fmt.Fprintf(os.Stderr, "netdiag: eBPF sampling failed; disabling collector: %v\n", err)
				if updateErr := updateCollectorStatus(r.Collectors, "ebpf_tcp_retransmit", model.CollectorUnavailable, err.Error()); updateErr != nil {
					return updateErr
				}
				r.EBPFFeatures = ebpfcollector.UnavailableFeatures(err.Error())
				_ = bpfCollector.Close()
				bpfCollector = nil
			} else {
				sample.EBPF = &stats
			}
		}

		sample.Timestamp = sampledAt.UTC()
		sample.ElapsedNanos = sampledAt.Sub(captureStart).Nanoseconds()

		r.Samples = append(r.Samples, sample)
		if len(r.Samples) >= *maxSamples {
			r.EndedAt = time.Now().UTC()
			return writeRecording(*output, r)
		}
		select {
		case <-deadline.C:
			r.EndedAt = time.Now().UTC()
			return writeRecording(*output, r)
		case <-ctx.Done():
			r.EndedAt = time.Now().UTC()
			return writeRecording(*output, r)
		case <-ticker.C:
		}
	}
}

func writeRecording(path string, r model.Recording) error {
	return atomicWriteRecording(path, r)
}

func atomicWriteRecording(path string, r model.Recording) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	pending, err := renameio.NewPendingFile(path, renameio.WithStaticPermissions(0o600))
	if err != nil {
		return err
	}
	defer pending.Cleanup()

	if _, err := pending.Write(data); err != nil {
		return fmt.Errorf("write recording: %w", err)
	}
	return pending.CloseAtomicallyReplace()
}

func analyze(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: netdiag analyze <capture.json>")
	}
	r, err := readRecording(args[0])
	if err != nil {
		return err
	}
	findings, err := analysis.Analyze(r)
	if err != nil {
		return err
	}
	fmt.Print(analysis.Render(findings))
	return nil
}

func compare(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: netdiag compare <baseline.json> <incident.json>")
	}
	baseline, err := readRecording(args[0])
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	incident, err := readRecording(args[1])
	if err != nil {
		return fmt.Errorf("read incident: %w", err)
	}
	comparison, err := analysis.Compare(baseline, incident)
	if err != nil {
		return err
	}
	fmt.Print(analysis.RenderComparison(args[0], args[1], comparison))
	return nil
}

func readRecording(path string) (model.Recording, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Recording{}, err
	}
	var r model.Recording
	if err := json.Unmarshal(data, &r); err != nil {
		return model.Recording{}, fmt.Errorf("decode recording: %w", err)
	}
	return r, nil
}

func buildCollectorManifest(iface string, useEBPF bool) []model.CollectorManifest {
	interfaceStatus := model.CollectorDisabled
	if iface != "" {
		interfaceStatus = model.CollectorEnabled
	}
	interruptStatus := model.CollectorDisabled
	if iface != "" {
		interruptStatus = model.CollectorEnabled
	}
	qdiscStatus := model.CollectorDisabled
	if iface != "" {
		qdiscStatus = model.CollectorEnabled
	}
	ebpfStatus := model.CollectorDisabled
	if useEBPF {
		ebpfStatus = model.CollectorEnabled
	}

	return []model.CollectorManifest{
		{
			CollectorName:   "proc_tcp",
			Status:          model.CollectorEnabled,
			VisibilityScope: "host-wide TCP counters; not scoped to an interface, process, socket, or flow",
		},
		{
			CollectorName:   "proc_softirq",
			Status:          model.CollectorEnabled,
			VisibilityScope: "host-wide NET_RX and NET_TX softirq counters preserved per CPU and as totals",
		},
		{
			CollectorName:   "proc_cpu",
			Status:          model.CollectorEnabled,
			VisibilityScope: "host per-CPU scheduler counters from /proc/stat and optional CPU pressure from /proc/pressure/cpu",
		},
		{
			CollectorName:   "interface_stats",
			Status:          interfaceStatus,
			VisibilityScope: "selected network interface",
		},
		{
			CollectorName:   "proc_interrupts",
			Status:          interruptStatus,
			VisibilityScope: "host interrupt counts and affinity for IRQs associated with the selected interface",
		},
		{
			CollectorName:   "tc_qdisc",
			Status:          qdiscStatus,
			VisibilityScope: "qdisc counters for the selected interface from tc -s qdisc",
		},
		{
			CollectorName:   "ebpf_tcp_retransmit",
			Status:          ebpfStatus,
			VisibilityScope: "host-wide TCP retransmission events; not scoped to an interface, process, socket, or flow",
		},
	}
}

func updateCollectorStatus(collectors []model.CollectorManifest, name string, status model.CollectorStatus, reason string) error {
	for i := range collectors {
		if collectors[i].CollectorName == name {
			collectors[i].Status = status
			collectors[i].FailureReason = reason
			return nil
		}
	}
	return fmt.Errorf("collector %q not found in manifest", name)
}
