package collect

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

type Collector struct {
	ProcRoot string
	SysRoot  string
}

func New() Collector { return Collector{ProcRoot: "/proc", SysRoot: "/sys"} }

func (c Collector) Sample(iface string) (model.Sample, error) {
	tcp, err := c.readTCP()
	if err != nil {
		return model.Sample{}, err
	}
	tcpSockets, err := c.readTCPSockets()
	if err != nil {
		return model.Sample{}, err
	}
	softirq, err := c.readSoftIRQs()
	if err != nil {
		return model.Sample{}, err
	}
	cpu, err := c.readCPU()
	if err != nil {
		return model.Sample{}, err
	}
	s := model.Sample{TCP: tcp, TCPSockets: tcpSockets, SoftIRQ: softirq, CPU: cpu}
	if iface != "" {
		stats, err := c.readInterface(iface)
		if err != nil {
			return model.Sample{}, err
		}
		s.Interface = &stats
	}
	return s, nil
}

func (c Collector) ReadInterrupts(iface string) (model.IRQStats, error) {
	irq, err := c.readInterrupts(iface)
	if err != nil {
		return model.IRQStats{}, err
	}

	return irq, nil
}

func (c Collector) ReadQdisc(iface string) (model.QdiscStats, error) {
	qdisc, err := c.readQdisc(iface)
	if err != nil {
		return model.QdiscStats{}, err
	}

	return qdisc, nil
}

func (c Collector) readTCP() (model.TCPStats, error) {
	f, err := os.Open(filepath.Join(c.ProcRoot, "net/snmp"))
	if err != nil {
		return model.TCPStats{}, fmt.Errorf("open TCP counters: %w", err)
	}
	defer f.Close()
	var header []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "Tcp:" {
			continue
		}
		if header == nil {
			header = fields[1:]
			continue
		}
		values := fields[1:]
		if len(values) != len(header) {
			return model.TCPStats{}, errors.New("malformed Tcp section in /proc/net/snmp")
		}
		m := make(map[string]uint64, 4)
		for i, name := range header {
			switch name {
			case "InSegs", "OutSegs", "RetransSegs", "InErrs":
			default:
				continue
			}
			value, parseErr := strconv.ParseUint(values[i], 10, 64)
			if parseErr != nil {
				return model.TCPStats{}, fmt.Errorf("parse TCP counter %s: %w", name, parseErr)
			}
			m[name] = value
		}
		for _, name := range []string{"InSegs", "OutSegs", "RetransSegs", "InErrs"} {
			if _, ok := m[name]; !ok {
				return model.TCPStats{}, fmt.Errorf("malformed Tcp section in /proc/net/snmp: missing %s", name)
			}
		}
		return model.TCPStats{InSegments: m["InSegs"], OutSegments: m["OutSegs"], Retransmits: m["RetransSegs"], InErrors: m["InErrs"]}, nil
	}
	if err := scanner.Err(); err != nil {
		return model.TCPStats{}, err
	}
	return model.TCPStats{}, errors.New("Tcp section not found in /proc/net/snmp")
}

func (c Collector) readSoftIRQs() (model.SoftIRQStats, error) {
	f, err := os.Open(filepath.Join(c.ProcRoot, "softirqs"))
	if err != nil {
		return model.SoftIRQStats{}, fmt.Errorf("open softirq counters: %w", err)
	}
	defer f.Close()
	var foundRX, foundTX bool
	scanner := bufio.NewScanner(f)
	cpuIDs, err := findAvailableCPUs(scanner)
	if err != nil {
		return model.SoftIRQStats{}, err
	}
	result := model.SoftIRQStats{
		CPUs: make([]model.SoftIRQCPUStats, len(cpuIDs)),
	}
	for i, cpu := range cpuIDs {
		result.CPUs[i].CPU = cpu
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if len(fields)-1 != len(cpuIDs) {
			return model.SoftIRQStats{}, fmt.Errorf("malformed /proc/softirqs: %s row has %d counters for %d CPUs", strings.TrimSuffix(fields[0], ":"), len(fields)-1, len(cpuIDs))
		}
		var total *uint64
		var assign func(int, uint64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "NET_RX":
			if foundRX {
				return model.SoftIRQStats{}, errors.New("malformed /proc/softirqs: duplicate NET_RX row")
			}
			total = &result.NetRX
			foundRX = true
			assign = func(i int, value uint64) { result.CPUs[i].NetRX = value }
		case "NET_TX":
			if foundTX {
				return model.SoftIRQStats{}, errors.New("malformed /proc/softirqs: duplicate NET_TX row")
			}
			total = &result.NetTX
			foundTX = true
			assign = func(i int, value uint64) { result.CPUs[i].NetTX = value }
		default:
			continue
		}
		for i, raw := range fields[1:] {
			value, parseErr := strconv.ParseUint(raw, 10, 64)
			if parseErr != nil {
				return model.SoftIRQStats{}, fmt.Errorf("parse softirq counter: %w", parseErr)
			}
			*total += value
			assign(i, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return model.SoftIRQStats{}, err
	}
	if !foundRX || !foundTX {
		return model.SoftIRQStats{}, errors.New("malformed /proc/softirqs: NET_RX and NET_TX rows are required")
	}
	return result, nil
}

func (c Collector) readInterface(iface string) (model.InterfaceStats, error) {
	if iface == "" || strings.ContainsAny(iface, "/\\") {
		return model.InterfaceStats{}, errors.New("invalid interface name")
	}
	base := filepath.Join(c.SysRoot, "class/net", iface, "statistics")
	read := func(name string) (uint64, error) {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			return 0, fmt.Errorf("read %s counter for %s: %w", name, iface, err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s counter for %s: %w", name, iface, err)
		}
		return value, nil
	}
	var s model.InterfaceStats
	fields := []struct {
		name string
		dst  *uint64
	}{
		{"rx_packets", &s.RXPackets}, {"tx_packets", &s.TXPackets},
		{"rx_bytes", &s.RXBytes}, {"tx_bytes", &s.TXBytes},
		{"rx_dropped", &s.RXDropped}, {"tx_dropped", &s.TXDropped},
		{"rx_errors", &s.RXErrors}, {"tx_errors", &s.TXErrors},
	}
	for _, field := range fields {
		value, err := read(field.name)
		if err != nil {
			return s, err
		}
		*field.dst = value
	}
	return s, nil
}

func (c Collector) readInterrupts(iface string) (model.IRQStats, error) {
	if iface == "" {
		return model.IRQStats{}, nil
	}
	if strings.ContainsAny(iface, "/\\") {
		return model.IRQStats{}, errors.New("invalid interface name")
	}

	f, err := os.Open(filepath.Join(c.ProcRoot, "interrupts"))
	if err != nil {
		return model.IRQStats{}, fmt.Errorf("open interrupt counters: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	cpuIDs, err := findAvailableCPUs(scanner)
	if err != nil {
		return model.IRQStats{}, err
	}

	numCPUs := len(cpuIDs)
	interfaceIRQs := c.interfaceIRQIDs(iface)
	var irqLines []model.IRQLineStats

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < numCPUs+2 {
			continue
		}

		description := strings.Join(fields[numCPUs+1:], " ")
		irqNumber := strings.TrimSuffix(fields[0], ":")
		irqNumberInt, err := strconv.Atoi(irqNumber)
		if err != nil {
			continue
		}
		if _, ok := interfaceIRQs[irqNumber]; !ok && !strings.Contains(description, iface) {
			continue
		}

		counts := make([]uint64, numCPUs)
		for i := range numCPUs {
			val, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return model.IRQStats{}, fmt.Errorf("parse interrupt counter for IRQ %s CPU%d: %w", irqNumber, cpuIDs[i], err)
			}
			counts[i] = val
		}

		var affinity []int
		raw, err := c.readInterruptAffinity(irqNumberInt)
		if err == nil {
			affinity, err = parseCPUList(raw)
			if err != nil {
				return model.IRQStats{}, fmt.Errorf("parse interrupt affinity for IRQ %s: %w", irqNumber, err)
			}
		}

		lineStats := model.IRQLineStats{
			IRQ:      irqNumber,
			Name:     description,
			Counts:   counts,
			CPUs:     cpuIDs,
			Affinity: affinity,
		}

		irqLines = append(irqLines, lineStats)
	}

	if err := scanner.Err(); err != nil {
		return model.IRQStats{}, fmt.Errorf("error reading interrupts: %w", err)
	}

	return model.IRQStats{
		IRQs: irqLines,
	}, nil
}

func (c Collector) interfaceIRQIDs(iface string) map[string]struct{} {
	entries, err := os.ReadDir(filepath.Join(c.SysRoot, "class/net", iface, "device/msi_irqs"))
	if err != nil {
		return nil
	}

	irqIDs := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		irqIDs[entry.Name()] = struct{}{}
	}
	return irqIDs
}

func findAvailableCPUs(scanner *bufio.Scanner) ([]int, error) {
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		cpus := make([]int, 0, len(fields))
		seen := make(map[int]struct{}, len(fields))
		for _, field := range fields {
			rawID, ok := strings.CutPrefix(field, "CPU")
			if !ok || rawID == "" {
				return nil, fmt.Errorf("malformed /proc/softirqs: invalid CPU header field %q", field)
			}
			cpu, err := strconv.Atoi(rawID)
			if err != nil || cpu < 0 {
				return nil, fmt.Errorf("malformed /proc/softirqs: invalid CPU header field %q", field)
			}
			if _, ok := seen[cpu]; ok {
				return nil, fmt.Errorf("malformed /proc/softirqs: duplicate CPU%d header field", cpu)
			}
			seen[cpu] = struct{}{}
			cpus = append(cpus, cpu)
		}
		if len(cpus) == 0 {
			return nil, errors.New("malformed /proc/softirqs: CPU header is required")
		}
		return cpus, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("malformed /proc/softirqs: CPU header is required")
}

func parseCPUList(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty CPU list")
	}

	var cpus []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid CPU list %q", raw)
		}

		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid CPU range %q", part)
		}

		start, err := strconv.Atoi(bounds[0])
		if err != nil {
			return nil, fmt.Errorf("invalid CPU %q: %w", bounds[0], err)
		}
		if start < 0 {
			return nil, fmt.Errorf("invalid negative CPU %d", start)
		}

		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid CPU %q: %w", bounds[1], err)
			}
			if end < start {
				return nil, fmt.Errorf("invalid descending CPU range %q", part)
			}
		}

		for cpu := start; cpu <= end; cpu++ {
			if _, ok := seen[cpu]; ok {
				continue
			}
			seen[cpu] = struct{}{}
			cpus = append(cpus, cpu)
		}
	}

	return cpus, nil
}

func (c Collector) readInterruptAffinity(irq int) (string, error) {
	path := filepath.Join(c.ProcRoot, "irq", strconv.Itoa(irq), "smp_affinity_list")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read irq affinity: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
