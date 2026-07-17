package collect

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

var (
	procStatCPULineRE      = regexp.MustCompile(`^cpu([0-9]+)\s+(.+)$`)
	procStatProcsRunningRE = regexp.MustCompile(`^procs_running\s+([0-9]+)$`)
)

func (c Collector) readCPU() (model.CPUStats, error) {
	stats, err := c.readCPUStat()
	if err != nil {
		return model.CPUStats{}, err
	}

	pressure, err := c.readCPUPressure()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stats, nil
		}
		return model.CPUStats{}, err
	}
	stats.Pressure = pressure

	return stats, nil
}

func (c Collector) readCPUStat() (model.CPUStats, error) {
	f, err := os.Open(filepath.Join(c.ProcRoot, "stat"))
	if err != nil {
		return model.CPUStats{}, fmt.Errorf("open CPU stat: %w", err)
	}
	defer f.Close()

	var cpus []model.CPUTimeStats
	seenCPUs := map[int]struct{}{}
	var foundProcsRunning bool
	var procsRunning uint64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if matches := procStatCPULineRE.FindStringSubmatch(line); matches != nil {
			cpu, err := strconv.Atoi(matches[1])
			if err != nil {
				return model.CPUStats{}, fmt.Errorf("parse CPU id %q: %w", matches[1], err)
			}
			if _, ok := seenCPUs[cpu]; ok {
				return model.CPUStats{}, fmt.Errorf("duplicate cpu%d row in /proc/stat", cpu)
			}
			seenCPUs[cpu] = struct{}{}

			parsed, err := parseCPUTimeFields(cpu, strings.Fields(matches[2]))
			if err != nil {
				return model.CPUStats{}, err
			}
			cpus = append(cpus, parsed)
			continue
		}

		if matches := procStatProcsRunningRE.FindStringSubmatch(line); matches != nil {
			value, err := strconv.ParseUint(matches[1], 10, 64)
			if err != nil {
				return model.CPUStats{}, fmt.Errorf("parse procs_running: %w", err)
			}
			procsRunning = value
			foundProcsRunning = true
		}
	}
	if err := scanner.Err(); err != nil {
		return model.CPUStats{}, err
	}

	if len(cpus) == 0 {
		return model.CPUStats{}, errors.New("malformed /proc/stat: no per-CPU rows found")
	}
	if !foundProcsRunning {
		return model.CPUStats{}, errors.New("malformed /proc/stat: procs_running row is required")
	}

	return model.CPUStats{
		CPUs:         cpus,
		ProcsRunning: procsRunning,
	}, nil
}

func parseCPUTimeFields(cpu int, fields []string) (model.CPUTimeStats, error) {
	if len(fields) < 7 {
		return model.CPUTimeStats{}, fmt.Errorf("malformed /proc/stat: cpu%d has %d fields, want at least 7", cpu, len(fields))
	}

	values := make([]uint64, len(fields))
	for i, raw := range fields {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return model.CPUTimeStats{}, fmt.Errorf("parse /proc/stat cpu%d field %d: %w", cpu, i, err)
		}
		values[i] = value
	}

	stat := model.CPUTimeStats{
		CPU:     cpu,
		User:    values[0],
		Nice:    values[1],
		System:  values[2],
		Idle:    values[3],
		IOWait:  values[4],
		IRQ:     values[5],
		SoftIRQ: values[6],
	}
	if len(values) > 7 {
		stat.Steal = values[7]
	}

	return stat, nil
}

func (c Collector) readCPUPressure() (*model.CPUPressureStats, error) {
	data, err := os.ReadFile(filepath.Join(c.ProcRoot, "pressure/cpu"))
	if err != nil {
		return nil, fmt.Errorf("read CPU pressure: %w", err)
	}
	return parseCPUPressure(string(data))
}

func parseCPUPressure(raw string) (*model.CPUPressureStats, error) {
	var stats model.CPUPressureStats
	var foundSome, foundFull bool

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 {
			return nil, fmt.Errorf("malformed /proc/pressure/cpu line %q", line)
		}

		values, err := parseCPUPressureValues(fields[1:])
		if err != nil {
			return nil, err
		}

		switch fields[0] {
		case "some":
			stats.SomeAvg10 = values.avg10
			stats.SomeAvg60 = values.avg60
			stats.SomeAvg300 = values.avg300
			stats.SomeTotal = values.total
			foundSome = true
		case "full":
			stats.FullAvg10 = values.avg10
			stats.FullAvg60 = values.avg60
			stats.FullAvg300 = values.avg300
			stats.FullTotal = values.total
			foundFull = true
		default:
			return nil, fmt.Errorf("malformed /proc/pressure/cpu: unknown pressure class %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !foundSome || !foundFull {
		return nil, errors.New("malformed /proc/pressure/cpu: some and full rows are required")
	}

	return &stats, nil
}

type cpuPressureValues struct {
	avg10  float64
	avg60  float64
	avg300 float64
	total  uint64
}

func parseCPUPressureValues(fields []string) (cpuPressureValues, error) {
	var values cpuPressureValues
	seen := map[string]struct{}{}
	for _, field := range fields {
		name, raw, ok := strings.Cut(field, "=")
		if !ok || name == "" || raw == "" {
			return cpuPressureValues{}, fmt.Errorf("malformed CPU pressure field %q", field)
		}
		if _, ok := seen[name]; ok {
			return cpuPressureValues{}, fmt.Errorf("duplicate CPU pressure field %q", name)
		}
		seen[name] = struct{}{}

		switch name {
		case "avg10":
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				return cpuPressureValues{}, fmt.Errorf("parse CPU pressure avg10: %w", err)
			}
			values.avg10 = value
		case "avg60":
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				return cpuPressureValues{}, fmt.Errorf("parse CPU pressure avg60: %w", err)
			}
			values.avg60 = value
		case "avg300":
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				return cpuPressureValues{}, fmt.Errorf("parse CPU pressure avg300: %w", err)
			}
			values.avg300 = value
		case "total":
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return cpuPressureValues{}, fmt.Errorf("parse CPU pressure total: %w", err)
			}
			values.total = value
		default:
			return cpuPressureValues{}, fmt.Errorf("unknown CPU pressure field %q", name)
		}
	}
	for _, required := range []string{"avg10", "avg60", "avg300", "total"} {
		if _, ok := seen[required]; !ok {
			return cpuPressureValues{}, fmt.Errorf("missing CPU pressure field %q", required)
		}
	}
	return values, nil
}
