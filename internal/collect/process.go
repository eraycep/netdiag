package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

func (c Collector) ReadProcessSchedstat(pid int) (model.ProcessStats, error) {
	if pid <= 0 {
		return model.ProcessStats{}, fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(filepath.Join(c.ProcRoot, strconv.Itoa(pid), "schedstat"))
	if err != nil {
		return model.ProcessStats{}, fmt.Errorf("read schedstat for pid %d: %w", pid, err)
	}
	stats, err := parseProcessSchedstat(string(data))
	if err != nil {
		return model.ProcessStats{}, fmt.Errorf("parse schedstat for pid %d: %w", pid, err)
	}
	stats.PID = pid
	return stats, nil
}

func parseProcessSchedstat(raw string) (model.ProcessStats, error) {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return model.ProcessStats{}, fmt.Errorf("expected 3 fields, got %d", len(fields))
	}

	runtime, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return model.ProcessStats{}, fmt.Errorf("parse runtime: %w", err)
	}
	runqueueWait, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return model.ProcessStats{}, fmt.Errorf("parse runqueue wait: %w", err)
	}
	timeslices, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return model.ProcessStats{}, fmt.Errorf("parse timeslices: %w", err)
	}

	return model.ProcessStats{
		RuntimeNanos:      runtime,
		RunqueueWaitNanos: runqueueWait,
		Timeslices:        timeslices,
	}, nil
}
