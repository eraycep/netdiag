package collect

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

const tcpEstablishedState = "01"

func (c Collector) readTCPSockets() (model.TCPSocketStats, error) {
	var result model.TCPSocketStats
	if err := c.readTCPSocketFile("net/tcp", &result, false); err != nil {
		return model.TCPSocketStats{}, err
	}
	if err := c.readTCPSocketFile("net/tcp6", &result, true); err != nil {
		return model.TCPSocketStats{}, err
	}
	return result, nil
}

func (c Collector) readTCPSocketFile(name string, result *model.TCPSocketStats, optional bool) error {
	f, err := os.Open(filepath.Join(c.ProcRoot, name))
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open /proc/%s: %w", name, err)
	}
	defer f.Close()

	if err := parseTCPSocketStats(f, result); err != nil {
		return fmt.Errorf("parse /proc/%s: %w", name, err)
	}
	return nil
}

func parseTCPSocketStats(r io.Reader, result *model.TCPSocketStats) error {
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if lineNumber == 1 && fields[0] == "sl" {
			continue
		}
		if len(fields) < 5 {
			return fmt.Errorf("line %d has %d fields, want at least 5", lineNumber, len(fields))
		}

		txQueue, rxQueue, err := parseTCPQueueField(fields[4])
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNumber, err)
		}

		result.Sockets++
		if fields[3] == tcpEstablishedState {
			result.Established++
		}
		result.TXQueue += txQueue
		result.RXQueue += rxQueue
		if txQueue > result.MaxTXQueue {
			result.MaxTXQueue = txQueue
		}
		if rxQueue > result.MaxRXQueue {
			result.MaxRXQueue = rxQueue
		}
		if txQueue > 0 {
			result.NonZeroTXSockets++
		}
		if rxQueue > 0 {
			result.NonZeroRXSockets++
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func parseTCPQueueField(raw string) (uint64, uint64, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid queue field %q", raw)
	}
	txQueue, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse tx_queue: %w", err)
	}
	rxQueue, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse rx_queue: %w", err)
	}
	return txQueue, rxQueue, nil
}
