package collect

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

const tcpEstablishedState = "01"

func (c Collector) readTCPSockets(maxTCPSocketQueues int) (model.TCPSocketStats, error) {
	var result model.TCPSocketStats
	if err := c.readTCPSocketFile("net/tcp", &result, false, "tcp4"); err != nil {
		return model.TCPSocketStats{}, err
	}
	if err := c.readTCPSocketFile("net/tcp6", &result, true, "tcp6"); err != nil {
		return model.TCPSocketStats{}, err
	}
	limitTCPSocketQueues(&result, maxTCPSocketQueues)
	return result, nil
}

func (c Collector) readTCPSocketFile(name string, result *model.TCPSocketStats, optional bool, protocol string) error {
	f, err := os.Open(filepath.Join(c.ProcRoot, name))
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open /proc/%s: %w", name, err)
	}
	defer f.Close()

	if err := parseTCPSocketStats(f, result, protocol); err != nil {
		return fmt.Errorf("parse /proc/%s: %w", name, err)
	}
	return nil
}

func parseTCPSocketStats(r io.Reader, result *model.TCPSocketStats, protocol string) error {
	if protocol != "tcp4" && protocol != "tcp6" {
		return fmt.Errorf("unsupported TCP socket protocol %q", protocol)
	}

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
		if txQueue == 0 && rxQueue == 0 {
			continue
		}

		localAddress, localPort, err := parseTCPEndpoint(fields[1], protocol)
		if err != nil {
			return fmt.Errorf("line %d local address: %w", lineNumber, err)
		}
		remoteAddress, remotePort, err := parseTCPEndpoint(fields[2], protocol)
		if err != nil {
			return fmt.Errorf("line %d remote address: %w", lineNumber, err)
		}

		result.TopQueues = append(result.TopQueues, model.TCPSocketQueue{
			Protocol:      protocol,
			LocalAddress:  localAddress,
			LocalPort:     localPort,
			RemoteAddress: remoteAddress,
			RemotePort:    remotePort,
			State:         fields[3],
			TXQueue:       txQueue,
			RXQueue:       rxQueue,
		})
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

func parseTCPEndpoint(raw string, protocol string) (addr string, port uint16, err error) {
	fields := strings.Split(raw, ":")
	if len(fields) != 2 {
		return "", 0, fmt.Errorf("invalid address: %q", raw)
	}

	ipBytes, err := hex.DecodeString(fields[0])
	if err != nil {
		return "", 0, fmt.Errorf("parse address: %w", err)
	}

	switch protocol {
	case "tcp4":
		if len(ipBytes) != 4 {
			return "", 0, fmt.Errorf("invalid IPv4 address length %d", len(ipBytes))
		}
		reverseBytes(ipBytes)
	case "tcp6":
		if len(ipBytes) != 16 {
			return "", 0, fmt.Errorf("invalid IPv6 address length %d", len(ipBytes))
		}
		for offset := 0; offset < len(ipBytes); offset += 4 {
			reverseBytes(ipBytes[offset : offset+4])
		}
	default:
		return "", 0, fmt.Errorf("unsupported protocol %q", protocol)
	}

	portValue, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}

	return net.IP(ipBytes).String(), uint16(portValue), nil
}

func reverseBytes(values []byte) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func limitTCPSocketQueues(stats *model.TCPSocketStats, maxQueues int) {
	stats.SocketQueueCount = len(stats.TopQueues)
	sort.Slice(stats.TopQueues, func(i, j int) bool {
		leftTotal := stats.TopQueues[i].RXQueue + stats.TopQueues[i].TXQueue
		rightTotal := stats.TopQueues[j].RXQueue + stats.TopQueues[j].TXQueue
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if stats.TopQueues[i].RXQueue != stats.TopQueues[j].RXQueue {
			return stats.TopQueues[i].RXQueue > stats.TopQueues[j].RXQueue
		}
		if stats.TopQueues[i].TXQueue != stats.TopQueues[j].TXQueue {
			return stats.TopQueues[i].TXQueue > stats.TopQueues[j].TXQueue
		}
		if stats.TopQueues[i].LocalAddress != stats.TopQueues[j].LocalAddress {
			return stats.TopQueues[i].LocalAddress < stats.TopQueues[j].LocalAddress
		}
		if stats.TopQueues[i].LocalPort != stats.TopQueues[j].LocalPort {
			return stats.TopQueues[i].LocalPort < stats.TopQueues[j].LocalPort
		}
		if stats.TopQueues[i].RemoteAddress != stats.TopQueues[j].RemoteAddress {
			return stats.TopQueues[i].RemoteAddress < stats.TopQueues[j].RemoteAddress
		}
		return stats.TopQueues[i].RemotePort < stats.TopQueues[j].RemotePort
	})

	if maxQueues >= len(stats.TopQueues) {
		return
	}
	stats.TopQueuesTruncated = len(stats.TopQueues) > 0
	if maxQueues == 0 {
		stats.TopQueues = nil
		return
	}
	stats.TopQueues = stats.TopQueues[:maxQueues]
}
