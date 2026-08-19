package collect

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/eray/netdiag/internal/model"
)

func (c Collector) ReadTCPInfo(maxSockets int) (model.TCPInfoStats, error) {
	if maxSockets < 0 {
		return model.TCPInfoStats{}, fmt.Errorf("max TCP info sockets must be non-negative")
	}
	output, err := exec.Command("ss", "-tin").Output()
	if err != nil {
		return model.TCPInfoStats{}, fmt.Errorf("run ss -tin: %w", err)
	}
	stats, err := parseTCPInfo(output)
	if err != nil {
		return model.TCPInfoStats{}, err
	}
	limitTCPInfoSockets(&stats, maxSockets)
	return stats, nil
}

func parseTCPInfo(raw []byte) (model.TCPInfoStats, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var result model.TCPInfoStats
	var current *model.TCPInfoSocket
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "State" || fields[0] == "Netid" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if current != nil {
				parseTCPInfoMetrics(fields, current)
			}
			continue
		}
		current = nil
		if fields[0] != "ESTAB" {
			continue
		}
		if len(fields) < 5 {
			return model.TCPInfoStats{}, fmt.Errorf("line %d has %d fields, want at least 5", lineNumber, len(fields))
		}

		localAddress, localPort, err := parseSSEndpoint(fields[3])
		if err != nil {
			return model.TCPInfoStats{}, fmt.Errorf("line %d local address: %w", lineNumber, err)
		}
		remoteAddress, remotePort, err := parseSSEndpoint(fields[4])
		if err != nil {
			return model.TCPInfoStats{}, fmt.Errorf("line %d remote address: %w", lineNumber, err)
		}

		result.Sockets = append(result.Sockets, model.TCPInfoSocket{
			Protocol:      tcpInfoProtocol(localAddress, remoteAddress),
			LocalAddress:  localAddress,
			LocalPort:     localPort,
			RemoteAddress: remoteAddress,
			RemotePort:    remotePort,
			State:         fields[0],
		})
		current = &result.Sockets[len(result.Sockets)-1]
	}
	if err := scanner.Err(); err != nil {
		return model.TCPInfoStats{}, err
	}

	return result, nil
}

func parseTCPInfoMetrics(fields []string, socket *model.TCPInfoSocket) {
	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "rtt:"):
			parseRTT(strings.TrimPrefix(field, "rtt:"), socket)
		case strings.HasPrefix(field, "cwnd:"):
			socket.CongestionWnd = parseOptionalUint(strings.TrimPrefix(field, "cwnd:"))
		case strings.HasPrefix(field, "bytes_acked:"):
			socket.BytesAcked = parseOptionalUint(strings.TrimPrefix(field, "bytes_acked:"))
		case strings.HasPrefix(field, "bytes_received:"):
			socket.BytesReceived = parseOptionalUint(strings.TrimPrefix(field, "bytes_received:"))
		case strings.HasPrefix(field, "retrans:"):
			socket.Retransmission = strings.TrimPrefix(field, "retrans:")
		}
	}
}

func parseRTT(raw string, socket *model.TCPInfoSocket) {
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return
	}
	if rtt, err := strconv.ParseFloat(parts[0], 64); err == nil {
		socket.RTTMillis = rtt
	}
	if rttVar, err := strconv.ParseFloat(parts[1], 64); err == nil {
		socket.RTTVarMillis = rttVar
	}
}

func parseOptionalUint(raw string) uint64 {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func parseSSEndpoint(raw string) (string, uint16, error) {
	index := strings.LastIndex(raw, ":")
	if index < 0 {
		return "", 0, fmt.Errorf("missing port in %q", raw)
	}
	address := strings.Trim(raw[:index], "[]")
	portRaw := raw[index+1:]
	portValue, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	return address, uint16(portValue), nil
}

func tcpInfoProtocol(addresses ...string) string {
	for _, address := range addresses {
		if strings.Contains(address, ":") {
			return "tcp6"
		}
	}
	return "tcp4"
}

func limitTCPInfoSockets(stats *model.TCPInfoStats, maxSockets int) {
	stats.Count = len(stats.Sockets)
	sort.Slice(stats.Sockets, func(i, j int) bool {
		if stats.Sockets[i].RTTMillis != stats.Sockets[j].RTTMillis {
			return stats.Sockets[i].RTTMillis > stats.Sockets[j].RTTMillis
		}
		if stats.Sockets[i].CongestionWnd != stats.Sockets[j].CongestionWnd {
			return stats.Sockets[i].CongestionWnd > stats.Sockets[j].CongestionWnd
		}
		if stats.Sockets[i].LocalAddress != stats.Sockets[j].LocalAddress {
			return stats.Sockets[i].LocalAddress < stats.Sockets[j].LocalAddress
		}
		return stats.Sockets[i].LocalPort < stats.Sockets[j].LocalPort
	})
	if maxSockets >= len(stats.Sockets) {
		return
	}
	stats.Truncated = len(stats.Sockets) > 0
	if maxSockets == 0 {
		stats.Sockets = nil
		return
	}
	stats.Sockets = stats.Sockets[:maxSockets]
}
