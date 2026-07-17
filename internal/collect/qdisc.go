package collect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/eray/netdiag/internal/model"
)

var (
	// Matches: Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
	line2Regex = regexp.MustCompile(`Sent\s+(?P<bytes>\d+)\s+bytes\s+(?P<pkts>\d+)\s+pkt\s+\(dropped\s+(?P<drops>\d+),\s+overlimits\s+(?P<overlimits>\d+)\s+requeues\s+(?P<requeues>\d+)\)`)
	// Matches: backlog 0b 0p ...
	line3Regex = regexp.MustCompile(`backlog\s+(?P<bbytes>\d+)[bB]\s+(?P<bpkts>\d+)[pP]`)

	qdiscCommand = func(ctx context.Context, iface string) ([]byte, error) {
		if _, err := exec.LookPath("tc"); err != nil {
			return nil, fmt.Errorf("tc command unavailable: %w", err)
		}
		return exec.CommandContext(ctx, "tc", "-s", "qdisc", "show", "dev", iface).CombinedOutput()
	}
)

func (c Collector) readQdisc(iface string) (model.QdiscStats, error) {
	if iface == "" {
		return model.QdiscStats{}, nil
	}
	if strings.ContainsAny(iface, "/\\") {
		return model.QdiscStats{}, fmt.Errorf("qdisc collector invalid interface name")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out, err := qdiscCommand(ctx, iface)
	if ctx.Err() != nil {
		return model.QdiscStats{}, fmt.Errorf("tc command timed out: %w", ctx.Err())
	}
	if err != nil {
		return model.QdiscStats{}, fmt.Errorf("tc command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	qdisc, err := parseQdiscStats(iface, string(out))
	if err != nil {
		return model.QdiscStats{}, fmt.Errorf("qdisc parse failed with: %w", err)
	}

	return qdisc, nil
}

func findNamedMatches(re *regexp.Regexp, text string) map[string]string {
	match := re.FindStringSubmatch(text)
	results := make(map[string]string)
	if match == nil {
		return results
	}
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			results[name] = match[i]
		}
	}
	return results
}

func parseRequiredUint(matches map[string]string, name string) (uint64, error) {
	raw, ok := matches[name]
	if !ok || raw == "" {
		return 0, fmt.Errorf("missing %s", name)
	}
	val, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return val, nil
}

func parseQdiscHeader(iface, line string) (model.QdiscLineStats, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "qdisc" {
		return model.QdiscLineStats{}, fmt.Errorf("malformed qdisc header %q", line)
	}

	qdisc := model.QdiscLineStats{
		Interface: iface,
		Kind:      fields[1],
		Handle:    strings.TrimSuffix(fields[2], ":"),
	}
	for i := 3; i < len(fields); i++ {
		switch fields[i] {
		case "root", "ingress":
			qdisc.Parent = fields[i]
		case "parent":
			if i+1 >= len(fields) {
				return model.QdiscLineStats{}, fmt.Errorf("malformed qdisc parent in %q", line)
			}
			qdisc.Parent = strings.TrimSuffix(fields[i+1], ":")
			i++
		}
	}
	return qdisc, nil
}

func applySentLine(qdisc *model.QdiscLineStats, line string) error {
	matches := findNamedMatches(line2Regex, line)
	if len(matches) == 0 {
		return fmt.Errorf("malformed qdisc Sent line %q", line)
	}

	var err error
	if qdisc.Bytes, err = parseRequiredUint(matches, "bytes"); err != nil {
		return err
	}
	if qdisc.Packets, err = parseRequiredUint(matches, "pkts"); err != nil {
		return err
	}
	if qdisc.Drops, err = parseRequiredUint(matches, "drops"); err != nil {
		return err
	}
	if qdisc.Overlimits, err = parseRequiredUint(matches, "overlimits"); err != nil {
		return err
	}
	if qdisc.Requeues, err = parseRequiredUint(matches, "requeues"); err != nil {
		return err
	}
	return nil
}

func applyBacklogLine(qdisc *model.QdiscLineStats, line string) error {
	matches := findNamedMatches(line3Regex, line)
	if len(matches) == 0 {
		return fmt.Errorf("malformed qdisc backlog line %q", line)
	}

	var err error
	if qdisc.BacklogBytes, err = parseRequiredUint(matches, "bbytes"); err != nil {
		return err
	}
	if qdisc.BacklogPackets, err = parseRequiredUint(matches, "bpkts"); err != nil {
		return err
	}
	return nil
}

func parseQdiscStats(iface string, raw string) (model.QdiscStats, error) {
	var stats model.QdiscStats
	scanner := bufio.NewScanner(strings.NewReader(raw))

	var currentQdisc *model.QdiscLineStats

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "qdisc") {
			if currentQdisc != nil {
				stats.Qdiscs = append(stats.Qdiscs, *currentQdisc)
			}
			qdisc, err := parseQdiscHeader(iface, line)
			if err != nil {
				return model.QdiscStats{}, err
			}
			currentQdisc = &qdisc
			continue
		}

		if strings.HasPrefix(line, "Sent ") {
			if currentQdisc == nil {
				return model.QdiscStats{}, errors.New("malformed qdisc output: Sent line before qdisc header")
			}
			if err := applySentLine(currentQdisc, line); err != nil {
				return model.QdiscStats{}, err
			}
			continue
		}

		if strings.HasPrefix(line, "backlog ") {
			if currentQdisc == nil {
				return model.QdiscStats{}, errors.New("malformed qdisc output: backlog line before qdisc header")
			}
			if err := applyBacklogLine(currentQdisc, line); err != nil {
				return model.QdiscStats{}, err
			}
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return model.QdiscStats{}, err
	}

	if currentQdisc != nil {
		stats.Qdiscs = append(stats.Qdiscs, *currentQdisc)
	}

	return stats, nil
}
