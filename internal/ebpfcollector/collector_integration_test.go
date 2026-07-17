package ebpfcollector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	rootTestsEnvironment     = "NETDIAG_ROOT_TESTS"
	trafficHelperEnvironment = "NETDIAG_RETRANSMIT_TRAFFIC_HELPER"
)

func TestTCPRetransmitIntegration(t *testing.T) {
	if os.Getenv(rootTestsEnvironment) != "1" {
		t.Skip("set NETDIAG_ROOT_TESTS=1 and run as root to enable")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration test requires root or equivalent BPF and network namespace capabilities")
	}

	unshare := requireExecutable(t, "unshare")
	ip := requireExecutable(t, "ip")
	tc := requireExecutable(t, "tc")

	collector, err := New()
	if err != nil {
		t.Fatalf("initialize eBPF collector: %v", err)
	}
	defer collector.Close()

	before, err := collector.Sample()
	if err != nil {
		t.Fatalf("sample eBPF counter before experiment: %v", err)
	}

	cmd := exec.Command(unshare, "--net", os.Args[0], "-test.run=^TestTCPRetransmitTrafficHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		trafficHelperEnvironment+"=1",
		"NETDIAG_IP_PATH="+ip,
		"NETDIAG_TC_PATH="+tc,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run isolated retransmission experiment: %v\n%s", err, output)
	}

	after, err := collector.Sample()
	if err != nil {
		t.Fatalf("sample eBPF counter after experiment: %v", err)
	}
	if after.TCPRetransmitEvents <= before.TCPRetransmitEvents {
		t.Fatalf("tcp_retransmit_skb count did not increase: before=%d after=%d", before.TCPRetransmitEvents, after.TCPRetransmitEvents)
	}
	t.Logf("tcp_retransmit_skb count increased from %d to %d", before.TCPRetransmitEvents, after.TCPRetransmitEvents)
}

// TestTCPRetransmitTrafficHelper runs only as a subprocess inside the network
// namespace created by TestTCPRetransmitIntegration.
func TestTCPRetransmitTrafficHelper(t *testing.T) {
	if os.Getenv(trafficHelperEnvironment) != "1" {
		t.Skip("integration test helper")
	}

	runCommand(t, os.Getenv("NETDIAG_IP_PATH"), "link", "set", "lo", "up")

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on isolated loopback: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("connect over isolated loopback: %v", err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatalf("accept loopback connection: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting loopback connection")
	}

	tc := os.Getenv("NETDIAG_TC_PATH")
	runCommand(t, tc, "qdisc", "add", "dev", "lo", "root", "netem", "loss", "100%")
	defer exec.Command(tc, "qdisc", "del", "dev", "lo", "root").Run()

	if _, err := client.Write([]byte("force a TCP data retransmission")); err != nil {
		t.Fatalf("write TCP data: %v", err)
	}
	// Linux's initial TCP data retransmission timeout is normally at most one
	// second. Two seconds allows the tracepoint to fire without making the
	// privileged test unnecessarily slow.
	time.Sleep(2 * time.Second)
}

func requireExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("required executable %q not found: %v", name, err)
	}
	return path
}

func runCommand(t *testing.T, path string, args ...string) {
	t.Helper()
	if path == "" {
		t.Fatalf("missing executable path for command %v", args)
	}
	if output, err := exec.Command(path, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", fmt.Sprintf("%s %v", path, args), err, output)
	}
}
