package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: netdiag-workload server|client [options]")
	}
	switch args[0] {
	case "server":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:18080", "listen address")
	payloadBytes := fs.Int("payload-bytes", 1024*1024, "response payload size in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *payloadBytes < 1 {
		return errors.New("payload-bytes must be positive")
	}

	payload := make([]byte, *payloadBytes)
	for i := range payload {
		payload[i] = 'x'
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/payload", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	})
	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	log.Printf("serving %d byte payload on %s", len(payload), *listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	url := fs.String("url", "http://127.0.0.1:18080/payload", "URL to fetch")
	duration := fs.Duration("duration", 30*time.Second, "measurement duration")
	concurrency := fs.Int("concurrency", 32, "concurrent workers")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 {
		return errors.New("duration must be positive")
	}
	if *concurrency < 1 {
		return errors.New("concurrency must be positive")
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	stats := executeClient(*url, *duration, *concurrency, *timeout)
	fmt.Printf("HTTP requests: %d succeeded, %d failed\n", stats.succeeded, stats.failed)
	fmt.Printf(
		"Latency milliseconds: p50=%.3f p95=%.3f p99=%.3f\n",
		percentile(stats.latenciesMillis, 50),
		percentile(stats.latenciesMillis, 95),
		percentile(stats.latenciesMillis, 99),
	)
	if stats.succeeded == 0 {
		return errors.New("no successful requests")
	}
	return nil
}

type clientStats struct {
	succeeded       uint64
	failed          uint64
	latenciesMillis []float64
}

func executeClient(url string, duration time.Duration, concurrency int, timeout time.Duration) clientStats {
	deadline := time.Now().Add(duration)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          concurrency * 2,
			MaxIdleConnsPerHost:   concurrency * 2,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
	}

	var succeeded atomic.Uint64
	var failed atomic.Uint64
	latenciesByWorker := make([][]float64, concurrency)
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				start := time.Now()
				if err := fetch(context.Background(), client, url); err != nil {
					failed.Add(1)
					continue
				}
				latenciesByWorker[worker] = append(latenciesByWorker[worker], float64(time.Since(start).Microseconds())/1000)
				succeeded.Add(1)
			}
		}(worker)
	}
	wg.Wait()

	var latencies []float64
	for _, workerLatencies := range latenciesByWorker {
		latencies = append(latencies, workerLatencies...)
	}
	return clientStats{
		succeeded:       succeeded.Load(),
		failed:          failed.Load(),
		latenciesMillis: latencies,
	}
}

func fetch(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func percentile(values []float64, percent float64) float64 {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	index := int((float64(len(ordered)-1) * percent / 100) + 0.5)
	return ordered[index]
}
