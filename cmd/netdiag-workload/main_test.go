package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
)

func TestPercentile(t *testing.T) {
	values := []float64{5, 1, 3, 2, 4}
	for _, tt := range []struct {
		percent float64
		want    float64
	}{
		{percent: 50, want: 3},
		{percent: 95, want: 5},
		{percent: 99, want: 5},
	} {
		if got := percentile(values, tt.percent); got != tt.want {
			t.Fatalf("percentile(%v, %.0f) = %v, want %v", values, tt.percent, got, tt.want)
		}
	}
}

func TestPercentileEmpty(t *testing.T) {
	if got := percentile(nil, 99); got != 0 {
		t.Fatalf("percentile(nil, 99) = %v, want 0", got)
	}
}

func TestFetchRecordsConnectLatency(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		if trace != nil {
			trace.ConnectStart("tcp", "127.0.0.1:18080")
			trace.ConnectDone("tcp", "127.0.0.1:18080", nil)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	})}

	metrics, err := fetch(context.Background(), client, "http://127.0.0.1:18080/payload")
	if err != nil {
		t.Fatal(err)
	}
	if !metrics.hadConnect {
		t.Fatal("fetch did not record connect latency")
	}
}

func TestPrintClientStatsIncludesConnectLatency(t *testing.T) {
	var output bytes.Buffer
	printClientStats(&output, clientStats{
		succeeded:              3,
		latenciesMillis:        []float64{1, 2, 3},
		connectLatenciesMillis: []float64{0.1, 0.2, 0.3},
	})

	for _, want := range []string{
		"HTTP requests:",
		"Latency milliseconds:",
		"Connect latency milliseconds:",
		"samples=3",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
