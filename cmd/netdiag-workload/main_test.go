package main

import "testing"

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
