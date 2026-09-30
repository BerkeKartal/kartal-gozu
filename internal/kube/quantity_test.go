package kube

import "testing"

func TestQuantities(t *testing.T) {
	milli := map[string]int64{"250m": 250, "2": 2000, "1.5": 1500, "123456789n": 123, "0": 0, "": 0, "junk": 0}
	for in, want := range milli {
		if got := MilliValue(in); got != want {
			t.Errorf("MilliValue(%q) = %d, want %d", in, got, want)
		}
	}
	bytes := map[string]int64{"128Mi": 128 << 20, "1Gi": 1 << 30, "500M": 500_000_000, "123456Ki": 123456 << 10, "1e3": 1000, "2Ei": 2 << 60, "3E": 3e18}
	for in, want := range bytes {
		if got := Value(in); got != want {
			t.Errorf("Value(%q) = %d, want %d", in, got, want)
		}
	}
}
