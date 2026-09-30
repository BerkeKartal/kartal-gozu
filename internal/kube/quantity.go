package kube

import (
	"math"
	"strconv"
	"strings"
)

var quantitySuffixes = []struct {
	suffix string
	factor float64
}{
	// Binary suffixes first so "Mi" is not mistaken for "M".
	{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"Pi", 1 << 50}, {"Ei", 1 << 60},
	{"n", 1e-9}, {"u", 1e-6}, {"m", 1e-3},
	{"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}, {"P", 1e15}, {"E", 1e18},
}

// parseQuantity reads a Kubernetes quantity such as "250m", "1.5", "128Mi"
// or "1e3". Precision is that of float64, which is ample for display.
func parseQuantity(q string) (float64, bool) {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0, false
	}
	if v, err := strconv.ParseFloat(q, 64); err == nil { // plain or exponent form
		return v, finite(v)
	}
	for _, s := range quantitySuffixes {
		if num, ok := strings.CutSuffix(q, s.suffix); ok {
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, false
			}
			return v * s.factor, finite(v * s.factor)
		}
	}
	return 0, false
}

// finite rejects "NaN" and "Inf", which ParseFloat accepts but no quantity is.
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// MilliValue returns a quantity in thousandths, e.g. CPU "250m" -> 250.
func MilliValue(q string) int64 {
	v, ok := parseQuantity(q)
	if !ok {
		return 0
	}
	return int64(math.Round(v * 1000))
}

// Value returns a quantity in base units, e.g. memory "1Ki" -> 1024.
func Value(q string) int64 {
	v, ok := parseQuantity(q)
	if !ok {
		return 0
	}
	return int64(math.Round(v))
}
