package promtext

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// FuzzParse checks that no page, however malformed, crashes the parser,
// and that what Format writes of a page reads back the same.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"# HELP x A thing.\n# TYPE x counter\nx_total{a=\"b\",c=\"d\\\"e\\n\"} 1.5e3 1700000000000\n",
		"# TYPE h histogram\nh_bucket{le=\"0.1\"} 1\nh_bucket{le=\"+Inf\"} 2\nh_sum 0.3\nh_count 2\n",
		"up NaN\ndown +Inf\nneg -Inf\n# EOF\n", "a{} 1\nb{x=\"\"} 2 # {trace_id=\"x\"} 1\n", "\n\n# comment\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, page string) {
		fams, _, err := Parse(strings.NewReader(page), 1000)
		if err != nil {
			return
		}
		var b bytes.Buffer
		if err := Format(&b, fams); err != nil {
			t.Fatalf("format: %v", err)
		}
		again, _, err := Parse(&b, 1000)
		if err != nil {
			t.Fatalf("%q formats as %q, which does not parse: %v", page, b.String(), err)
		}
		if count(fams) != count(again) {
			t.Fatalf("%q: %d samples, %d after formatting as %q", page, count(fams), count(again), b.String())
		}
		for i := range fams {
			for j, s := range fams[i].Samples {
				if j >= len(again[i].Samples) {
					break
				}
				a, b := float64(s.Value), float64(again[i].Samples[j].Value)
				if a != b && !(math.IsNaN(a) && math.IsNaN(b)) {
					t.Fatalf("%q: %v read back as %v", page, a, b)
				}
			}
		}
	})
}

func count(fams []protocol.MetricFamily) int {
	n := 0
	for _, f := range fams {
		n += len(f.Samples)
	}
	return n
}
