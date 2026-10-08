package promtext

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

func TestFormatParsesBack(t *testing.T) {
	page := `# HELP http_requests_total Requests.
# TYPE http_requests_total counter
http_requests_total{code="200",method="GET"} 1027
http_requests_total{code="500",path="/a\"b\\c\nd"} 3
# TYPE latency_seconds histogram
latency_seconds_bucket{le="0.1"} 5
latency_seconds_bucket{le="+Inf"} 9
latency_seconds_sum 1.5
latency_seconds_count 9
# TYPE temp gauge
temp NaN
temp{room="x"} -Inf
untyped_thing 1e-07
`
	fams, _, err := Parse(strings.NewReader(page), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Format(&out, fams); err != nil {
		t.Fatal(err)
	}
	again, _, err := Parse(strings.NewReader(out.String()), 1000)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for i := range fams {
		fams[i].Help = ""
	}
	// NaN never equals itself; compare it apart.
	norm := func(fs []protocol.MetricFamily) {
		for i := range fs {
			for j := range fs[i].Samples {
				if math.IsNaN(float64(fs[i].Samples[j].Value)) {
					fs[i].Samples[j].Value = -12345
				}
			}
		}
	}
	norm(fams)
	norm(again)
	if !reflect.DeepEqual(fams, again) {
		t.Errorf("round trip changed the families:\n%+v\n%+v\n%s", fams, again, out.String())
	}
}
