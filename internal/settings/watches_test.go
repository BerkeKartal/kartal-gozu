package settings

import (
	"math"
	"testing"
)

func TestWatchNormalize(t *testing.T) {
	w := Watch{Cluster: " prod ", Namespace: "shop", Target: "Deployment/web", Port: "9100", Metric: " http_requests_total ",
		Labels: map[string]string{" code ": "500", "": "dropped"}}
	if err := w.Normalize(); err != nil {
		t.Fatal(err)
	}
	if w.Name != "http_requests_total" || w.Path != "/metrics" || w.Aggregate != "sum" || w.Cluster != "prod" ||
		len(w.Labels) != 1 || w.Labels["code"] != "500" {
		t.Errorf("normalized: %+v", w)
	}
	// Reads changes with what is read, not with the name or the limits.
	before := w.Reads()
	above := 3.0
	w.Name, w.Above = "Errors", &above
	if w.Reads() != before {
		t.Error("renaming changed what is read")
	}
	w.Labels["code"] = "502"
	if w.Reads() == before {
		t.Error("another label did not change what is read")
	}
	// A clone shares nothing.
	c := w.clone()
	c.Labels["code"], *c.Above = "200", 9
	if w.Labels["code"] != "502" || *w.Above != 3 {
		t.Error("the clone shares its labels or limits")
	}
}

func TestWatchValidate(t *testing.T) {
	good := Watch{Name: "x", Cluster: "prod", Namespace: "shop", Target: "Deployment/web", Port: "9100", Path: "/metrics", Metric: "up", Aggregate: "sum"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	nan := math.NaN()
	for name, change := range map[string]func(*Watch){
		"namespace":   func(w *Watch) { w.Namespace = "Shop" },
		"target kind": func(w *Watch) { w.Target = "Service/web" },
		"target name": func(w *Watch) { w.Target = "Pod/../x" },
		"port name":   func(w *Watch) { w.Port = "metrics" },
		"port range":  func(w *Watch) { w.Port = "70000" },
		"path":        func(w *Watch) { w.Path = "/metrics/../../secret" },
		"query":       func(w *Watch) { w.Path = "/metrics?debug=1" },
		"metric":      func(w *Watch) { w.Metric = "http-requests" },
		"label":       func(w *Watch) { w.Labels = map[string]string{"1code": "x"} },
		"aggregate":   func(w *Watch) { w.Aggregate = "median" },
		"limit":       func(w *Watch) { w.Above = &nan },
		"cluster":     func(w *Watch) { w.Cluster = "a/b" },
	} {
		w := good
		change(&w)
		if err := w.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, w)
		}
	}
}
