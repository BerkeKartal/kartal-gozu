package versions

import "testing"

func TestKubeVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v1.33.11": "1.33.11", "v1.33.11+k3s1": "1.33.11", "v1.29.6-eks-db838b0": "1.29.6", "1.28.9-gke.1000": "1.28.9",
		"v1.34.0-rc.1": "1.34.0", "": "", "dev": "", "v1.33": "", "v1.x.3": "",
	} {
		if got := KubeVersion(in); got != want {
			t.Errorf("KubeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSame(t *testing.T) {
	same := [][2]string{{"7804c92", "7804c92"}, {"7804c92", "7804c92-dirty"}, {"7804c92", "7804c926f1aa"},
		{"v0.2.0-3-g7804c92", "7804c92"}, {"v0.2.0", "v0.2.0"}, {"7804C92", "7804c92"}}
	for _, p := range same {
		if !Same(p[0], p[1]) {
			t.Errorf("%s and %s should be the same", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{"7804c92", "f254f26"}, {"v0.2.0", "v0.3.0"}, {"7804c92", "v0.2.0"}} {
		if Same(p[0], p[1]) {
			t.Errorf("%s and %s should differ", p[0], p[1])
		}
	}
	if Known("dev") || Known(" ") || !Known("7804c92") {
		t.Error("Known")
	}
}

func TestValidRepo(t *testing.T) {
	for repo, ok := range map[string]bool{"BerkeKartal/kartal-gozu": true, "a/b.c_d": true, "a": false, "a/b/c": false,
		"a/b?x": false, "/b": false, "a b/c": false} {
		if ValidRepo(repo) != ok {
			t.Errorf("ValidRepo(%q) = %t", repo, !ok)
		}
	}
}
