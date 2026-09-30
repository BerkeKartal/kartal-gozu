package config

import "testing"

func TestAgentTokens(t *testing.T) {
	tokens, clusters, err := AgentTokens("demo=aaaaaaaaaaaaaaaa1,\n# yorum satiri\nlocal = bbbbbbbbbbbbbbbb2\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 || tokens["aaaaaaaaaaaaaaaa1"] != "demo" || tokens["bbbbbbbbbbbbbbbb2"] != "local" {
		t.Fatalf("tokens=%v clusters=%v", tokens, clusters)
	}

	bad := map[string]string{
		"no separator":  "demo",
		"short token":   "demo=short",
		"shared token":  "a=aaaaaaaaaaaaaaaa1,b=aaaaaaaaaaaaaaaa1",
		"cluster twice": "a=aaaaaaaaaaaaaaaa1,a=bbbbbbbbbbbbbbbb2",
		"empty cluster": "=aaaaaaaaaaaaaaaa1",
	}
	for name, raw := range bad {
		if _, _, err := AgentTokens(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSecretSources(t *testing.T) {
	t.Setenv("KARTAL_X", "direct")
	if v, err := Secret("KARTAL_X"); err != nil || v != "direct" {
		t.Fatalf("v=%q err=%v", v, err)
	}
	t.Setenv("KARTAL_X_FILE", "/does/not/matter")
	if _, err := Secret("KARTAL_X"); err == nil {
		t.Fatal("expected an error when both KEY and KEY_FILE are set")
	}
}
