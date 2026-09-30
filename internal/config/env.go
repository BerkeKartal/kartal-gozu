// Package config reads settings from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func String(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func Duration(key string, def time.Duration) (time.Duration, error) {
	v := String(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %q is not a positive duration (e.g. 15s, 1m)", key, v)
	}
	return d, nil
}

func Bool(key string, def bool) (bool, error) {
	v := String(key, "")
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean", key, v)
	}
	return b, nil
}

// List splits a comma separated value, dropping empty items.
func List(key string) []string {
	var out []string
	for _, part := range strings.Split(String(key, ""), ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Secret reads KEY, or the file named by KEY_FILE (for mounted Kubernetes
// Secrets). Setting both is an error so the source is never ambiguous.
func Secret(key string) (string, error) {
	direct := String(key, "")
	file := String(key+"_FILE", "")
	switch {
	case direct != "" && file != "":
		return "", fmt.Errorf("set only one of %s and %s_FILE", key, key)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return direct, nil
	}
}

const minTokenLength = 16

// AgentTokens parses "cluster=token" entries separated by commas or newlines
// into a token -> cluster map.
func AgentTokens(raw string) (map[string]string, []string, error) {
	tokens := map[string]string{}
	var clusters []string
	seen := map[string]bool{}
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		cluster, token, ok := strings.Cut(entry, "=")
		cluster, token = strings.TrimSpace(cluster), strings.TrimSpace(token)
		if !ok || cluster == "" || token == "" {
			return nil, nil, fmt.Errorf("agent token entry %q must look like cluster=token", entry)
		}
		if len(token) < minTokenLength {
			return nil, nil, fmt.Errorf("token for cluster %q is shorter than %d characters", cluster, minTokenLength)
		}
		if _, dup := tokens[token]; dup {
			return nil, nil, fmt.Errorf("the same token is used for more than one cluster")
		}
		if seen[cluster] {
			return nil, nil, fmt.Errorf("cluster %q is listed twice", cluster)
		}
		seen[cluster] = true
		tokens[token] = cluster
		clusters = append(clusters, cluster)
	}
	return tokens, clusters, nil
}
