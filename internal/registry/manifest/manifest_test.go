package manifest

import (
	"errors"
	"strings"
	"testing"
)

const (
	d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	d3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestParseImage(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"` + DockerManifest + `",
		"config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"` + d1 + `","size":100},
		"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"` + d2 + `","size":2000},
		          {"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","digest":"` + d3 + `","size":9,"urls":["https://example.org/l"]}]}`
	m, err := Parse(DockerManifest, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if m.MediaType != DockerManifest || m.Index() || m.Kind() != "image" || m.Config.Digest != d1 || len(m.Layers) != 2 {
		t.Fatalf("%+v", m)
	}
	// The foreign layer is pulled from elsewhere, so it is not needed here.
	refs := m.References()
	if len(refs) != 2 || refs[0].Digest != d1 || refs[1].Digest != d2 {
		t.Errorf("references: %+v", refs)
	}
	// A Content-Type that names no manifest type says nothing.
	if _, err := Parse("application/json", []byte(body)); err != nil {
		t.Errorf("sent as application/json: %v", err)
	}
	if _, err := Parse(OCIManifest, []byte(body)); err == nil || !strings.Contains(err.Error(), "sent as") {
		t.Errorf("sent as another manifest type: %v", err)
	}
}

func TestParseOCIIndexAndArtifacts(t *testing.T) {
	index := `{"schemaVersion":2,"mediaType":"` + OCIIndex + `","manifests":[
		{"mediaType":"` + OCIManifest + `","digest":"` + d1 + `","size":500,"platform":{"architecture":"amd64","os":"linux"}},
		{"mediaType":"` + OCIManifest + `","digest":"` + d2 + `","size":500,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}}]}`
	m, err := Parse(OCIIndex, []byte(index))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Index() || m.Kind() != "index" || len(m.Manifests) != 2 || m.Manifests[1].Platform.String() != "linux/arm64/v8" || len(m.References()) != 0 {
		t.Fatalf("%+v", m)
	}
	// An OCI manifest may leave its media type out.
	sbom := `{"schemaVersion":2,"artifactType":"application/spdx+json",
		"config":{"mediaType":"` + OCIEmpty + `","digest":"` + d3 + `","size":2},
		"layers":[{"mediaType":"application/spdx+json","digest":"` + d2 + `","size":10}],
		"subject":{"mediaType":"` + OCIManifest + `","digest":"` + d1 + `","size":500}}`
	m, err = Parse("", []byte(sbom))
	if err != nil {
		t.Fatal(err)
	}
	if m.MediaType != OCIManifest || m.Kind() != "sbom" || m.Subject == nil || m.Subject.Digest != d1 {
		t.Fatalf("%+v", m)
	}
	helm := `{"schemaVersion":2,"config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"` + d1 + `","size":10},"layers":[]}`
	if m, err := Parse(OCIManifest, []byte(helm)); err != nil || m.Kind() != "helm" {
		t.Errorf("helm: %v %v", m, err)
	}
	cosign := `{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + d1 + `","size":10},
		"layers":[{"mediaType":"application/vnd.dev.cosign.simplesigning.v1+json","digest":"` + d2 + `","size":10}]}`
	if m, err := Parse(OCIManifest, []byte(cosign)); err != nil || m.Kind() != "signature" {
		t.Errorf("cosign: %v %v", m, err)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `{`,
		"schema 1":        `{"schemaVersion":1,"name":"x","fsLayers":[]}`,
		"unknown type":    `{"schemaVersion":2,"mediaType":"application/x-unknown"}`,
		"no config":       `{"schemaVersion":2,"mediaType":"` + OCIManifest + `","layers":[]}`,
		"bad digest":      `{"schemaVersion":2,"mediaType":"` + OCIManifest + `","config":{"mediaType":"a","digest":"sha256:nothex","size":1}}`,
		"md5 digest":      `{"schemaVersion":2,"mediaType":"` + OCIManifest + `","config":{"mediaType":"a","digest":"md5:abc","size":1}}`,
		"negative size":   `{"schemaVersion":2,"mediaType":"` + OCIManifest + `","config":{"mediaType":"a","digest":"` + d1 + `","size":-1}}`,
		"no media type":   `{"schemaVersion":2,"mediaType":"` + OCIManifest + `","config":{"digest":"` + d1 + `","size":1}}`,
		"index w/ layers": `{"schemaVersion":2,"mediaType":"` + OCIIndex + `","manifests":[],"layers":[]}`,
		"docker subject":  `{"schemaVersion":2,"mediaType":"` + DockerManifest + `","config":{"mediaType":"a","digest":"` + d1 + `","size":1},"subject":{"mediaType":"a","digest":"` + d2 + `","size":1}}`,
	} {
		if _, err := Parse("", []byte(body)); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := Parse("", []byte(`{"schemaVersion":1}`)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("schema 1 is not unsupported: %v", err)
	}
	if _, err := Parse("", []byte(`{"schemaVersion":2,"x":"`+strings.Repeat("a", MaxSize)+`"}`)); err == nil {
		t.Error("an oversized manifest was taken")
	}
}

func TestImageConfig(t *testing.T) {
	c, err := ImageConfig([]byte(`{"architecture":"arm64","os":"linux","variant":"v8","created":"2026-11-20T10:00:00Z",
		"config":{"Labels":{"org.opencontainers.image.revision":"abc123"}},
		"history":[{"created_by":"COPY . /app"},{"created_by":"ENV X=1","empty_layer":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Platform.String() != "linux/arm64/v8" || c.Created == nil || c.Labels["org.opencontainers.image.revision"] != "abc123" ||
		len(c.History) != 2 || !c.History[1].EmptyLayer {
		t.Errorf("%+v", c)
	}
	if !IsImageConfig("application/vnd.oci.image.config.v1+json") || IsImageConfig(OCIEmpty) {
		t.Error("IsImageConfig")
	}
}
