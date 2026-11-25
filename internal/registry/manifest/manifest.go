// Package manifest reads the manifests a registry stores: Docker's v2
// image manifest and manifest list, and OCI's image manifest and index.
// It tells what a manifest refers to, so that a push of one whose content
// is missing can be refused, and what it is: its platforms, its subject
// (for signatures and SBOMs), and from an image's config its creation time
// and labels.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The media types taken.
const (
	DockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	DockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	OCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	OCIIndex       = "application/vnd.oci.image.index.v1+json"
	// OCIEmpty is the config of an artifact that has none.
	OCIEmpty = "application/vnd.oci.empty.v1+json"
)

// MaxSize is the largest manifest taken, as other registries do.
const MaxSize = 4 << 20

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Platform is what an image runs on.
type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
	OSVersion    string `json:"os.version,omitempty"`
}

func (p *Platform) String() string {
	if p == nil {
		return ""
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// Descriptor points at content by its digest.
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Platform     *Platform         `json:"platform,omitempty"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// Manifest is a manifest as read.
type Manifest struct {
	MediaType    string
	ArtifactType string
	// Config and Layers are an image manifest's.
	Config *Descriptor
	Layers []Descriptor
	// Manifests are an index's: one per platform, or any artifacts.
	Manifests   []Descriptor
	Subject     *Descriptor
	Annotations map[string]string
}

// Index tells whether the manifest lists other manifests.
func (m *Manifest) Index() bool { return m.MediaType == DockerList || m.MediaType == OCIIndex }

// Kind is what the manifest is, as people would say it: an image, an
// image for several platforms, a Helm chart, a signature or an SBOM, or
// another artifact.
func (m *Manifest) Kind() string {
	t := m.ArtifactType
	if t == "" && m.Config != nil && m.Config.MediaType != OCIEmpty && !strings.Contains(m.Config.MediaType, "image.config") &&
		m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		t = m.Config.MediaType
	}
	for _, l := range m.Layers {
		if t == "" && (strings.Contains(l.MediaType, "simplesigning") || strings.Contains(l.MediaType, "cosign")) {
			t = l.MediaType + "+signature"
		}
	}
	switch {
	case strings.Contains(t, "helm"):
		return "helm"
	case strings.Contains(t, "sigstore") || strings.Contains(t, "notary") || strings.Contains(t, "signature"):
		return "signature"
	case strings.Contains(t, "spdx") || strings.Contains(t, "cyclonedx") || strings.Contains(t, "sbom"):
		return "sbom"
	case t != "":
		return "artifact"
	case m.Index():
		return "index"
	}
	return "image"
}

// References are the blobs the manifest needs: its config and layers. A
// layer that may be pulled from elsewhere (one with urls, as Windows base
// layers are) is not needed.
func (m *Manifest) References() []Descriptor {
	var out []Descriptor
	if m.Config != nil {
		out = append(out, *m.Config)
	}
	for _, l := range m.Layers {
		if len(l.URLs) == 0 {
			out = append(out, l)
		}
	}
	return out
}

var known = map[string]bool{DockerManifest: true, DockerList: true, OCIManifest: true, OCIIndex: true}

// ErrUnsupported is a manifest of a kind that is not taken, such as Docker's
// old schema 1.
var ErrUnsupported = errors.New("unsupported manifest media type")

type wire struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        *Descriptor       `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Manifests     []Descriptor      `json:"manifests"`
	Subject       *Descriptor       `json:"subject"`
	Annotations   map[string]string `json:"annotations"`
}

// Parse reads a manifest pushed with the given Content-Type.
func Parse(contentType string, body []byte) (*Manifest, error) {
	if len(body) > MaxSize {
		return nil, fmt.Errorf("the manifest is larger than %d bytes", MaxSize)
	}
	contentType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	var w wire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("the manifest is not JSON: %w", err)
	}
	if w.SchemaVersion != 2 {
		return nil, fmt.Errorf("%w: schemaVersion %d (only 2 is taken)", ErrUnsupported, w.SchemaVersion)
	}
	// The Content-Type must agree with the manifest; one that names no
	// manifest type (application/json, say) says nothing.
	if !known[contentType] {
		contentType = ""
	}
	mt := w.MediaType
	switch {
	case mt == "" && contentType != "":
		mt = contentType
	case mt != "" && contentType != "" && mt != contentType:
		return nil, fmt.Errorf("the manifest says it is %s but was sent as %s", mt, contentType)
	}
	if mt == "" {
		// An OCI manifest may leave its media type out; what it holds says
		// which it is.
		mt = OCIManifest
		if w.Manifests != nil && w.Config == nil {
			mt = OCIIndex
		}
	}
	m := &Manifest{MediaType: mt, ArtifactType: w.ArtifactType, Subject: w.Subject, Annotations: w.Annotations}
	switch mt {
	case DockerManifest, OCIManifest:
		if w.Config == nil {
			return nil, errors.New("an image manifest needs a config")
		}
		if w.Manifests != nil {
			return nil, errors.New("an image manifest has no manifests")
		}
		m.Config, m.Layers = w.Config, w.Layers
		if mt == DockerManifest && (w.ArtifactType != "" || w.Subject != nil) {
			return nil, errors.New("a Docker manifest has no artifactType or subject")
		}
	case DockerList, OCIIndex:
		if w.Config != nil || w.Layers != nil {
			return nil, errors.New("an index has no config or layers")
		}
		m.Manifests = w.Manifests
		if mt == DockerList && (w.ArtifactType != "" || w.Subject != nil) {
			return nil, errors.New("a Docker manifest list has no artifactType or subject")
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, mt)
	}
	check := func(what string, d *Descriptor) error {
		if !digestRE.MatchString(d.Digest) {
			return fmt.Errorf("%s has no valid sha256 digest: %q", what, d.Digest)
		}
		if d.Size < 0 {
			return fmt.Errorf("%s has a negative size", what)
		}
		if d.MediaType == "" {
			return fmt.Errorf("%s has no media type", what)
		}
		return nil
	}
	if m.Config != nil {
		if err := check("the config", m.Config); err != nil {
			return nil, err
		}
	}
	for i := range m.Layers {
		if err := check(fmt.Sprintf("layer %d", i), &m.Layers[i]); err != nil {
			return nil, err
		}
	}
	for i := range m.Manifests {
		if err := check(fmt.Sprintf("manifest %d", i), &m.Manifests[i]); err != nil {
			return nil, err
		}
	}
	if m.Subject != nil {
		if err := check("the subject", m.Subject); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Config is what the registry keeps of an image's config.
type Config struct {
	Platform Platform
	Created  *time.Time
	Labels   map[string]string
	History  []History
}

// History is a step that built an image.
type History struct {
	Created    *time.Time `json:"created,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	EmptyLayer bool       `json:"empty_layer,omitempty"`
	Comment    string     `json:"comment,omitempty"`
}

// MaxConfigSize is the largest config read; a larger one is kept, not read.
const MaxConfigSize = 4 << 20

// ImageConfig reads an image's config, which says what it runs on.
func ImageConfig(body []byte) (*Config, error) {
	var w struct {
		Architecture string     `json:"architecture"`
		OS           string     `json:"os"`
		Variant      string     `json:"variant"`
		OSVersion    string     `json:"os.version"`
		Created      *time.Time `json:"created"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
		History []History `json:"history"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, err
	}
	return &Config{
		Platform: Platform{Architecture: w.Architecture, OS: w.OS, Variant: w.Variant, OSVersion: w.OSVersion},
		Created:  w.Created, Labels: w.Config.Labels, History: w.History,
	}, nil
}

// IsImageConfig tells whether a config's media type is an image's, which
// ImageConfig can read.
func IsImageConfig(mediaType string) bool {
	return mediaType == "application/vnd.docker.container.image.v1+json" || mediaType == "application/vnd.oci.image.config.v1+json"
}
