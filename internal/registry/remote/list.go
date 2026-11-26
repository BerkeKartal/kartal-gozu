package remote

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The kinds of sources: Harbor and Nexus, whose own APIs list projects and
// push times, and any registry of the Distribution API (Docker Hub, GitLab,
// another kartal-registry), which only has its catalog and tags.
const (
	KindHarbor   = "harbor"
	KindNexus    = "nexus"
	KindRegistry = "registry"
)

// Kinds are the kinds of sources.
var Kinds = []string{KindHarbor, KindNexus, KindRegistry}

// Source is a registry to copy from.
type Source struct {
	Kind string
	// URL is the registry's: Harbor's and other registries' host, or Nexus's
	// base (https://nexus.example.org, or below a path), whose Repository
	// is the Docker repository to read.
	URL        string
	Repository string
	Options    Options
}

// Image is a tag a source has, with what it knows of it: its digest and
// when it was pushed, when its listing says.
type Image struct {
	Repo   string    `json:"repo"`
	Tag    string    `json:"tag"`
	Digest string    `json:"digest,omitempty"`
	Pushed time.Time `json:"pushed,omitempty"`
}

// Project is a group of a source's repositories: Harbor's projects, or
// the first part of their names elsewhere.
type Project struct {
	Name         string `json:"name"`
	Public       bool   `json:"public"`
	Repositories int    `json:"repositories"`
}

// Open makes the source's client, reading its registry where its Docker
// API is: a Nexus repository's below /repository/<name>.
func Open(src Source) (*Client, error) {
	o := src.Options
	o.URL = strings.TrimSuffix(src.URL, "/")
	switch src.Kind {
	case KindNexus:
		if src.Repository == "" {
			return nil, fmt.Errorf("a Nexus source names its Docker repository")
		}
		o.URL += "/repository/" + url.PathEscape(src.Repository)
	case KindHarbor, KindRegistry:
	default:
		return nil, fmt.Errorf("%q is not a kind of source: harbor, nexus or registry", src.Kind)
	}
	return New(o)
}

// Fixed tells whether a pattern names one repository only, which is read
// without listing: Docker Hub has no catalog.
func Fixed(pattern string) bool { return pattern != "" && !strings.ContainsAny(pattern, "*?[") }

// Projects lists the source's projects.
func Projects(ctx context.Context, src Source, c *Client) ([]Project, error) {
	switch src.Kind {
	case KindHarbor:
		return harborProjects(ctx, c)
	case KindNexus:
		comps, err := nexusComponents(ctx, c, src)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, comp := range comps {
			names = append(names, comp.Name)
		}
		return byFirstPart(names), nil
	}
	repos, err := c.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return byFirstPart(repos), nil
}

// byFirstPart groups repositories into projects by the first part of
// their names.
func byFirstPart(repos []string) []Project {
	count := map[string]map[string]bool{}
	for _, r := range repos {
		first, _, _ := strings.Cut(r, "/")
		if count[first] == nil {
			count[first] = map[string]bool{}
		}
		count[first][r] = true
	}
	out := make([]Project, 0, len(count))
	for name, rs := range count {
		out = append(out, Project{Name: name, Repositories: len(rs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Images lists the tags of the repositories match lets through; a
// pattern that names one repository (Fixed) reads it alone.
func Images(ctx context.Context, src Source, c *Client, pattern string, match func(repo string) bool) ([]Image, error) {
	var out []Image
	switch src.Kind {
	case KindHarbor:
		projects, err := harborProjects(ctx, c)
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			if Fixed(pattern) && !strings.HasPrefix(pattern, p.Name+"/") {
				continue
			}
			repos, err := harborRepositories(ctx, c, p.Name)
			if err != nil {
				return nil, err
			}
			for _, r := range repos {
				if !match(r) {
					continue
				}
				imgs, err := harborImages(ctx, c, p.Name, r)
				if err != nil {
					return nil, err
				}
				out = append(out, imgs...)
			}
		}
	case KindNexus:
		comps, err := nexusComponents(ctx, c, src)
		if err != nil {
			return nil, err
		}
		for _, comp := range comps {
			if comp.Version == "" || !match(comp.Name) {
				continue
			}
			img := Image{Repo: comp.Name, Tag: comp.Version}
			for _, a := range comp.Assets {
				if strings.Contains(a.Path, "/manifests/") {
					img.Digest = "sha256:" + a.Checksum.SHA256
					if t, err := time.Parse(time.RFC3339, a.LastModified); err == nil {
						img.Pushed = t
					}
				}
			}
			if !strings.HasPrefix(img.Digest, "sha256:") || len(img.Digest) != 71 {
				img.Digest = ""
			}
			out = append(out, img)
		}
	default:
		repos := []string{pattern}
		if !Fixed(pattern) {
			var err error
			if repos, err = c.Catalog(ctx); err != nil {
				return nil, fmt.Errorf("the registry does not list its repositories (%w); name a repository instead of a pattern", err)
			}
		}
		for _, r := range repos {
			if !match(r) {
				continue
			}
			tags, err := c.Tags(ctx, r)
			if err != nil {
				return nil, err
			}
			for _, t := range tags {
				out = append(out, Image{Repo: r, Tag: t})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Tag < out[j].Tag
	})
	return out, nil
}

// ---------------------------------------------------------------- Harbor

const harborPage = 100

func harborProjects(ctx context.Context, c *Client) ([]Project, error) {
	var out []Project
	for page := 1; page < 1000; page++ {
		var got []struct {
			Name      string `json:"name"`
			RepoCount int    `json:"repo_count"`
			Metadata  struct {
				Public string `json:"public"`
			} `json:"metadata"`
		}
		if _, err := c.getJSON(ctx, c.endpoint(fmt.Sprintf("/api/v2.0/projects?page=%d&page_size=%d", page, harborPage)), &got); err != nil {
			return nil, err
		}
		for _, p := range got {
			out = append(out, Project{Name: p.Name, Public: p.Metadata.Public == "true", Repositories: p.RepoCount})
		}
		if len(got) < harborPage {
			break
		}
	}
	return out, nil
}

func harborRepositories(ctx context.Context, c *Client, project string) ([]string, error) {
	var out []string
	for page := 1; page < 1000; page++ {
		var got []struct {
			Name string `json:"name"`
		}
		u := c.endpoint(fmt.Sprintf("/api/v2.0/projects/%s/repositories?page=%d&page_size=%d", url.PathEscape(project), page, harborPage))
		if _, err := c.getJSON(ctx, u, &got); err != nil {
			return nil, err
		}
		for _, r := range got {
			out = append(out, r.Name)
		}
		if len(got) < harborPage {
			break
		}
	}
	return out, nil
}

func harborImages(ctx context.Context, c *Client, project, repo string) ([]Image, error) {
	// Harbor wants a repository's name without its project, its slashes
	// escaped twice.
	rest := strings.TrimPrefix(repo, project+"/")
	name := url.PathEscape(url.PathEscape(rest))
	var out []Image
	for page := 1; page < 1000; page++ {
		var got []struct {
			Digest   string    `json:"digest"`
			PushTime time.Time `json:"push_time"`
			Tags     []struct {
				Name string `json:"name"`
			} `json:"tags"`
		}
		u := c.endpoint(fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d&with_tag=true",
			url.PathEscape(project), name, page, harborPage))
		if _, err := c.getJSON(ctx, u, &got); err != nil {
			return nil, err
		}
		for _, a := range got {
			for _, t := range a.Tags {
				out = append(out, Image{Repo: repo, Tag: t.Name, Digest: a.Digest, Pushed: a.PushTime})
			}
		}
		if len(got) < harborPage {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- Nexus

type nexusComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Assets  []struct {
		Path         string `json:"path"`
		LastModified string `json:"lastModified"`
		Checksum     struct {
			SHA256 string `json:"sha256"`
		} `json:"checksum"`
	} `json:"assets"`
}

func nexusComponents(ctx context.Context, c *Client, src Source) ([]nexusComponent, error) {
	api := strings.TrimSuffix(src.URL, "/") + "/service/rest/v1/components?repository=" + url.QueryEscape(src.Repository)
	var out []nexusComponent
	token := ""
	for page := 0; page < 10000; page++ {
		u := api
		if token != "" {
			u += "&continuationToken=" + url.QueryEscape(token)
		}
		var got struct {
			Items             []nexusComponent `json:"items"`
			ContinuationToken *string          `json:"continuationToken"`
		}
		if _, err := c.getJSON(ctx, u, &got); err != nil {
			return nil, err
		}
		out = append(out, got.Items...)
		if got.ContinuationToken == nil || *got.ContinuationToken == "" {
			break
		}
		token = *got.ContinuationToken
	}
	return out, nil
}
