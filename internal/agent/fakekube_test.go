package agent

import (
	"net/http/httptest"
	"testing"

	"github.com/BerkeKartal/kartal-gozu/internal/fakekube"
	"github.com/BerkeKartal/kartal-gozu/internal/kube"
)

// NewFakeKube starts the fake Kubernetes API and returns a client for it.
func NewFakeKube(t *testing.T) (*fakekube.Server, *kube.Client) {
	t.Helper()
	f := &fakekube.Server{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, kube.New(srv.URL, fakekube.Token, false)
}
