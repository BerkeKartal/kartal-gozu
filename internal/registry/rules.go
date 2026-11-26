package registry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/registry/meta"
)

// RuleView is a replication rule as the API shows it: with its source's
// name, and when it runs next.
type RuleView struct {
	meta.ReplicationRule
	SourceName string     `json:"sourceName"`
	Next       *time.Time `json:"next,omitempty"`
}

func (s *Server) ruleView(r meta.ReplicationRule) RuleView {
	v := RuleView{ReplicationRule: r}
	if src, ok := s.cfg.DB.Source(r.Source); ok {
		v.SourceName = src.Name
	}
	if next := s.NextRuleRun(r); !next.IsZero() {
		next = next.UTC()
		v.Next = &next
	}
	return v
}

func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	out := []RuleView{}
	for _, r := range s.cfg.DB.Rules() {
		out = append(out, s.ruleView(r))
	}
	adminJSON(w, http.StatusOK, out)
}

func ruleError(w http.ResponseWriter, s *Server, what string, err error) {
	switch {
	case errors.Is(err, ErrRule):
		adminError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, meta.ErrExists):
		adminError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrNotFound):
		adminError(w, http.StatusNotFound, "no such rule or source")
	default:
		s.adminInternal(w, what, err)
	}
}

// ruleInput is a rule as an admin sends it; what the registry keeps of its
// runs is its own.
func ruleInput(r *http.Request, w http.ResponseWriter) (meta.ReplicationRule, bool) {
	var in meta.ReplicationRule
	if !readBody(w, r, &in) {
		return meta.ReplicationRule{}, false
	}
	in.Name, in.Repositories, in.Tags, in.Cron = strings.TrimSpace(in.Name), strings.TrimSpace(in.Repositories),
		strings.TrimSpace(in.Tags), strings.TrimSpace(in.Cron)
	if len(in.Platforms) == 0 {
		in.Platforms = nil
	}
	return in, true
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	in, ok := ruleInput(r, w)
	if !ok {
		return
	}
	b := make([]byte, 8)
	rand.Read(b)
	now := s.now().UTC()
	in.ID, in.Created, in.By, in.Since, in.Last = hex.EncodeToString(b), now, actor(r), now, nil
	err := s.checkRule(in)
	if err == nil {
		err = s.cfg.DB.PutRule(in, actor(r))
	}
	if err != nil {
		ruleError(w, s, "adding a rule", err)
		return
	}
	adminJSON(w, http.StatusCreated, s.ruleView(in))
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.cfg.DB.Rule(r.PathValue("id"))
	if !ok {
		adminError(w, http.StatusNotFound, "no such rule")
		return
	}
	in, ok := ruleInput(r, w)
	if !ok {
		return
	}
	in.ID, in.Created, in.By, in.Since, in.Last = cur.ID, cur.Created, cur.By, cur.Since, cur.Last
	// A schedule set anew starts from now.
	if in.Cron != cur.Cron || in.Enabled != cur.Enabled {
		in.Since = s.now().UTC()
	}
	err := s.checkRule(in)
	if err == nil {
		err = s.cfg.DB.PutRule(in, actor(r))
	}
	if err != nil {
		ruleError(w, s, "changing a rule", err)
		return
	}
	adminJSON(w, http.StatusOK, s.ruleView(in))
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.DB.DeleteRule(r.PathValue("id"), actor(r)); err != nil {
		ruleError(w, s, "deleting a rule", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	if err := s.CancelJob(r.PathValue("id"), actor(r)); err != nil {
		adminError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
