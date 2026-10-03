// Package alert watches the snapshots for problems (a node not ready, a pod
// crash-looping, a workload short of replicas, an agent gone silent...) and
// notifies people through Teams, e-mail or a webhook.
//
// A problem must last a little while before anyone is told, so a rolling
// update does not page anybody. Everything that starts or ends together is
// sent as one message per cluster, not one message per pod.
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/protocol"
)

// Alert is one problem on one object.
type Alert struct {
	Cluster   string     `json:"cluster"`
	Kind      string     `json:"kind"` // what failed: NodeNotReady, PodFailing, ...
	Severity  string     `json:"severity"`
	Namespace string     `json:"namespace,omitempty"`
	Object    string     `json:"object"`
	Detail    string     `json:"detail"`
	Since     time.Time  `json:"since"`
	Notified  bool       `json:"notified"`
	Resolved  *time.Time `json:"resolved,omitempty"`
}

func (a Alert) key() string {
	return a.Cluster + "\x00" + a.Kind + "\x00" + a.Namespace + "\x00" + a.Object
}

// Summary is a one-line description, as used in notifications.
func (a Alert) Summary() string {
	where := a.Object
	if a.Namespace != "" {
		where = a.Namespace + "/" + a.Object
	}
	return fmt.Sprintf("%s %s: %s", titles[a.Kind], where, a.Detail)
}

const (
	critical = "critical"
	warning  = "warning"
)

var titles = map[string]string{
	"AgentOffline":        "Agent offline",
	"NodeNotReady":        "Node not ready",
	"NodePressure":        "Node under pressure",
	"PodFailing":          "Pod failing",
	"WorkloadDegraded":    "Workload degraded",
	"JobFailed":           "Job failed",
	"VolumeClaimUnbound":  "Volume claim unbound",
	"VolumeFilling":       "Volume filling up",
	"CertificateExpiring": "Certificate expiring",
	"URLDown":             "Address not answering",
	"MetricLimit":         "Metric past its limit",
}

// podFailing are the pod reasons worth telling someone about; a pod merely
// starting up or pending for a moment is not.
var podFailing = map[string]bool{
	"CrashLoopBackOff": true, "ImagePullBackOff": true, "ErrImagePull": true, "CreateContainerConfigError": true,
	"CreateContainerError": true, "InvalidImageName": true, "RunContainerError": true, "OOMKilled": true, "Error": true,
	"Evicted": true,
}

// Notification is what a Notifier sends: what started and what ended.
type Notification struct {
	Cluster  string
	Firing   []Alert
	Resolved []Alert
	URL      string
}

// Title is the subject line of a notification.
func (n Notification) Title() string {
	var parts []string
	if len(n.Firing) > 0 {
		parts = append(parts, fmt.Sprintf("%d new problem(s)", len(n.Firing)))
	}
	if len(n.Resolved) > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", len(n.Resolved)))
	}
	if n.Cluster == "" {
		// The server's own checks, of no cluster.
		return "Kartal Gözü: " + strings.Join(parts, ", ")
	}
	return "Kartal Gözü · " + n.Cluster + ": " + strings.Join(parts, ", ")
}

// Lines lists the alerts of a notification, at most limit of each kind.
func (n Notification) Lines(limit int) []string {
	var out []string
	add := func(prefix string, list []Alert) {
		for i, a := range list {
			if i == limit {
				out = append(out, fmt.Sprintf("%s … and %d more", prefix, len(list)-limit))
				break
			}
			out = append(out, prefix+" "+a.Summary())
		}
	}
	add("🔴", n.Firing)
	add("✅", n.Resolved)
	return out
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, n Notification) error
}

// Switchable is a channel that can be set, changed or turned off while the
// server runs, as the e-mail settings made in the UI are.
type Switchable struct {
	name string
	mu   sync.RWMutex
	cur  Notifier
}

func NewSwitchable(name string) *Switchable { return &Switchable{name: name} }

// Set puts n behind the channel; nil turns it off.
func (s *Switchable) Set(n Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = n
}

func (s *Switchable) Name() string { return s.name }

func (s *Switchable) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur != nil
}

func (s *Switchable) Send(ctx context.Context, n Notification) error {
	s.mu.RLock()
	cur := s.cur
	s.mu.RUnlock()
	if cur == nil {
		return fmt.Errorf("the %s channel is turned off", s.name)
	}
	return cur.Send(ctx, n)
}

// enabled reports whether a channel is on; only a Switchable can be off.
func enabled(n Notifier) bool {
	if s, ok := n.(interface{ Enabled() bool }); ok {
		return s.Enabled()
	}
	return true
}

// Manager keeps the current alerts and sends notifications.
type Manager struct {
	// After is how long a problem must last before it is notified.
	After     time.Duration
	Notifiers []Notifier
	// PublicURL, when set, is linked from notifications.
	PublicURL string
	Log       *slog.Logger
	// VolumeWarning and VolumeCritical are how full a volume may get, in
	// percent; zero means 85 and 95.
	VolumeWarning, VolumeCritical float64
	// CertificateWarning and CertificateCritical are how close a
	// certificate's expiry may come; zero means 14 days and 3 days.
	CertificateWarning, CertificateCritical time.Duration

	mu     sync.Mutex
	active map[string]*Alert
	recent []Alert // newest last, at most keepRecent
	sent   []Delivery
	// One queue and one sender per channel, so a problem's "resolved"
	// message never overtakes the message that announced it.
	start  sync.Once
	queues []chan Notification
}

// Delivery records one notification attempt, for the UI.
type Delivery struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	Title   string    `json:"title"`
	Error   string    `json:"error,omitempty"`
}

const (
	keepRecent     = 200
	keepDeliveries = 50
	sendTimeout    = 20 * time.Second
)

func NewManager(after time.Duration, log *slog.Logger, notifiers ...Notifier) *Manager {
	return &Manager{After: after, Notifiers: notifiers, Log: log, active: map[string]*Alert{}}
}

// Observe compares a cluster's snapshot with the alerts it had so far.
func (m *Manager) Observe(cluster string, snap *protocol.Snapshot, now time.Time) {
	found := map[string]Alert{}
	add := func(a Alert) {
		a.Cluster = cluster
		found[a.key()] = a
	}
	for _, n := range snap.Nodes {
		if !n.Ready {
			detail := "NotReady"
			if len(n.Pressure) > 0 {
				detail += " (" + strings.Join(n.Pressure, ", ") + ")"
			}
			add(Alert{Kind: "NodeNotReady", Severity: critical, Object: n.Name, Detail: detail})
		} else if len(n.Pressure) > 0 {
			// A ready node short of disk or memory evicts pods to cope.
			add(Alert{Kind: "NodePressure", Severity: warning, Object: n.Name, Detail: strings.Join(n.Pressure, ", ")})
		}
	}
	for _, p := range snap.Pods {
		// A Job's finished pods are its history; the Job's own alert says
		// how it ended. Its running pods can still crash-loop. A pod that
		// its controller replaced is history too; NodePressure and
		// WorkloadDegraded tell what matters.
		if strings.HasPrefix(p.Owner, "Job/") && (p.Phase == "Failed" || p.Phase == "Succeeded") || p.Replaced() {
			continue
		}
		// An init container's trouble comes as "Init:CrashLoopBackOff" and
		// the like.
		reason := strings.TrimPrefix(p.Reason, "Init:")
		if podFailing[reason] || (p.Phase == "Failed" && p.Owner != "") {
			detail := p.Reason
			if detail == "" {
				detail = p.Phase
			}
			if p.Restarts > 0 {
				detail += fmt.Sprintf(", %d restarts", p.Restarts)
			}
			add(Alert{Kind: "PodFailing", Severity: warning, Namespace: p.Namespace, Object: p.Name, Detail: detail})
		}
	}
	for _, w := range snap.Workloads {
		if w.Degraded() {
			sev := warning
			if w.Ready == 0 {
				sev = critical
			}
			add(Alert{Kind: "WorkloadDegraded", Severity: sev, Namespace: w.Namespace, Object: w.Kind + "/" + w.Name,
				Detail: fmt.Sprintf("%d of %d ready", w.Ready, w.Desired)})
		}
	}
	for _, j := range snap.Jobs {
		// Only a Job that gave up; one between retries has failed pods too.
		if j.HasFailed() {
			add(Alert{Kind: "JobFailed", Severity: warning, Namespace: j.Namespace, Object: j.Name, Detail: fmt.Sprintf("%d failed", j.Failed)})
		}
	}
	for _, v := range snap.VolumeClaims {
		if v.Phase != "Bound" {
			add(Alert{Kind: "VolumeClaimUnbound", Severity: warning, Namespace: v.Namespace, Object: v.Name, Detail: v.Phase})
		}
		if sev, detail := m.volumeFilling(v); sev != "" {
			add(Alert{Kind: "VolumeFilling", Severity: sev, Namespace: v.Namespace, Object: v.Name, Detail: detail})
		}
	}
	for _, c := range snap.Certificates {
		if a, ok := m.CertificateAlert(c.NotAfter, now); ok {
			a.Namespace, a.Object = c.Namespace, c.Secret
			if c.Subject != "" {
				a.Detail = c.Subject + ": " + a.Detail
			}
			add(a)
		}
	}
	m.update(cluster, found, func(a *Alert) bool { return a.Kind != "AgentOffline" && a.Kind != MetricLimit }, now)
}

// VolumeLevels are how full a volume may get, in percent, before it is a
// warning and before it is critical. A nil manager has the defaults.
func (m *Manager) VolumeLevels() (warn, crit float64) {
	warn, crit = 85, 95
	if m != nil && m.VolumeWarning > 0 {
		warn = m.VolumeWarning
	}
	if m != nil && m.VolumeCritical > 0 {
		crit = m.VolumeCritical
	}
	return warn, crit
}

// CertificateLevels are how close a certificate's expiry may come before
// it is a warning and before it is critical. A nil manager has the defaults.
func (m *Manager) CertificateLevels() (warn, crit time.Duration) {
	warn, crit = 14*24*time.Hour, 3*24*time.Hour
	if m != nil && m.CertificateWarning > 0 {
		warn = m.CertificateWarning
	}
	if m != nil && m.CertificateCritical > 0 {
		crit = m.CertificateCritical
	}
	return warn, crit
}

// volumeFilling tells how bad a volume's fill level is: by space or, when
// that is worse, by inodes (many small files fill a disk too).
func (m *Manager) volumeFilling(v protocol.VolumeClaim) (severity, detail string) {
	warn, crit := m.VolumeLevels()
	var p float64
	if v.CapacityBytes > 0 {
		p = 100 * float64(v.UsedBytes) / float64(v.CapacityBytes)
		detail = fmt.Sprintf("%.0f%% full (%s of %s)", p, size(v.UsedBytes), size(v.CapacityBytes))
	}
	if v.Inodes > 0 {
		if q := 100 * float64(v.InodesUsed) / float64(v.Inodes); q > p {
			p, detail = q, fmt.Sprintf("%.0f%% of inodes used (%d of %d files)", q, v.InodesUsed, v.Inodes)
		}
	}
	switch {
	case p >= crit:
		return critical, detail
	case p >= warn:
		return warning, detail
	}
	return "", ""
}

// size writes bytes for people: 9.5 GiB.
func size(b int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	v, i := float64(b), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 || v >= 10 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// CertificateAlert is the alert for a certificate that expires at notAfter,
// if it expires soon or has. The caller says which certificate it is.
func (m *Manager) CertificateAlert(notAfter, now time.Time) (Alert, bool) {
	if notAfter.IsZero() {
		return Alert{}, false
	}
	warn, crit := m.CertificateLevels()
	left := notAfter.Sub(now)
	a := Alert{Kind: "CertificateExpiring", Severity: warning}
	switch {
	case left <= 0:
		a.Severity, a.Detail = critical, "expired "+days(-left)+" ago"
	case left <= crit:
		a.Severity, a.Detail = critical, "expires in "+days(left)
	case left <= warn:
		a.Detail = "expires in " + days(left)
	default:
		return Alert{}, false
	}
	a.Detail += " (" + notAfter.UTC().Format("2006-01-02 15:04") + " UTC)"
	return a, true
}

// days writes a span in whole days, or hours under a day.
func days(d time.Duration) string {
	switch h := int(d.Hours()); {
	case h < 1:
		return "less than an hour"
	case h < 24:
		return fmt.Sprintf("%d hours", h)
	case h < 48:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", h/24)
	}
}

// ObserveChecks replaces the alerts of the server's own address checks,
// which belong to no cluster.
func (m *Manager) ObserveChecks(alerts []Alert, now time.Time) {
	found := map[string]Alert{}
	for _, a := range alerts {
		a.Cluster = ""
		found[a.key()] = a
	}
	m.update("", found, func(*Alert) bool { return true }, now)
}

// MetricLimit is the kind of alert for a watched metric past its limit.
const MetricLimit = "MetricLimit"

// ObserveMetrics replaces a cluster's alerts about watched metrics.
func (m *Manager) ObserveMetrics(cluster string, alerts []Alert, now time.Time) {
	found := map[string]Alert{}
	for _, a := range alerts {
		a.Cluster, a.Kind = cluster, MetricLimit
		found[a.key()] = a
	}
	m.update(cluster, found, func(a *Alert) bool { return a.Kind == MetricLimit }, now)
}

// AgentStatus records whether a cluster's agent is reporting.
func (m *Manager) AgentStatus(cluster string, online bool, lastSeen, now time.Time) {
	found := map[string]Alert{}
	if !online {
		a := Alert{Cluster: cluster, Kind: "AgentOffline", Severity: critical, Object: cluster,
			Detail: "no report since " + lastSeen.UTC().Format(time.RFC3339)}
		found[a.key()] = a
	}
	m.update(cluster, found, func(a *Alert) bool { return a.Kind == "AgentOffline" }, now)
}

// update replaces a cluster's alerts of the kinds owns selects with found,
// then sends what became due.
func (m *Manager) update(cluster string, found map[string]Alert, owns func(*Alert) bool, now time.Time) {
	m.mu.Lock()
	var resolved []Alert
	for k, a := range m.active {
		if a.Cluster != cluster || !owns(a) {
			continue
		}
		if _, still := found[k]; still {
			continue
		}
		delete(m.active, k)
		t := now
		a.Resolved = &t
		m.remember(*a)
		if a.Notified {
			resolved = append(resolved, *a)
		}
	}
	for k, a := range found {
		if cur, ok := m.active[k]; ok {
			cur.Detail, cur.Severity = a.Detail, a.Severity
			continue
		}
		a.Since = now
		m.active[k] = &a
	}
	// With no channel on, due problems wait: a channel turned on later (such
	// as e-mail set up in the UI) gets them with the next snapshot.
	listening := len(m.Channels()) > 0
	var firing []Alert
	for _, a := range m.active {
		if listening && a.Cluster == cluster && !a.Notified && now.Sub(a.Since) >= m.After {
			a.Notified = true
			firing = append(firing, *a)
			m.remember(*a)
		}
	}
	m.mu.Unlock()
	if len(firing)+len(resolved) > 0 {
		sortAlerts(firing)
		sortAlerts(resolved)
		m.notify(Notification{Cluster: cluster, Firing: firing, Resolved: resolved, URL: m.PublicURL})
	}
}

func sortAlerts(list []Alert) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Severity != list[j].Severity {
			return list[i].Severity == critical
		}
		return list[i].key() < list[j].key()
	})
}

func (m *Manager) remember(a Alert) {
	m.recent = append(m.recent, a)
	if len(m.recent) > keepRecent {
		m.recent = m.recent[len(m.recent)-keepRecent:]
	}
}

// queueSize bounds what waits for a slow channel; beyond it, messages are
// dropped (and logged) rather than piling up.
const queueSize = 100

// notify hands the notification to each channel's sender, so a slow mail
// server never holds up an agent's report.
func (m *Manager) notify(n Notification) {
	m.start.Do(func() {
		for _, nt := range m.Notifiers {
			q := make(chan Notification, queueSize)
			m.queues = append(m.queues, q)
			go func() {
				for n := range q {
					m.deliver(nt, n)
				}
			}()
		}
	})
	for i, q := range m.queues {
		if !enabled(m.Notifiers[i]) {
			continue
		}
		select {
		case q <- n:
		default:
			if m.Log != nil {
				m.Log.Warn("notification dropped: channel is not keeping up", "channel", m.Notifiers[i].Name())
			}
		}
	}
}

func (m *Manager) deliver(nt Notifier, n Notification) {
	if !enabled(nt) {
		return // turned off since the notification was queued
	}
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	err := nt.Send(ctx, n)
	d := Delivery{Time: time.Now().UTC(), Channel: nt.Name(), Title: n.Title()}
	if err != nil {
		d.Error = err.Error()
		if m.Log != nil {
			m.Log.Warn("notification failed", "channel", nt.Name(), "err", err)
		}
	}
	m.mu.Lock()
	m.sent = append(m.sent, d)
	if len(m.sent) > keepDeliveries {
		m.sent = m.sent[len(m.sent)-keepDeliveries:]
	}
	m.mu.Unlock()
}

// SampleNotification is what a test of a channel sends.
func SampleNotification(publicURL string) Notification {
	return Notification{Cluster: "test", URL: publicURL, Firing: []Alert{{
		Cluster: "test", Kind: "PodFailing", Severity: warning, Namespace: "kartal-gozu", Object: "test-notification",
		Detail: "this is a test notification; nothing is wrong", Since: time.Now().UTC(),
	}}}
}

// Channels names the channels that are on.
func (m *Manager) Channels() []string {
	out := []string{}
	for _, nt := range m.Notifiers {
		if enabled(nt) {
			out = append(out, nt.Name())
		}
	}
	return out
}

// Test sends a sample notification through every channel that is on, and
// waits.
func (m *Manager) Test(ctx context.Context) map[string]string {
	n := SampleNotification(m.PublicURL)
	out := map[string]string{}
	for _, nt := range m.Notifiers {
		if !enabled(nt) {
			continue
		}
		if err := nt.Send(ctx, n); err != nil {
			out[nt.Name()] = err.Error()
		} else {
			out[nt.Name()] = "ok"
		}
	}
	return out
}

// State is what the UI shows: current alerts, recent history, channels.
type State struct {
	Enabled    bool       `json:"enabled"`
	Active     []Alert    `json:"active"`
	Recent     []Alert    `json:"recent"`
	Channels   []string   `json:"channels"`
	Deliveries []Delivery `json:"deliveries"`
	After      string     `json:"after"`
}

func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := State{Enabled: true, Active: []Alert{}, Recent: []Alert{}, Channels: m.Channels(), Deliveries: []Delivery{}, After: m.After.String()}
	for _, a := range m.active {
		st.Active = append(st.Active, *a)
	}
	sortAlerts(st.Active)
	for i := len(m.recent) - 1; i >= 0; i-- {
		st.Recent = append(st.Recent, m.recent[i])
	}
	for i := len(m.sent) - 1; i >= 0; i-- {
		st.Deliveries = append(st.Deliveries, m.sent[i])
	}
	return st
}

// ActiveCount is how many problems a cluster has right now, counting only
// those keep accepts (nil: all).
func (m *Manager) ActiveCount(cluster string, keep func(Alert) bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, a := range m.active {
		if a.Cluster == cluster && (keep == nil || keep(*a)) {
			n++
		}
	}
	return n
}
