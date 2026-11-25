package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
	"github.com/BerkeKartal/kartal-gozu/internal/settings"
)

// RobotPrefix starts a robot account's name when it signs in, as in
// Harbor: robot$ci pushes, robot$nodes pulls.
const RobotPrefix = "robot$"

// MaxRobots keeps the settings a reasonable size.
const MaxRobots = 200

// ErrRobotNotFound is a name no robot account has.
var ErrRobotNotFound = errors.New("there is no such robot account")

var validRobotName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// RobotEntry is a robot account as the API shows it, without its secret.
type RobotEntry struct {
	Name        string     `json:"name"`
	Login       string     `json:"login"`
	Description string     `json:"description"`
	Grants      []string   `json:"grants"`
	Expires     *time.Time `json:"expires,omitempty"`
	Expired     bool       `json:"expired"`
	Disabled    bool       `json:"disabled"`
	Created     time.Time  `json:"created"`
	By          string     `json:"by"`
	Changed     time.Time  `json:"changed,omitempty"`
	ChangedBy   string     `json:"changedBy,omitempty"`
}

func (m *Manager) robotEntry(r settings.Robot) RobotEntry {
	return RobotEntry{Name: r.Name, Login: RobotPrefix + r.Name, Description: r.Description, Grants: nonNil(r.Grants),
		Expires: r.Expires, Expired: r.Expires != nil && m.now().After(*r.Expires), Disabled: r.Disabled,
		Created: r.Created, By: r.By, Changed: r.Changed, ChangedBy: r.ChangedBy}
}

// RobotInput is what an admin sets on a robot account. Left out (nil), a
// field keeps what it was; Expires "" means it never expires.
type RobotInput struct {
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	Grants      []string `json:"grants"`
	Expires     *string  `json:"expires"`
	Disabled    *bool    `json:"disabled"`
}

// checkRobotGrants takes only grants of the image registry: a robot
// signs in to the registry alone, and a grant without a scope would give
// it every cluster too.
func checkRobotGrants(grants []string) ([]string, error) {
	out, err := checkGrants(grants)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, invalid("a robot account needs a grant, such as operator@registry:team-a")
	}
	for _, text := range out {
		g, _ := auth.ParseGrant(text)
		if len(g.Scopes) == 0 {
			return nil, invalid("%q reaches everything; a robot account's grants name registry projects, such as %s@registry:team-a", text, g.Role)
		}
		for _, s := range g.Scopes {
			if !s.Registry() {
				return nil, invalid("%q names a cluster; a robot account signs in to the image registry only", text)
			}
		}
	}
	return out, nil
}

func (m *Manager) fillRobot(r *settings.Robot, in RobotInput) error {
	if in.Description != nil {
		d, err := plainText(*in.Description, 200, "description")
		if err != nil {
			return err
		}
		r.Description = d
	}
	if in.Grants != nil {
		g, err := checkRobotGrants(in.Grants)
		if err != nil {
			return err
		}
		r.Grants = g
	}
	if in.Expires != nil {
		if *in.Expires == "" {
			r.Expires = nil
		} else {
			t, err := time.Parse(time.RFC3339, *in.Expires)
			if err != nil {
				return invalid("the expiry must be a time such as 2027-01-01T00:00:00Z")
			}
			t = t.UTC()
			r.Expires = &t
		}
	}
	if in.Disabled != nil {
		r.Disabled = *in.Disabled
	}
	return nil
}

// newSecret makes a robot's secret and the digest that is kept of it.
func newSecret() (secret, hash string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	secret = "kgr_" + hex.EncodeToString(b)
	return secret, digestOf(secret)
}

func digestOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func findRobot(robots []settings.Robot, name string) (int, bool) {
	for i, r := range robots {
		if r.Name == name {
			return i, true
		}
	}
	return -1, false
}

// Robots are the robot accounts, by name.
func (m *Manager) Robots() []RobotEntry {
	s := m.keeper.Get()
	out := make([]RobotEntry, 0, len(s.Robots))
	for _, r := range s.Robots {
		out = append(out, m.robotEntry(r))
	}
	byName(out, func(r RobotEntry) string { return r.Name })
	return out
}

// AddRobot makes a robot account; its secret is returned this once.
func (m *Manager) AddRobot(ctx context.Context, in RobotInput, by string) (RobotEntry, string, error) {
	name := strings.TrimSpace(strings.TrimPrefix(in.Name, RobotPrefix))
	if !validRobotName.MatchString(name) {
		return RobotEntry{}, "", invalid("a robot account's name is lowercase letters, digits and . _ -, starting with a letter or digit, up to 63 characters")
	}
	if in.Grants == nil {
		return RobotEntry{}, "", invalid("a robot account needs a grant, such as operator@registry:team-a")
	}
	secret, hash := newSecret()
	r := settings.Robot{Name: name, Hash: hash, Created: m.now().UTC(), By: by}
	if err := m.fillRobot(&r, in); err != nil {
		return RobotEntry{}, "", err
	}
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		if _, ok := findRobot(s.Robots, name); ok {
			return invalid("there is a robot account named %q already", name)
		}
		if len(s.Robots) >= MaxRobots {
			return invalid("there are %d robot accounts already, the most there may be", MaxRobots)
		}
		s.Robots = append(s.Robots, r)
		return nil
	})
	if err != nil {
		return RobotEntry{}, "", err
	}
	return m.robotEntry(r), secret, nil
}

// UpdateRobot changes a robot account; see RobotInput.
func (m *Manager) UpdateRobot(ctx context.Context, name string, in RobotInput, by string) (before, after RobotEntry, err error) {
	_, err = m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findRobot(s.Robots, name)
		if !ok {
			return ErrRobotNotFound
		}
		before = m.robotEntry(s.Robots[i])
		r := s.Robots[i]
		if err := m.fillRobot(&r, in); err != nil {
			return err
		}
		r.Changed, r.ChangedBy = m.now().UTC(), by
		s.Robots[i] = r
		after = m.robotEntry(r)
		return nil
	})
	return before, after, err
}

// RotateRobot gives a robot account a new secret, returned this once; the
// old one stops working at once.
func (m *Manager) RotateRobot(ctx context.Context, name, by string) (RobotEntry, string, error) {
	secret, hash := newSecret()
	var out RobotEntry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findRobot(s.Robots, name)
		if !ok {
			return ErrRobotNotFound
		}
		s.Robots[i].Hash = hash
		s.Robots[i].Changed, s.Robots[i].ChangedBy = m.now().UTC(), by
		out = m.robotEntry(s.Robots[i])
		return nil
	})
	if err != nil {
		return RobotEntry{}, "", err
	}
	return out, secret, nil
}

// RemoveRobot deletes a robot account.
func (m *Manager) RemoveRobot(ctx context.Context, name string) (RobotEntry, error) {
	var out RobotEntry
	_, err := m.keeper.Update(ctx, func(s *settings.Settings) error {
		i, ok := findRobot(s.Robots, name)
		if !ok {
			return ErrRobotNotFound
		}
		out = m.robotEntry(s.Robots[i])
		s.Robots = append(s.Robots[:i], s.Robots[i+1:]...)
		return nil
	})
	return out, err
}

// CheckRobot signs a robot account in: its login (robot$name) and its
// secret. A disabled or expired one is refused.
func (m *Manager) CheckRobot(login, secret string) (auth.User, bool) {
	name, ok := strings.CutPrefix(login, RobotPrefix)
	if !ok {
		return auth.User{}, false
	}
	s := m.keeper.Get()
	i, found := findRobot(s.Robots, name)
	hash := digestOf(secret)
	if !found {
		// Compared anyway, so timing does not tell which names exist.
		subtle.ConstantTimeCompare([]byte(hash), []byte(strings.Repeat("0", len(hash))))
		return auth.User{}, false
	}
	r := s.Robots[i]
	if subtle.ConstantTimeCompare([]byte(hash), []byte(r.Hash)) != 1 || r.Disabled || (r.Expires != nil && m.now().After(*r.Expires)) {
		return auth.User{}, false
	}
	return auth.NewUser(RobotPrefix+r.Name, parseAll(r.Grants)), true
}
