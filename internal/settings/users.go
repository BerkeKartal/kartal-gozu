package settings

import "time"

// User is someone an admin added in the UI, who signs in with a name and
// password. Only the password's hash is kept (auth.HashPassword).
//
// Grants say what they may do where, each written as auth.ParseGrant reads
// it ("operator@production/team-a"). Grant is the single grant users had
// before there could be several; it is still read, and folded into Grants
// the next time the user is saved.
type User struct {
	Name      string    `json:"name"`
	FullName  string    `json:"fullName,omitempty"`
	Email     string    `json:"email,omitempty"`
	Grant     string    `json:"grant,omitempty"`
	Grants    []string  `json:"grants,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	Hash      string    `json:"hash"`
	Created   time.Time `json:"created"`
	By        string    `json:"by"`
	Changed   time.Time `json:"changed,omitempty"`
	ChangedBy string    `json:"changedBy,omitempty"`
}

// AllGrants are the user's grants, the old single one included.
func (u User) AllGrants() []string {
	out := make([]string, 0, len(u.Grants)+1)
	if u.Grant != "" {
		out = append(out, u.Grant)
	}
	return append(out, u.Grants...)
}

// Group gives its grants to its members: people named in Members (users of
// the UI, of KARTAL_USERS who sign in with a password, or of the directory)
// and the members of the directory groups in Directory (whole DNs or CNs).
type Group struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Grants      []string  `json:"grants,omitempty"`
	Members     []string  `json:"members,omitempty"`
	Directory   []string  `json:"directory,omitempty"`
	Created     time.Time `json:"created"`
	By          string    `json:"by"`
	Changed     time.Time `json:"changed,omitempty"`
	ChangedBy   string    `json:"changedBy,omitempty"`
}
