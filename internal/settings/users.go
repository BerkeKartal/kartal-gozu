package settings

import "time"

// User is someone an admin added in the UI, who signs in with a name and
// password. Only the password's hash is kept (auth.HashPassword).
type User struct {
	Name      string    `json:"name"`
	Grant     string    `json:"grant"`
	Hash      string    `json:"hash"`
	Created   time.Time `json:"created"`
	By        string    `json:"by"`
	Changed   time.Time `json:"changed,omitempty"`
	ChangedBy string    `json:"changedBy,omitempty"`
}
