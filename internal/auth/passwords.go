package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A user of KARTAL_USERS may have a password instead of a token: the entry's
// last field is then a hash, written by HashPassword (kartal-server
// hash-password), and the user signs in with a name and password as with a
// directory. The hash is PBKDF2 with SHA-256 (RFC 8018):
//
//	pbkdf2-sha256$<iterations>$<salt>$<key>
//
// with the salt and the 32-byte key in unpadded base64.
const (
	passwordScheme     = "pbkdf2-sha256"
	passwordIterations = 600_000
	// Fewer would make a stolen hash cheap to guess.
	minPasswordIterations = 100_000
	passwordSaltBytes     = 16
	passwordKeyBytes      = sha256.Size
	// MinPasswordLength keeps passwords from being guessable.
	MinPasswordLength = 10
)

// IsPasswordHash tells whether a KARTAL_USERS secret is a password hash
// rather than a token.
func IsPasswordHash(secret string) bool {
	return strings.HasPrefix(secret, passwordScheme+"$")
}

// HashPassword returns the hash to put in KARTAL_USERS for a password.
func HashPassword(password string) (string, error) {
	if len([]rune(password)) < MinPasswordLength {
		return "", fmt.Errorf("the password is shorter than %d characters", MinPasswordLength)
	}
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, passwordIterations, passwordKeyBytes)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", passwordScheme, passwordIterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

type passwordHash struct {
	iterations int
	salt, key  []byte
}

func parsePasswordHash(s string) (passwordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return passwordHash{}, errors.New("a password hash must look like pbkdf2-sha256$<iterations>$<salt>$<key>; make one with kartal-server hash-password")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < minPasswordIterations || iter > 100_000_000 {
		return passwordHash{}, fmt.Errorf("a password hash needs at least %d iterations", minPasswordIterations)
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	key, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) != passwordKeyBytes {
		return passwordHash{}, errors.New("a password hash has a damaged salt or key; make it again with kartal-server hash-password")
	}
	return passwordHash{iterations: iter, salt: salt, key: key}, nil
}

func (h passwordHash) matches(password string) bool {
	got := pbkdf2SHA256([]byte(password), h.salt, h.iterations, len(h.key))
	return subtle.ConstantTimeCompare(got, h.key) == 1
}

// pbkdf2SHA256 is PBKDF2 (RFC 8018, section 5.2) with HMAC-SHA-256.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	out := make([]byte, 0, keyLen)
	u := make([]byte, sha256.Size)
	t := make([]byte, sha256.Size)
	for block := uint32(1); len(out) < keyLen; block++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u = prf.Sum(u[:0])
		copy(t, u)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// decoy is checked for names nobody has, so that how long a refusal takes
// does not tell which names exist.
var decoy = passwordHash{iterations: passwordIterations, salt: make([]byte, passwordSaltBytes), key: make([]byte, passwordKeyBytes)}

// DecoyPassword takes as long as checking a password, for a name nobody has.
func DecoyPassword(password string) { decoy.matches(password) }

// CheckPassword tells whether a password matches a hash from HashPassword;
// a damaged hash matches nothing.
func CheckPassword(hash, password string) bool {
	h, err := parsePasswordHash(hash)
	if err != nil {
		DecoyPassword(password)
		return false
	}
	return h.matches(password)
}

// Passwords signs in the users of KARTAL_USERS that have a password.
type Passwords struct {
	byName map[string]passwordUser
}

type passwordUser struct {
	user User
	hash passwordHash
}

func newPasswords() *Passwords {
	return &Passwords{byName: map[string]passwordUser{}}
}

// Len is how many users have a password.
func (p *Passwords) Len() int { return len(p.byName) }

// Users are the users with a password.
func (p *Passwords) Users() []User {
	out := make([]User, 0, len(p.byName))
	for _, pu := range p.byName {
		out = append(out, pu.user)
	}
	return out
}

func (p *Passwords) add(u User, h passwordHash) {
	p.byName[strings.ToLower(u.Name)] = passwordUser{user: u, hash: h}
}

// Login checks a name and password; names are matched regardless of case.
func (p *Passwords) Login(_ context.Context, name, password string) (User, error) {
	pu, ok := p.byName[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		DecoyPassword(password)
		return User{}, ErrInvalidCredentials
	}
	if !pu.hash.matches(password) {
		return User{}, ErrInvalidCredentials
	}
	return pu.user, nil
}

// Login checks a user name and password.
type Login interface {
	Login(ctx context.Context, user, password string) (User, error)
}

// Chain tries its logins in turn: a wrong name or password moves on to the
// next, any other answer (signed in, no access, a directory that did not
// answer) is final.
type Chain []Login

// Login asks each login in turn.
func (c Chain) Login(ctx context.Context, user, password string) (User, error) {
	for _, l := range c {
		u, err := l.Login(ctx, user, password)
		if !errors.Is(err, ErrInvalidCredentials) {
			return u, err
		}
	}
	return User{}, ErrInvalidCredentials
}
