package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// RFC 7914, section 11: PBKDF2-HMAC-SHA256 test vectors.
func TestPBKDF2Vectors(t *testing.T) {
	for _, c := range []struct {
		password, salt string
		iterations     int
		want           string
	}{
		{"passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	} {
		got := hex.EncodeToString(pbkdf2SHA256([]byte(c.password), []byte(c.salt), c.iterations, 64))
		if got != c.want {
			t.Errorf("%s/%s/%d: %s", c.password, c.salt, c.iterations, got)
		}
	}
}

func TestPasswordUsers(t *testing.T) {
	hash, err := HashPassword("dogru-parola-1")
	if err != nil {
		t.Fatal(err)
	}
	if !IsPasswordHash(hash) || strings.Contains(hash, "dogru") {
		t.Fatalf("hash: %s", hash)
	}
	if again, _ := HashPassword("dogru-parola-1"); again == hash {
		t.Error("two hashes of one password are the same: no salt")
	}
	tokens, passwords, err := ParseUsers("ali:operator@production/payments-*:" + hash + "\nscript:viewer:aaaaaaaaaaaaaaaa1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || passwords.Len() != 1 {
		t.Fatalf("%d tokens, %d passwords", len(tokens), passwords.Len())
	}
	if _, ok := tokens[hash]; ok {
		t.Error("a password hash works as a token")
	}
	ctx := context.Background()
	u, err := passwords.Login(ctx, " ALI ", "dogru-parola-1")
	if err != nil || u.Name != "ali" || u.RoleIn("production", "payments-api") != Operator || u.RoleIn("production", "kube-system") != 0 {
		t.Fatalf("sign-in: %+v %v", u, err)
	}
	for _, c := range [][2]string{{"ali", "yanlis-parola-1"}, {"veli", "dogru-parola-1"}, {"ali", ""}} {
		if _, err := passwords.Login(ctx, c[0], c[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s/%s: %v", c[0], c[1], err)
		}
	}
	if _, err := HashPassword("kisa"); err == nil {
		t.Error("a short password was hashed")
	}
}

func TestParseUsersRejectsBadHashes(t *testing.T) {
	good, _ := HashPassword("dogru-parola-1")
	parts := strings.Split(good, "$")
	for _, h := range []string{
		"pbkdf2-sha256$600000$abc",                              // missing key
		"pbkdf2-sha256$1000$" + parts[2] + "$" + parts[3],       // too few iterations
		"pbkdf2-sha256$600000$" + parts[2] + "$" + parts[3][:8], // short key
		"pbkdf2-sha256$600000$!!!$" + parts[3],                  // bad salt
	} {
		if _, _, err := ParseUsers("ali:viewer:" + h); err == nil {
			t.Errorf("%q was accepted", h)
		}
	}
	// A name may not be both, even in another case.
	if _, _, err := ParseUsers("ali:viewer:" + good + "\nALI:admin:aaaaaaaaaaaaaaaa1"); err == nil {
		t.Error("a name listed twice was accepted")
	}
}

type fixedLogin struct {
	u   User
	err error
}

func (f fixedLogin) Login(context.Context, string, string) (User, error) { return f.u, f.err }

func TestChain(t *testing.T) {
	ctx := context.Background()
	wrong := fixedLogin{err: ErrInvalidCredentials}
	ok := fixedLogin{u: User{Name: "ayse"}}
	down := fixedLogin{err: errors.New("directory down")}
	if u, err := (Chain{wrong, ok}).Login(ctx, "", ""); err != nil || u.Name != "ayse" {
		t.Errorf("wrong then right: %+v %v", u, err)
	}
	if _, err := (Chain{fixedLogin{err: ErrNoAccess}, ok}).Login(ctx, "", ""); !errors.Is(err, ErrNoAccess) {
		t.Errorf("no access should be final: %v", err)
	}
	if _, err := (Chain{wrong, down}).Login(ctx, "", ""); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a directory that did not answer should say so: %v", err)
	}
	if _, err := (Chain{wrong, wrong}).Login(ctx, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("all wrong: %v", err)
	}
}
