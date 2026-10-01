// Package ldap signs people in against Active Directory or another LDAP
// server: a small LDAPv3 client (a simple bind and one search, over TLS)
// and the mapping of the user's groups to Kartal Gözü roles.
package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/auth"
)

// Config says where the directory is and how to find people in it.
type Config struct {
	// URL is ldaps://host:636, or ldap://host:389 (with StartTLS, or plain
	// only for testing).
	URL      string
	StartTLS bool
	TLS      *tls.Config
	// BindDN and BindPassword are a service account that looks people up.
	// Without one, people bind as user@UPNDomain (Active Directory) and
	// look themselves up.
	BindDN       string
	BindPassword string
	UPNDomain    string
	// UserBase is where people are searched for, UserAttr the attribute
	// that holds the name they sign in with (sAMAccountName in AD).
	UserBase string
	UserAttr string
	Timeout  time.Duration
}

// Entry is someone found in the directory.
type Entry struct {
	DN string
	// Name is the name they sign in with, as the directory spells it.
	Name        string
	DisplayName string
	Groups      []string // the DNs of the groups they are a direct member of
}

var (
	// ErrInvalidCredentials is a wrong name or password; which of the two
	// is not told.
	ErrInvalidCredentials = auth.ErrInvalidCredentials
	errNotFound           = errors.New("no such user")
)

// resultError is an LDAP result other than success.
type resultError struct {
	code    int
	message string
}

func (e *resultError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("ldap result %d: %s", e.code, e.message)
	}
	return fmt.Sprintf("ldap result %d", e.code)
}

const codeInvalidCredentials = 49

// Authenticate checks a user's password and returns their entry.
func (c Config) Authenticate(ctx context.Context, user, password string) (Entry, error) {
	user = c.accountName(user)
	// An empty password is an "unauthenticated bind", which many servers
	// accept for any name: it must never count as signing in.
	if user == "" || password == "" || len(user) > 256 {
		return Entry{}, ErrInvalidCredentials
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer conn.close()

	// In Active Directory, someone may give their user principal name
	// (ayse@example.org) instead: it is then what is bound with and looked
	// up by.
	lookup := c.attr()
	upn := strings.Contains(user, "@") && strings.EqualFold(lookup, "sAMAccountName")
	if upn {
		lookup = "userPrincipalName"
	}
	if c.BindDN != "" {
		if err := conn.bind(c.BindDN, c.BindPassword); err != nil {
			return Entry{}, fmt.Errorf("the directory refused the service account: %w", err)
		}
	} else {
		bindName := user + "@" + c.UPNDomain
		if upn {
			bindName = user
		}
		if err := conn.bind(bindName, password); err != nil {
			return Entry{}, credentials(err)
		}
	}
	entry, err := conn.findUser(c.UserBase, lookup, c.attr(), user)
	if errors.Is(err, errNotFound) {
		return Entry{}, ErrInvalidCredentials
	}
	if err != nil {
		return Entry{}, err
	}
	if c.BindDN != "" {
		if err := conn.bind(entry.DN, password); err != nil {
			return Entry{}, credentials(err)
		}
	}
	if entry.Name == "" {
		entry.Name = user
	}
	return entry, nil
}

func (c Config) attr() string {
	if c.UserAttr == "" {
		return "sAMAccountName"
	}
	return c.UserAttr
}

// accountName is the name someone signs in with, however they wrote it:
// "EXAMPLE\ayse" and, in the UPN domain, "ayse@example.org" are "ayse".
func (c Config) accountName(user string) string {
	user = strings.TrimSpace(user)
	if i := strings.LastIndex(user, `\`); i >= 0 {
		user = user[i+1:]
	}
	if i := strings.LastIndex(user, "@"); i > 0 && c.UPNDomain != "" && strings.EqualFold(user[i+1:], c.UPNDomain) {
		user = user[:i]
	}
	return user
}

// accountError is a refused sign-in that is not a wrong password. Active
// Directory says why only to someone who gave the right password.
type accountError string

func (e accountError) Error() string        { return string(e) }
func (e accountError) Is(target error) bool { return target == ErrInvalidCredentials }

// adReasons are the "data" codes of Active Directory's refusals that are
// worth telling, by what they mean.
var adReasons = map[string]accountError{
	"532": "your password has expired; change it, then sign in again",
	"773": "your password must be changed before you can sign in",
	"533": "your account is disabled",
	"701": "your account has expired",
}

var adData = regexp.MustCompile(`\bdata ([0-9a-f]+)\b`)

// credentials turns a refused bind into ErrInvalidCredentials, or into the
// reason an account may not sign in.
func credentials(err error) error {
	var re *resultError
	if !errors.As(err, &re) || re.code != codeInvalidCredentials {
		return err
	}
	if m := adData.FindStringSubmatch(re.message); m != nil {
		if reason, ok := adReasons[m[1]]; ok {
			return reason
		}
	}
	return ErrInvalidCredentials
}

// conn is one connection to the directory.
type conn struct {
	nc   net.Conn
	r    *bufio.Reader
	next int
	stop func() bool
}

func (c Config) dial(ctx context.Context) (*conn, error) {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return nil, fmt.Errorf("the directory URL %q must be ldap://host or ldaps://host", c.URL)
	}
	host := u.Host
	if u.Port() == "" {
		port := "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	tc := c.tlsConfig(u.Hostname())
	var nc net.Conn
	if u.Scheme == "ldaps" {
		nc, err = (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", host)
	} else {
		nc, err = (&net.Dialer{}).DialContext(ctx, "tcp", host)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	// The whole conversation lives within the timeout.
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	cn := &conn{nc: nc, r: bufio.NewReader(nc), next: 1, stop: func() bool { cancel(); return stop() }}
	if u.Scheme == "ldap" && c.StartTLS {
		if err := cn.startTLS(tc); err != nil {
			cn.close()
			return nil, err
		}
	}
	return cn, nil
}

func (c Config) tlsConfig(host string) *tls.Config {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLS != nil {
		tc = c.TLS.Clone()
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	return tc
}

func (cn *conn) close() {
	// An unbind is a courtesy; the server closes its side either way.
	cn.nc.Write(seq(tagSequence, integer(tagInteger, cn.next), tlv(tagUnbindRequest, nil)))
	cn.stop()
	cn.nc.Close()
}

// send writes a request and returns its message id.
func (cn *conn) send(op []byte) (int, error) {
	id := cn.next
	cn.next++
	_, err := cn.nc.Write(seq(tagSequence, integer(tagInteger, id), op))
	return id, err
}

// receive reads the next message for id and returns its operation.
func (cn *conn) receive(id int) (packet, error) {
	for {
		raw, err := readMessage(cn.r)
		if err != nil {
			return packet{}, err
		}
		msg, _, err := parse(raw)
		if err != nil {
			return packet{}, err
		}
		parts, err := msg.kids()
		if err != nil || len(parts) < 2 {
			return packet{}, errors.New("ldap: bad message")
		}
		got, err := parts[0].int()
		if err != nil {
			return packet{}, err
		}
		if got == id {
			return parts[1], nil
		}
		// A notice of disconnection (id 0) ends the conversation.
		if got == 0 {
			return packet{}, errors.New("ldap: the server closed the connection")
		}
	}
}

// result reads an LDAPResult: code, matched DN, message.
func result(op packet) error {
	parts, err := op.kids()
	if err != nil || len(parts) < 3 {
		return errors.New("ldap: bad result")
	}
	code, err := parts[0].int()
	if err != nil {
		return err
	}
	if code != 0 {
		return &resultError{code: code, message: parts[2].str()}
	}
	return nil
}

func (cn *conn) bind(name, password string) error {
	id, err := cn.send(seq(tagBindRequest,
		integer(tagInteger, 3), octets(tagOctetString, name), octets(tagSimpleAuth, password)))
	if err != nil {
		return err
	}
	op, err := cn.receive(id)
	if err != nil {
		return err
	}
	if op.tag != tagBindResponse {
		return errors.New("ldap: unexpected answer to a bind")
	}
	return result(op)
}

func (cn *conn) startTLS(tc *tls.Config) error {
	id, err := cn.send(seq(tagExtendedRequest, octets(tagExtendedName, "1.3.6.1.4.1.1466.20037")))
	if err != nil {
		return err
	}
	op, err := cn.receive(id)
	if err != nil {
		return err
	}
	if op.tag != tagExtendedResponse {
		return errors.New("ldap: unexpected answer to StartTLS")
	}
	if err := result(op); err != nil {
		return fmt.Errorf("StartTLS: %w", err)
	}
	tlsConn := tls.Client(cn.nc, tc)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	cn.nc, cn.r = tlsConn, bufio.NewReader(tlsConn)
	return nil
}

// findUser looks for exactly one entry whose attr equals name, and reads
// its name from nameAttr. The filter is built as BER, never parsed from
// text, so no name can change it.
func (cn *conn) findUser(base, attr, nameAttr, name string) (Entry, error) {
	filter := seq(tagEqualityMatch, octets(tagOctetString, attr), octets(tagOctetString, name))
	attrs := seq(tagSequence, octets(tagOctetString, "memberOf"), octets(tagOctetString, "displayName"), octets(tagOctetString, nameAttr))
	id, err := cn.send(seq(tagSearchRequest,
		octets(tagOctetString, base),
		tlv(tagEnumerated, []byte{2}), // whole subtree
		tlv(tagEnumerated, []byte{0}), // never dereference aliases
		integer(tagInteger, 2),        // two are enough to tell "more than one"
		integer(tagInteger, 10),       // seconds
		boolean(false),
		filter, attrs))
	if err != nil {
		return Entry{}, err
	}
	var found []Entry
	for {
		op, err := cn.receive(id)
		if err != nil {
			return Entry{}, err
		}
		switch op.tag {
		case tagSearchEntry:
			e, err := decodeEntry(op, nameAttr)
			if err != nil {
				return Entry{}, err
			}
			found = append(found, e)
		case tagSearchReference: // a referral elsewhere
		case tagSearchDone:
			var re *resultError
			if err := result(op); err != nil && !(errors.As(err, &re) && re.code == 4 && len(found) > 1) {
				return Entry{}, err
			}
			switch len(found) {
			case 0:
				return Entry{}, errNotFound
			case 1:
				return found[0], nil
			}
			return Entry{}, fmt.Errorf("more than one directory entry has %s=%s", attr, name)
		default:
			return Entry{}, errors.New("ldap: unexpected answer to a search")
		}
	}
}

// decodeEntry reads a search result entry; nameAttr holds the user name.
func decodeEntry(op packet, nameAttr string) (Entry, error) {
	parts, err := op.kids()
	if err != nil || len(parts) < 2 {
		return Entry{}, errors.New("ldap: bad entry")
	}
	e := Entry{DN: parts[0].str()}
	attrs, err := parts[1].kids()
	if err != nil {
		return Entry{}, err
	}
	for _, a := range attrs {
		kv, err := a.kids()
		if err != nil || len(kv) < 2 {
			return Entry{}, errors.New("ldap: bad attribute")
		}
		vals, err := kv[1].kids()
		if err != nil {
			return Entry{}, err
		}
		name := kv[0].str()
		switch {
		case strings.EqualFold(name, "memberOf"):
			for _, v := range vals {
				e.Groups = append(e.Groups, v.str())
			}
		case strings.EqualFold(name, "displayName") && len(vals) > 0:
			e.DisplayName = vals[0].str()
		case strings.EqualFold(name, nameAttr) && len(vals) > 0:
			e.Name = vals[0].str()
		}
	}
	return e, nil
}
