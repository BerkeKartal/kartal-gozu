package ldap

import (
	"bufio"
	"net"
	"strings"
	"sync"
)

// Fake is a tiny directory for tests and the demo: people with a password
// and groups, over plain LDAP. Like real servers, it accepts an anonymous
// bind (no name, no password), which the client must never take for a
// sign-in.
type Fake struct {
	Domain       string // people may bind as name@Domain
	BindDN       string // an optional service account
	BindPassword string
	People       map[string]FakePerson // by sign-in name

	ln   net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	open map[net.Conn]bool
}

// FakePerson is someone in a Fake directory.
type FakePerson struct {
	Password    string
	DisplayName string
	Groups      []string
	// Refusal, such as "532" (password expired), is the Active Directory
	// code a bind with the right password gets instead of success.
	Refusal string
}

// DN is the entry name of a person.
func (f *Fake) DN(name string) string { return "CN=" + name + ",OU=People,DC=example,DC=org" }

// Start listens on a free local port and returns the ldap:// URL.
func (f *Fake) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	f.ln, f.open = ln, map[net.Conn]bool{}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.open[c] = true
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.serve(c)
				f.mu.Lock()
				delete(f.open, c)
				f.mu.Unlock()
			}()
		}
	}()
	return "ldap://" + ln.Addr().String(), nil
}

// Close stops the directory and waits for its connections to end.
func (f *Fake) Close() {
	f.ln.Close()
	f.mu.Lock()
	for c := range f.open {
		c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *Fake) person(bindName string) (string, FakePerson, bool) {
	for name, p := range f.People {
		if strings.EqualFold(bindName, name+"@"+f.Domain) || strings.EqualFold(bindName, f.DN(name)) {
			return name, p, true
		}
	}
	return "", FakePerson{}, false
}

func (f *Fake) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	bound := false
	reply := func(id int, op []byte) { c.Write(seq(tagSequence, integer(tagInteger, id), op)) }
	done := func(tag byte, code int, msg string) []byte {
		return seq(tag, tlv(tagEnumerated, []byte{byte(code)}), octets(tagOctetString, ""), octets(tagOctetString, msg))
	}
	for {
		raw, err := readMessage(r)
		if err != nil {
			return
		}
		msg, _, err := parse(raw)
		if err != nil {
			return
		}
		parts, err := msg.kids()
		if err != nil || len(parts) < 2 {
			return
		}
		id, _ := parts[0].int()
		op := parts[1]
		switch op.tag {
		case tagBindRequest:
			args, _ := op.kids()
			if len(args) < 3 {
				return
			}
			name, password := args[1].str(), args[2].str()
			_, p, isPerson := f.person(name)
			switch {
			case name == "" && password == "":
				bound = true // anonymous, as real servers allow
				reply(id, done(tagBindResponse, 0, ""))
			case isPerson && password == p.Password && p.Refusal != "":
				bound = false
				reply(id, done(tagBindResponse, codeInvalidCredentials, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data "+p.Refusal+", v4563"))
			case (f.BindDN != "" && name == f.BindDN && password == f.BindPassword) || (isPerson && password == p.Password):
				bound = true
				reply(id, done(tagBindResponse, 0, ""))
			default:
				bound = false
				reply(id, done(tagBindResponse, codeInvalidCredentials, "80090308: AcceptSecurityContext error"))
			}
		case tagSearchRequest:
			if !bound {
				reply(id, done(tagSearchDone, 1, "a bind must come first"))
				continue
			}
			args, _ := op.kids()
			if len(args) < 7 {
				return
			}
			kv, _ := args[6].kids()
			if len(kv) == 2 && args[6].tag == tagEqualityMatch {
				attr, value := kv[0].str(), kv[1].str()
				// Like Active Directory, names match whatever their case.
				for name, p := range f.People {
					if !(strings.EqualFold(attr, "sAMAccountName") && strings.EqualFold(value, name)) &&
						!(strings.EqualFold(attr, "userPrincipalName") && strings.EqualFold(value, name+"@"+f.Domain)) {
						continue
					}
					groups := make([][]byte, len(p.Groups))
					for i, g := range p.Groups {
						groups[i] = octets(tagOctetString, g)
					}
					reply(id, seq(tagSearchEntry, octets(tagOctetString, f.DN(name)), seq(tagSequence,
						seq(tagSequence, octets(tagOctetString, "sAMAccountName"), seq(tagSet, octets(tagOctetString, name))),
						seq(tagSequence, octets(tagOctetString, "memberOf"), seq(tagSet, groups...)),
						seq(tagSequence, octets(tagOctetString, "displayName"), seq(tagSet, octets(tagOctetString, p.DisplayName))))))
				}
			}
			reply(id, done(tagSearchDone, 0, ""))
		case tagUnbindRequest:
			return
		default: // StartTLS and anything else
			reply(id, done(tagExtendedResponse, 2, "not supported here"))
		}
	}
}
