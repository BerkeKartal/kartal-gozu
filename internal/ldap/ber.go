package ldap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// LDAP messages are BER: every value is a tag, a length and the content,
// and constructed values nest more of them. This is the part of BER that
// LDAP needs: one-byte tags, definite lengths.

const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructed      = 0x20

	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x30
	tagSet         = 0x31
)

// The LDAP messages and choices used (RFC 4511), each a class and a number.
const (
	tagBindRequest      = classApplication | constructed // number 0
	tagBindResponse     = classApplication | constructed | 1
	tagUnbindRequest    = classApplication | 2
	tagSearchRequest    = classApplication | constructed | 3
	tagSearchEntry      = classApplication | constructed | 4
	tagSearchDone       = classApplication | constructed | 5
	tagSearchReference  = classApplication | constructed | 19
	tagExtendedRequest  = classApplication | constructed | 23
	tagExtendedResponse = classApplication | constructed | 24
	tagEqualityMatch    = classContext | constructed | 3
	// Both are [0] in their own message: a simple bind's password, and an
	// extended request's name.
	tagSimpleAuth   = classContext
	tagExtendedName = classContext
)

// maxMessage bounds what a server may send in one message.
const maxMessage = 4 << 20

func appendLength(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n < 0x100:
		return append(b, 0x81, byte(n))
	case n < 0x10000:
		return append(b, 0x82, byte(n>>8), byte(n))
	default:
		return append(b, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// tlv encodes one value.
func tlv(tag byte, content []byte) []byte {
	out := appendLength([]byte{tag}, len(content))
	return append(out, content...)
}

// seq encodes a constructed value from encoded parts.
func seq(tag byte, parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return tlv(tag, content)
}

func octets(tag byte, s string) []byte { return tlv(tag, []byte(s)) }

func integer(tag byte, v int) []byte {
	// Two's complement, big-endian, as short as it goes.
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return tlv(tag, b)
}

func boolean(v bool) []byte {
	if v {
		return tlv(tagBoolean, []byte{0xff})
	}
	return tlv(tagBoolean, []byte{0})
}

// packet is one decoded value.
type packet struct {
	tag   byte
	value []byte
}

// parse reads one value off the front of b.
func parse(b []byte) (packet, []byte, error) {
	if len(b) < 2 {
		return packet{}, nil, errors.New("ldap: truncated value")
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return packet{}, nil, errors.New("ldap: multi-byte tags are not supported")
	}
	n, hdr := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return packet{}, nil, errors.New("ldap: bad length")
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		hdr += k
	}
	if n < 0 || n > len(b)-hdr {
		return packet{}, nil, errors.New("ldap: truncated value")
	}
	return packet{tag: tag, value: b[hdr : hdr+n]}, b[hdr+n:], nil
}

// kids decodes the values inside a constructed one.
func (p packet) kids() ([]packet, error) {
	var out []packet
	rest := p.value
	for len(rest) > 0 {
		k, r, err := parse(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		rest = r
	}
	return out, nil
}

func (p packet) int() (int, error) {
	if len(p.value) == 0 || len(p.value) > 4 {
		return 0, fmt.Errorf("ldap: bad integer of %d bytes", len(p.value))
	}
	v := int(int8(p.value[0])) // the sign
	for _, c := range p.value[1:] {
		v = v<<8 | int(c)
	}
	return v, nil
}

func (p packet) str() string { return string(p.value) }

// readMessage reads one whole message from a connection.
func readMessage(r *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 2, 6)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 {
			return nil, errors.New("ldap: bad length")
		}
		ext := make([]byte, k)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		hdr = append(hdr, ext...)
		n = 0
		for _, c := range ext {
			n = n<<8 | int(c)
		}
	}
	if n > maxMessage {
		return nil, errors.New("ldap: message too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}
