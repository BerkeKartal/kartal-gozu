package settings

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Check is an address the server requests regularly, to tell whether it
// answers and, for https, when its certificate expires.
type Check struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Interval is how often, in seconds.
	Interval int `json:"interval"`
	// Timeout is how long one request may take, in seconds.
	Timeout int `json:"timeout"`
	// Status is the status code expected; 0 accepts any below 400.
	Status int `json:"status,omitempty"`
	// Contains, when set, must appear in the start of the body.
	Contains string `json:"contains,omitempty"`
	// Insecure skips verifying the certificate; its expiry is still watched.
	Insecure bool `json:"insecure,omitempty"`
}

const (
	// MaxChecks keeps the server from becoming a load generator.
	MaxChecks       = 200
	defaultInterval = 60
	defaultTimeout  = 10
)

// Normalize trims a check and fills in the defaults (https for an address
// without a scheme), then validates it.
func (c *Check) Normalize() error {
	c.Name, c.URL, c.Contains = strings.TrimSpace(c.Name), strings.TrimSpace(c.URL), strings.TrimSpace(c.Contains)
	if c.URL != "" && !strings.Contains(c.URL, "://") {
		c.URL = "https://" + c.URL
	}
	if c.Interval == 0 {
		c.Interval = defaultInterval
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.Name == "" {
		c.Name = c.URL
	}
	return c.Validate()
}

// Validate tells what is wrong with a check, if anything.
func (c Check) Validate() error {
	if c.Name == "" || len(c.Name) > 100 || strings.IndexFunc(c.Name, unicode.IsControl) >= 0 {
		return errors.New("the name must be 1 to 100 characters on one line")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(c.URL) > 2000 {
		return fmt.Errorf("%q is not an http:// or https:// address", c.URL)
	}
	if u.User != nil {
		return errors.New("put no user name or password in the address: everyone who sees the checks would see them")
	}
	if c.Interval < 30 || c.Interval > 3600 {
		return errors.New("the interval must be 30 to 3600 seconds")
	}
	if c.Timeout < 1 || c.Timeout > 60 || c.Timeout >= c.Interval {
		return errors.New("the timeout must be 1 to 60 seconds, and shorter than the interval")
	}
	if c.Status != 0 && (c.Status < 100 || c.Status > 599) {
		return fmt.Errorf("%d is not an HTTP status code", c.Status)
	}
	if len(c.Contains) > 200 {
		return errors.New("the text to look for may be at most 200 characters")
	}
	return nil
}

// NewCheckID makes an identifier for a new check.
func NewCheckID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
