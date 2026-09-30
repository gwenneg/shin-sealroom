// Package egress is Sealroom's proxy: the agent's only way out. It accepts
// one exact form of every request, decides on those bytes, and forwards the
// same bytes on a request it builds itself. Anything unusual is refused,
// never fixed. See docs/proxy.md.
package egress

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Rule allows one kind of request. Hosts and methods are exact; the path is
// exact except that a "*" segment stands for exactly one path segment, and a
// final "**" segment for one or more.
type Rule struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	// Query is the exact raw query required, "" for none, or AnyQuery for
	// any query that passes the strict query checks.
	Query string `json:"query"`
	// Headers are the request headers forwarded upstream, in canonical form;
	// every other header is dropped. A credential header is never one: the
	// rule's credential is added by the proxy.
	Headers []string `json:"headers"`
	// Credential, when set, is added to every request the rule allows.
	Credential *Credential `json:"credential,omitempty"`
	// InspectMessages refuses requests to Claude's Messages API that ask
	// Anthropic's servers to reach anything the proxy cannot see.
	InspectMessages bool `json:"inspect_messages,omitempty"`
}

// Credential says how the user's credential is added to a request.
type Credential struct {
	// Secret names the credential among the proxy's secrets, or is Google
	// for an access token minted from the user's Google credentials.
	Secret string `json:"secret"`
	// Header is Authorization or X-Api-Key.
	Header string `json:"header"`
	// Scheme formats the value: "" for the secret alone, "Bearer", "token",
	// or "basic-x-access-token" for git's Basic authentication.
	Scheme string `json:"scheme"`
}

// Google is the secret of a Credential minted from the user's Google
// credentials.
const Google = "google"

var schemes = []string{"", "Bearer", "token", "basic-x-access-token"}

// AnyQuery lets a rule accept any strict query.
const AnyQuery = "*"

// Config is the proxy's configuration for one run.
type Config struct {
	// Placeholder is the only credential the agent holds. It may appear in a
	// credential header, where it is dropped, and nowhere else.
	Placeholder string `json:"placeholder"`
	Rules       []Rule `json:"rules"`
}

var (
	hostPattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	headerPattern = regexp.MustCompile(`^[A-Z][a-z0-9]*(-[A-Z0-9][a-z0-9]*)*$`)
	methods       = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
)

// Validate checks every rule. A config with no rule is valid and allows
// nothing.
func (c Config) Validate() error {
	if len(c.Placeholder) < 8 || strings.ContainsFunc(c.Placeholder, func(r rune) bool { return !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) {
		return errors.New("the placeholder must be at least 8 lowercase letters, digits or dashes")
	}
	for i, r := range c.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	switch {
	case !slices.Contains(methods, r.Method):
		return fmt.Errorf("method %q", r.Method)
	case !hostPattern.MatchString(r.Host) || strings.Contains(r.Host, "xn--"):
		return fmt.Errorf("host %q is not a plain lowercase DNS name", r.Host)
	case checkPattern(r.Path) != nil:
		return fmt.Errorf("path %q: %v", r.Path, checkPattern(r.Path))
	case r.Query != "" && r.Query != AnyQuery && checkQuery(r.Query) != nil:
		return fmt.Errorf("query %q: %v", r.Query, checkQuery(r.Query))
	}
	for _, h := range r.Headers {
		if !headerPattern.MatchString(h) {
			return fmt.Errorf("header %q is not in canonical form", h)
		}
		if _, hop := hopByHop[h]; hop {
			return fmt.Errorf("header %q is never forwarded", h)
		}
		if _, cred := credentialHeaders[h]; cred {
			return fmt.Errorf("header %q carries credentials, which only the proxy adds", h)
		}
	}
	if c := r.Credential; c != nil {
		switch {
		case c.Secret == "":
			return errors.New("a credential needs a secret")
		case c.Header != "Authorization" && c.Header != "X-Api-Key":
			return fmt.Errorf("credential header %q", c.Header)
		case !slices.Contains(schemes, c.Scheme):
			return fmt.Errorf("credential scheme %q", c.Scheme)
		case c.Secret == Google && (c.Header != "Authorization" || c.Scheme != "Bearer"):
			return errors.New("a Google token goes in Authorization as a bearer token")
		}
	}
	return nil
}

// Hosts returns every host the rules name, the only names the proxy answers
// for and mints certificates for.
func (c Config) Hosts() []string {
	var hosts []string
	for _, r := range c.Rules {
		if !slices.Contains(hosts, r.Host) {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// errNoRule is the refusal of a well-formed request that no rule allows.
var errNoRule = errors.New("no rule allows this request")

// match returns the rule allowing a request, already checked for its form.
func (c Config) match(method, host, path, query string) (*Rule, error) {
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Method != method || r.Host != host || !pathMatches(r.Path, path) {
			continue
		}
		if r.Query == AnyQuery || r.Query == query {
			return r, nil
		}
	}
	return nil, errNoRule
}

// pathMatches compares a canonical path with a rule's pattern, segment by
// segment. A "*" segment matches exactly one segment, and a final "**"
// segment one or more; nothing else is a wildcard.
func pathMatches(pattern, path string) bool {
	ps, qs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if n := len(ps); n > 0 && ps[n-1] == "**" {
		if len(qs) < n {
			return false
		}
		qs = append(qs[:n-1], strings.Join(qs[n-1:], "/"))
		ps[n-1] = "*"
	}
	if len(ps) != len(qs) {
		return false
	}
	for i := range ps {
		if ps[i] == "*" {
			if qs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != qs[i] {
			return false
		}
	}
	return true
}
