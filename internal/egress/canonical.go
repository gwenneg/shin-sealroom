package egress

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Every check here refuses; none normalizes. A request that is not already
// in its one canonical form never reaches a rule: a proxy that decides on
// one reading of a request and forwards another is how path, header and
// host confusions bypass proxies.

// Refusal reasons, stable codes for the audit log and the agent.
const (
	reasonForm      = "request-form"
	reasonPath      = "path"
	reasonQuery     = "query"
	reasonHost      = "host"
	reasonHeader    = "header"
	reasonBody      = "body"
	reasonNoRule    = "no-rule"
	reasonTooLarge  = "too-large"
	reasonUpstream  = "upstream"
	reasonForbidden = "forbidden-address"
	reasonCred      = "credential"
	reasonTool      = "server-tool"
	reasonToken     = "token-unavailable"
)

// refusal is a request refused with a reason code.
type refusal struct {
	reason string
	err    error
}

func (r *refusal) Error() string { return r.reason + ": " + r.err.Error() }

func refuse(reason string, format string, args ...any) *refusal {
	return &refusal{reason, fmt.Errorf(format, args...)}
}

// pathByte reports whether b may appear in a path segment: letters, digits
// and -._~:@. No percent-encoding, so the raw path and the decoded path are
// the same bytes.
func pathByte(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' ||
		strings.IndexByte("-._~:@", b) >= 0
}

// checkPath accepts only a canonical absolute path: rooted, no empty
// segment, no dot segment, and only pathByte bytes.
func checkPath(p string) error {
	return checkSegments(p, false)
}

// checkPattern is checkPath for a rule, where a segment may be "*", and the
// last one "**".
func checkPattern(p string) error {
	return checkSegments(p, true)
}

// CheckPathPattern checks a path pattern as rules use it, for what plugins
// declare.
func CheckPathPattern(p string) error {
	return checkPattern(p)
}

func checkSegments(p string, pattern bool) error {
	if p == "/" {
		return nil
	}
	if !strings.HasPrefix(p, "/") || len(p) > 2048 {
		return errors.New("not a rooted path of at most 2048 bytes")
	}
	segs := strings.Split(p[1:], "/")
	for i, seg := range segs {
		switch {
		case seg == "":
			return errors.New("empty segment")
		case seg == "." || seg == "..":
			return errors.New("dot segment")
		case pattern && seg == "*":
			continue
		case pattern && seg == "**" && i == len(segs)-1:
			continue
		}
		for i := 0; i < len(seg); i++ {
			if !pathByte(seg[i]) {
				return fmt.Errorf("byte %q", seg[i])
			}
		}
	}
	return nil
}

// checkQuery accepts name=value pairs joined by &, with letters, digits,
// -._~ and well-formed percent-escapes of any byte but a control one or DEL.
// Escapes of bytes over 0x7f stay allowed, for UTF-8 search terms.
func checkQuery(q string) error {
	if len(q) > 2048 {
		return errors.New("longer than 2048 bytes")
	}
	for _, pair := range strings.Split(q, "&") {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return fmt.Errorf("%q is not name=value", pair)
		}
		for _, part := range []string{name, value} {
			for i := 0; i < len(part); i++ {
				b := part[i]
				switch {
				case pathByte(b) && b != ':' && b != '@':
				case b == '%' && i+2 < len(part) && isHex(part[i+1]) && isHex(part[i+2]) && unhex(part[i+1])<<4|unhex(part[i+2]) >= 0x20 && unhex(part[i+1])<<4|unhex(part[i+2]) != 0x7f:
					i += 2
				default:
					return fmt.Errorf("byte %q", b)
				}
			}
		}
	}
	return nil
}

func isHex(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}

func unhex(b byte) byte {
	switch {
	case b <= '9':
		return b - '0'
	case b <= 'F':
		return b - 'A' + 10
	default:
		return b - 'a' + 10
	}
}

// credentialHeaders carry credentials. Only the proxy ever sets one upstream.
// From the agent, Authorization and X-Api-Key may hold the placeholder,
// which is dropped; anything else in any of them refuses the request.
var credentialHeaders = map[string]struct{}{
	"Authorization": {}, "X-Api-Key": {}, "Proxy-Authorization": {}, "Cookie": {},
	"Private-Token": {}, "X-Goog-Api-Key": {}, "X-Goog-User-Project": {},
	"X-Goog-Iam-Authorization-Token": {}, "X-Amz-Security-Token": {}, "X-Auth-Token": {},
}

// hopByHop headers are never forwarded, in either direction.
var hopByHop = map[string]struct{}{
	"Connection": {}, "Keep-Alive": {}, "Proxy-Authenticate": {}, "Proxy-Authorization": {},
	"Proxy-Connection": {}, "Te": {}, "Trailer": {}, "Transfer-Encoding": {}, "Upgrade": {},
}

// checkRequest checks everything about a request but the rule: its form,
// path, query, host and headers. sni is the TLS server name the connection
// was opened with, already one of the allowed hosts.
func checkRequest(r *http.Request, sni string) (path, query string, err *refusal) {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		return "", "", refuse(reasonForm, "protocol %s", r.Proto)
	}
	// Origin form only: "/path?query". No absolute URI, no "*", no CONNECT.
	uri := r.RequestURI
	if r.Method == http.MethodConnect || !strings.HasPrefix(uri, "/") {
		return "", "", refuse(reasonForm, "request target %q is not in origin form", uri)
	}
	path, query, hasQuery := strings.Cut(uri, "?")
	if strings.ContainsAny(uri, "#") {
		return "", "", refuse(reasonForm, "fragment in the request target")
	}
	if err := checkPath(path); err != nil {
		return "", "", refuse(reasonPath, "%v", err)
	}
	if hasQuery {
		if err := checkQuery(query); err != nil {
			return "", "", refuse(reasonQuery, "%v", err)
		}
	}
	// The Host header must name exactly the host the TLS connection is for:
	// no other name, no port but 443, no trailing dot, no other case.
	host := r.Host
	if h, port, ok := strings.Cut(host, ":"); ok {
		if port != "443" {
			return "", "", refuse(reasonHost, "port %q", port)
		}
		host = h
	}
	if host != sni {
		return "", "", refuse(reasonHost, "host %q is not the TLS server name", r.Host)
	}
	if ref := checkHeaders(r); ref != nil {
		return "", "", ref
	}
	return path, query, nil
}

// checkHeaders refuses what could make the proxy and the server read a
// request differently: duplicates, odd names or bytes, upgrades, framing
// that is not plain.
func checkHeaders(r *http.Request) *refusal {
	for name, values := range r.Header {
		if len(values) != 1 {
			return refuse(reasonHeader, "%d values for %s", len(values), name)
		}
		for i := 0; i < len(name); i++ {
			if b := name[i]; !(b == '-' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9') {
				return refuse(reasonHeader, "header name %q", name)
			}
		}
		for i := 0; i < len(values[0]); i++ {
			if b := values[0][i]; b != '\t' && (b < 0x20 || b > 0x7e) {
				return refuse(reasonHeader, "byte %q in %s", b, name)
			}
		}
	}
	if r.Header.Get("Upgrade") != "" {
		return refuse(reasonForm, "upgrade")
	}
	// An empty Expect, as git sends, is no expectation.
	if r.Header.Get("Expect") != "" {
		return refuse(reasonForm, "expect")
	}
	if c := strings.ToLower(r.Header.Get("Connection")); c != "" && c != "keep-alive" && c != "close" {
		return refuse(reasonHeader, "connection %q", c)
	}
	// Go's server accepts a request with both Content-Length and chunked
	// framing, reading it as chunked. The request sent upstream is built anew,
	// with its own framing and no trailers, so no other reading reaches the
	// server; this keeps the only framing forms simple and known.
	if len(r.TransferEncoding) > 1 || len(r.TransferEncoding) == 1 && r.TransferEncoding[0] != "chunked" {
		return refuse(reasonBody, "transfer encoding %v", r.TransferEncoding)
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.ContentLength > 0 || len(r.TransferEncoding) > 0) {
		return refuse(reasonBody, "a body on %s", r.Method)
	}
	if len(r.Trailer) > 0 {
		return refuse(reasonHeader, "trailers")
	}
	return nil
}
