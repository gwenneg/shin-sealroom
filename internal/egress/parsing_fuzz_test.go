package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// parStrictHead is a request head as an independent strict parser reads it.
type parStrictHead struct {
	method, target string
	fields         map[string]string // by canonical name, each name once
	length         int64             // -1 for chunked
}

// parStrict parses a request head by RFC 9112 with nothing obsolete or
// lenient: CRLF line ends only, no folding, no whitespace before a colon,
// each field once, one framing. It shares no code with Go's parser.
func parStrict(raw string) (*parStrictHead, error) {
	end := strings.Index(raw, "\r\n\r\n")
	if end < 0 {
		return nil, errors.New("no end of head")
	}
	head := raw[:end]
	if strings.ContainsAny(strings.ReplaceAll(head, "\r\n", ""), "\r\n") {
		return nil, errors.New("bare CR or LF")
	}
	lines := strings.Split(head, "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[2] != "HTTP/1.1" || !parToken(parts[0]) || parts[1] == "" {
		return nil, errors.New("request line")
	}
	for i := 0; i < len(parts[1]); i++ {
		if b := parts[1][i]; b <= 0x20 || b >= 0x7f {
			return nil, errors.New("target byte")
		}
	}
	h := &parStrictHead{method: parts[0], target: parts[1], fields: map[string]string{}}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !parToken(name) {
			return nil, errors.New("field name")
		}
		value = strings.Trim(value, " \t")
		for i := 0; i < len(value); i++ {
			if b := value[i]; b != ' ' && b != '\t' && (b < 0x21 || b > 0x7e) {
				return nil, errors.New("field value byte")
			}
		}
		key := http.CanonicalHeaderKey(name)
		if _, dup := h.fields[key]; dup {
			return nil, errors.New("field twice")
		}
		h.fields[key] = value
	}
	if _, ok := h.fields["Host"]; !ok {
		return nil, errors.New("no Host")
	}
	cl, hasCL := h.fields["Content-Length"]
	te, hasTE := h.fields["Transfer-Encoding"]
	switch {
	case hasCL && hasTE:
		return nil, errors.New("two framings")
	case hasTE && !strings.EqualFold(te, "chunked"):
		return nil, errors.New("coding")
	case hasTE:
		h.length = -1
	case hasCL:
		if cl == "" || strings.Trim(cl, "0123456789") != "" {
			return nil, errors.New("length")
		}
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil {
			return nil, err
		}
		h.length = n
	}
	return h, nil
}

func parToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !('a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0) {
			return false
		}
	}
	return true
}

// FuzzParDifferential reads raw requests as the proxy does, through
// wireConn, Go's parser and the proxy's checks, and with an independent strict parser. Whatever the proxy accepts,
// the strict parser must accept and read the same way: method, target, Host,
// every header value, and the body's framing. A request the two read
// differently is one where the proxy decided on something no strict server
// would see.
func FuzzParDifferential(f *testing.F) {
	for _, seed := range []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET /v1/models?a=b HTTP/1.1\r\nHost: example.com:443\r\nX-Note: a\tb\r\n\r\n",
		"POST /v1/messages?beta=true HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
		"POST /v1/messages?beta=true HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"GET /v1/%2e%2e/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\nX-Note : a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: a\r\nx-note: b\r\n\r\n",
		// Go's parser alone accepts each of these, normalized: wireConn
		// refuses them before it reads them.
		"GET / HTTP/1.1\nHost: example.com\n\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\nX-Note: a\r\n b\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
		"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// What Go's parser reads is what wireConn hands it.
		wc := &wireConn{buf: []byte(raw)}
		wc.process()
		if wc.next() != nil || wc.failed != nil {
			return
		}
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(wc.out)))
		if err != nil {
			return
		}
		r.TLS = &tls.ConnectionState{ServerName: "example.com"}
		if _, _, ref := checkRequest(r, "example.com"); ref != nil {
			return
		}
		s, err := parStrict(raw)
		if err != nil {
			t.Fatalf("the proxy accepts what a strict parser refuses (%v): %q", err, raw)
		}
		if s.method != r.Method || s.target != r.RequestURI {
			t.Fatalf("the strict parser reads %s %s, the proxy %s %s", s.method, s.target, r.Method, r.RequestURI)
		}
		if strings.TrimSuffix(s.fields["Host"], ":443") != strings.TrimSuffix(r.Host, ":443") {
			t.Fatalf("the strict parser reads Host %q, the proxy %q", s.fields["Host"], r.Host)
		}
		for name, values := range r.Header {
			if s.fields[name] != values[0] {
				t.Fatalf("the strict parser reads %s %q, the proxy %q", name, s.fields[name], values[0])
			}
		}
		if s.length != r.ContentLength {
			t.Fatalf("the strict parser reads a body of %d, the proxy %d", s.length, r.ContentLength)
		}
	})
}
