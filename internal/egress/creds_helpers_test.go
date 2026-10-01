package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The tests in creds_*_test.go are the credential and exfiltration part of
// the regression table of docs/proxy.md: each case is a hostile request
// from a malicious plugin, the outcome the proxy must reach, and what the
// upstream must or must not receive. docs/proxy-tests/credentials.md lists
// them by ID, with their sources.

// creForwarded is the outcome of a request the proxy must carry.
const creForwarded = "forwarded"

// creSecret is the user's Claude credential in these tests, and
// creGitHubSecret their GitHub token.
const (
	creSecret       = "sk-ant-oat01-user-0123456789"
	creGitHubSecret = "ghp_userTokenAbcdef0123456789"
)

// creCase is one hostile request. limit, when set, marks a channel the
// proxy cannot close, and says why: the case pins what happens today.
type creCase struct {
	name  string
	req   func(t *testing.T) *http.Request
	want  string // a refusal reason, or creForwarded
	limit string
	check func(t *testing.T, seen *creSeen)
}

// creSeen is what the upstream received.
type creSeen struct {
	mu     sync.Mutex
	hits   int
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

func (s *creSeen) record(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	s.method, s.path, s.query, s.header, s.body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), b
	io.WriteString(w, "ok")
}

// creProxy starts an upstream recording what it receives, and a proxy with
// rules reaching it.
func creProxy(t *testing.T, secrets Secrets, rules ...Rule) (*Proxy, *creSeen) {
	t.Helper()
	seen := &creSeen{}
	p, _ := upstreamWith(t, true, secrets, seen.record, rules...)
	return p, seen
}

// creRun sends a case's request through a proxy of its own and checks the
// outcome.
func creRun(t *testing.T, c creCase, secrets Secrets, rules ...Rule) {
	t.Helper()
	p, seen := creProxy(t, secrets, rules...)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, c.req(t))
	creVerdict(t, w, seen, c.want)
	if c.check != nil {
		c.check(t, seen)
	}
	if c.limit != "" {
		t.Logf("documented limit: %s", c.limit)
	}
}

// creVerdict checks a proxy's answer and what reached the upstream.
func creVerdict(t *testing.T, w *httptest.ResponseRecorder, seen *creSeen, want string) {
	t.Helper()
	seen.mu.Lock()
	hits := seen.hits
	seen.mu.Unlock()
	if want == creForwarded {
		if w.Code != http.StatusOK || hits != 1 {
			t.Errorf("want forwarded, got %d %q with %d upstream requests", w.Code, w.Body.String(), hits)
		}
		return
	}
	if hits != 0 {
		t.Errorf("a request to refuse (%s) reached the upstream", want)
	}
	if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "refused ("+want+")") {
		t.Errorf("want refused (%s), got %d %q", want, w.Code, w.Body.String())
	}
}

// creRaw reads a request as the proxy's server reads it, through Go's HTTP
// parser, received on a TLS connection for host.
func creRaw(t *testing.T, host, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("Go's parser refused the request, so the proxy never sees it: %v", err)
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, ServerName: host}
	r.RemoteAddr = "10.0.0.3:40000"
	return r
}

// creWith returns a request builder: an agent's request, then set applied.
func creWith(method, url, body string, set func(r *http.Request)) func(t *testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		var b io.Reader
		if body != "" {
			b = strings.NewReader(body)
		}
		r := agentRequest(method, url, b)
		if set != nil {
			set(r)
		}
		return r
	}
}

// creTarget is a request whose raw target is set as is, beyond what
// net/url would build.
func creTarget(method, host, target string, set func(r *http.Request)) func(t *testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := agentRequest(method, "https://"+host+"/", nil)
		r.RequestURI = target
		if set != nil {
			set(r)
		}
		return r
	}
}

// creHeader sets one header.
func creHeader(name, value string) func(r *http.Request) {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// creNoHeader checks that the upstream received none of names.
func creNoHeader(names ...string) func(t *testing.T, seen *creSeen) {
	return func(t *testing.T, seen *creSeen) {
		for _, n := range names {
			if v := seen.header.Get(n); v != "" {
				t.Errorf("the upstream received %s: %q", n, v)
			}
		}
	}
}

// creHeaderIs checks the one value the upstream received in a header.
func creHeaderIs(name, want string) func(t *testing.T, seen *creSeen) {
	return func(t *testing.T, seen *creSeen) {
		if got := seen.header.Values(name); len(got) != 1 || got[0] != want {
			t.Errorf("the upstream received %s %q, want %q", name, got, want)
		}
	}
}

// creServeRaw sends a request read by Go's parser through the proxy, as
// received on a TLS connection for example.com.
func creServeRaw(p *Proxy, r *http.Request) *httptest.ResponseRecorder {
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, ServerName: "example.com"}
	r.RemoteAddr = "10.0.0.3:40000"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

// creBody is a request body.
func creBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
