package egress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// agentRequest is a request as the agent sends it: the target in origin
// form, as httptest leaves it absolute.
func agentRequest(method, url string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, url, body)
	r.RequestURI = r.URL.RequestURI()
	return r
}

func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, "https://example.com/", nil)
	r.RequestURI = target
	return r
}

// TestCheckRequestRefuses holds the tricks that let requests past other
// proxies: each must be refused before any rule is looked at.
func TestCheckRequestRefuses(t *testing.T) {
	tests := map[string]func() *http.Request{
		"double slash":           func() *http.Request { return request("GET", "/v1//messages") },
		"dot segment":            func() *http.Request { return request("GET", "/v1/./messages") },
		"dot-dot segment":        func() *http.Request { return request("GET", "/v1/messages/../files") },
		"encoded dot-dot":        func() *http.Request { return request("GET", "/v1/%2e%2e/files") },
		"encoded slash":          func() *http.Request { return request("GET", "/v1%2Ffiles") },
		"matrix parameter":       func() *http.Request { return request("GET", "/v1/messages;x=y") },
		"backslash":              func() *http.Request { return request("GET", `/v1\messages`) },
		"fragment":               func() *http.Request { return request("GET", "/v1/messages#x") },
		"absolute form":          func() *http.Request { return request("GET", "https://evil.example/v1/messages") },
		"asterisk form":          func() *http.Request { return request("OPTIONS", "*") },
		"opaque form":            func() *http.Request { return request("GET", "http:http://internal/admin") },
		"non-ASCII":              func() *http.Request { return request("GET", "/v1/m\xc3\xa9ssages") },
		"control byte":           func() *http.Request { return request("GET", "/v1/mess\x01ages") },
		"trailing slash segment": func() *http.Request { return request("GET", "/v1/messages/") },
		"query without value":    func() *http.Request { return request("GET", "/v1?beta") },
		"query semicolon":        func() *http.Request { return request("GET", "/v1?a=b;c=d") },
		"query encoded control":  func() *http.Request { return request("GET", "/v1?a=%00") },
		"query bad escape":       func() *http.Request { return request("GET", "/v1?a=%zz") },
		"host of another name":   func() *http.Request { r := request("GET", "/"); r.Host = "evil.example"; return r },
		"host with trailing dot": func() *http.Request { r := request("GET", "/"); r.Host = "example.com."; return r },
		"host in capitals":       func() *http.Request { r := request("GET", "/"); r.Host = "EXAMPLE.com"; return r },
		"host with another port": func() *http.Request { r := request("GET", "/"); r.Host = "example.com:8443"; return r },
		"duplicate header": func() *http.Request {
			r := request("GET", "/")
			r.Header["Authorization"] = []string{"a", "b"}
			return r
		},
		"underscore in a name":    func() *http.Request { r := request("GET", "/"); r.Header["X_Api_Key"] = []string{"a"}; return r },
		"control byte in a value": func() *http.Request { r := request("GET", "/"); r.Header.Set("X-A", "a\x01b"); return r },
		"upgrade":                 func() *http.Request { r := request("GET", "/"); r.Header.Set("Upgrade", "h2c"); return r },
		"expect":                  func() *http.Request { r := request("POST", "/"); r.Header.Set("Expect", "100-continue"); return r },
		"connection token":        func() *http.Request { r := request("GET", "/"); r.Header.Set("Connection", "X-Api-Key"); return r },
		"gzip transfer encoding": func() *http.Request {
			r := request("POST", "/")
			r.TransferEncoding = []string{"gzip", "chunked"}
			return r
		},
		"body on GET": func() *http.Request { r := request("GET", "/"); r.ContentLength = 5; return r },
		"HTTP/1.0":    func() *http.Request { r := request("GET", "/"); r.ProtoMinor = 0; return r },
		"HTTP/2":      func() *http.Request { r := request("GET", "/"); r.ProtoMajor, r.ProtoMinor = 2, 0; return r },
		"CONNECT":     func() *http.Request { return request("CONNECT", "example.com:443") },
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := checkRequest(build(), "example.com"); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestCheckRequestAccepts(t *testing.T) {
	for _, target := range []string{"/", "/v1/messages?beta=true", "/o/r.git/info/refs?service=git-upload-pack",
		"/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-x@20250929:streamRawPredict",
		"/search/code?q=repo%3Aowner%2Fname&per_page=5"} {
		r := request("POST", target)
		r.Header.Set("Expect", "") // git sends an empty one
		r.Header.Set("Connection", "keep-alive")
		if _, _, err := checkRequest(r, "example.com"); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	r := request("GET", "/")
	r.Host = "example.com:443"
	if _, _, err := checkRequest(r, "example.com"); err != nil {
		t.Errorf("port 443 in Host: %v", err)
	}
}

func TestMatch(t *testing.T) {
	cfg := Config{Rules: []Rule{
		{Method: "POST", Host: "api.example.com", Path: "/v1/messages", Query: "beta=true"},
		{Method: "GET", Host: "api.example.com", Path: "/repos/o/r/*", Query: AnyQuery},
		{Method: "GET", Host: "raw.example.com", Path: "/o/**"},
	}}
	for _, c := range []struct {
		method, host, path, query string
		ok                        bool
	}{
		{"POST", "api.example.com", "/v1/messages", "beta=true", true},
		{"POST", "api.example.com", "/v1/messages", "", false},
		{"POST", "api.example.com", "/v1/messages", "beta=true&x=y", false},
		{"GET", "api.example.com", "/v1/messages", "beta=true", false},
		{"POST", "other.example.com", "/v1/messages", "beta=true", false},
		{"GET", "api.example.com", "/repos/o/r/contents", "ref=main", true},
		{"GET", "api.example.com", "/repos/o/r/contents/file", "", false},
		{"GET", "api.example.com", "/repos/o/r", "", false},
		{"GET", "raw.example.com", "/o/r/main/README.md", "", true},
		{"GET", "raw.example.com", "/o", "", false},
	} {
		_, err := cfg.match(c.method, c.host, c.path, c.query)
		if (err == nil) != c.ok {
			t.Errorf("%s %s%s?%s: matched %v, want %v", c.method, c.host, c.path, c.query, err == nil, c.ok)
		}
	}
	if _, err := (Config{}).match("GET", "api.example.com", "/", ""); err == nil {
		t.Error("an empty config allowed a request")
	}
}

func TestValidateRefuses(t *testing.T) {
	for name, r := range map[string]Rule{
		"unknown method":       {Method: "CONNECT", Host: "a.example.com", Path: "/"},
		"capital host":         {Method: "GET", Host: "A.example.com", Path: "/"},
		"wildcard host":        {Method: "GET", Host: "*.example.com", Path: "/"},
		"address host":         {Method: "GET", Host: "169.254.169.254", Path: "/"},
		"punycode host":        {Method: "GET", Host: "xn--80ak6aa92e.com", Path: "/"},
		"dot-dot path":         {Method: "GET", Host: "a.example.com", Path: "/a/../b"},
		"partial wildcard":     {Method: "GET", Host: "a.example.com", Path: "/a*"},
		"bad query":            {Method: "GET", Host: "a.example.com", Path: "/", Query: "a;b"},
		"hop-by-hop header":    {Method: "GET", Host: "a.example.com", Path: "/", Headers: []string{"Connection"}},
		"non-canonical named":  {Method: "GET", Host: "a.example.com", Path: "/", Headers: []string{"x-api-key"}},
		"credential header":    {Method: "GET", Host: "a.example.com", Path: "/", Headers: []string{"Authorization"}},
		"double star inside":   {Method: "GET", Host: "a.example.com", Path: "/a/**/b"},
		"unknown scheme":       {Method: "GET", Host: "a.example.com", Path: "/", Credential: &Credential{Secret: "s", Header: "Authorization", Scheme: "Digest"}},
		"credential in cookie": {Method: "GET", Host: "a.example.com", Path: "/", Credential: &Credential{Secret: "s", Header: "Cookie"}},
	} {
		if err := (Config{Placeholder: testPlaceholder, Rules: []Rule{r}}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, ph := range []string{"", "short", "Sealroom-Placeholder", "sealroom placeholder"} {
		if err := (Config{Placeholder: ph}).Validate(); err == nil {
			t.Errorf("placeholder %q accepted", ph)
		}
	}
}

func TestDenied(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "fe80::1%eth0"} {
		if !denied(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "140.82.112.3", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if denied(netip.MustParseAddr(s)) {
			t.Errorf("%s denied", s)
		}
	}
	if controlDial("tcp", "1.1.1.1:443", nil) != nil {
		t.Error("a public address on 443 was refused")
	}
	for _, a := range []string{"1.1.1.1:80", "1.1.1.1:22", "169.254.169.254:443", "[::1]:443"} {
		if controlDial("tcp", a, nil) == nil {
			t.Errorf("%s allowed", a)
		}
	}
}

func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	out, ok := dnsAnswer(q, map[string]bool{"api.example.com": true}, netip.MustParseAddr("10.9.8.7"))
	if !ok {
		t.Fatalf("no answer for %s", name)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDNS(t *testing.T) {
	m := dnsQuery(t, "api.example.com.", dnsmessage.TypeA)
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 9, 8, 7} || m.Header.ID != 7 {
		t.Errorf("A for an allowed name: %+v", m)
	}
	if m := dnsQuery(t, "API.Example.com.", dnsmessage.TypeA); len(m.Answers) != 1 {
		t.Error("DNS names are case-insensitive")
	}
	if m := dnsQuery(t, "api.example.com.", dnsmessage.TypeAAAA); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("AAAA for an allowed name: %+v", m)
	}
	for _, name := range []string{"evil.example.", "data.exfiltrated.api.example.com.", "example.com."} {
		if m := dnsQuery(t, name, dnsmessage.TypeA); m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Errorf("%s: %+v", name, m)
		}
	}
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return ca, key
}

func TestCerts(t *testing.T) {
	ca, key := testCA(t)
	c, err := newCerts(ca, key, map[string]bool{"api.example.com": true})
	if err != nil {
		t.Fatal(err)
	}
	var refused []string
	c.refused = func(name string, _ error) { refused = append(refused, name) }
	for _, name := range []string{"", "1.2.3.4", "api.example.com.", "API.example.com", "xn--api.example.com", "evil.example"} {
		if _, err := c.get(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Errorf("%q: minted", name)
		}
	}
	if len(refused) != 6 {
		t.Errorf("refused handshakes told: %v", refused)
	}
	cert, err := c.get(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "api.example.com" || cert.Leaf.IsCA {
		t.Errorf("leaf %v", cert.Leaf.DNSNames)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.example.com"}); err != nil {
		t.Error(err)
	}
	again, _ := c.get(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if again != cert {
		t.Error("the certificate was not reused")
	}
}

// upstream starts a TLS test server speaking HTTP/2 and a proxy whose rule
// host reaches it.
func upstream(t *testing.T, h http.HandlerFunc, rules ...Rule) (*Proxy, *bytes.Buffer) {
	return upstreamHTTP(t, true, h, rules...)
}

const testPlaceholder = "sealroom-placeholder"

func upstreamHTTP(t *testing.T, http2 bool, h http.HandlerFunc, rules ...Rule) (*Proxy, *bytes.Buffer) {
	return upstreamWith(t, http2, Secrets{}, h, rules...)
}

func upstreamWith(t *testing.T, http2 bool, secrets Secrets, h http.HandlerFunc, rules ...Rule) (*Proxy, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	var log bytes.Buffer
	p, err := newProxy(Config{Placeholder: testPlaceholder, Rules: rules}, secrets, &log, options{
		roots: roots,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, &log
}

func TestForward(t *testing.T) {
	var got *http.Request
	// HTTP/1.1 upstream: HTTP/2 has no Connection header to name others.
	p, log := upstreamWith(t, false, Secrets{Values: map[string]string{"key": "real-secret-1234"}}, func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "tracker=1")
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.Header().Set("Connection", "X-Hidden")
		w.Header().Set("X-Hidden", "1")
		w.Header().Set("Retry-After", "3")
		io.WriteString(w, "answer")
	}, Rule{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: "beta=true", Headers: []string{"Content-Type"},
		Credential: &Credential{Secret: "key", Header: "X-Api-Key"}})

	r := agentRequest("POST", "https://example.com/v1/messages?beta=true", strings.NewReader(`{"a":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Api-Key", testPlaceholder)
	r.Header.Set("X-Secret-Extra", "must-not-pass")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != 200 || w.Body.String() != "answer" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if got.URL.Path != "/v1/messages" || got.URL.RawQuery != "beta=true" || got.Host != "example.com" {
		t.Errorf("upstream got %s %s", got.Host, got.URL)
	}
	if got.Header.Get("X-Secret-Extra") != "" || got.Header.Get("X-Api-Key") != "real-secret-1234" {
		t.Errorf("upstream headers %v", got.Header)
	}
	for _, h := range []string{"Set-Cookie", "Alt-Svc", "X-Hidden", "Connection"} {
		if w.Header().Get(h) != "" {
			t.Errorf("%s reached the agent", h)
		}
	}
	if w.Header().Get("Retry-After") != "3" {
		t.Error("Retry-After did not reach the agent")
	}
	if strings.Contains(log.String(), "must-not-pass") || strings.Contains(log.String(), "real-secret-1234") || strings.Contains(log.String(), testPlaceholder) {
		t.Errorf("a header value reached the log: %s", log)
	}
	if !strings.Contains(log.String(), `"decision":"allowed"`) {
		t.Errorf("no audit line: %s", log)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	hits := 0
	p, _ := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}, Rule{Method: "GET", Host: "example.com", Path: "/r"})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, agentRequest("GET", "https://example.com/r", nil))
	if w.Code != http.StatusFound || hits != 1 || w.Header().Get("Location") != "https://evil.example/steal" {
		t.Errorf("got %d after %d upstream calls", w.Code, hits)
	}
}

func TestRefusals(t *testing.T) {
	p, log := upstream(t, func(w http.ResponseWriter, r *http.Request) { t.Error("a refused request reached upstream") },
		Rule{Method: "POST", Host: "example.com", Path: "/ok"})
	for _, c := range []struct {
		method, target string
		body           string
		length         int64
		status         int
		reason         string
	}{
		{"GET", "/ok", "", 0, 403, reasonNoRule},
		{"POST", "/other", "", 0, 403, reasonNoRule},
		{"POST", "/ok/../x", "", 0, 403, reasonPath},
		{"POST", "/ok", "x", MaxBodyBytes + 1, 413, reasonTooLarge},
	} {
		r := httptest.NewRequest(c.method, "https://example.com/", strings.NewReader(c.body))
		r.RequestURI = c.target
		if c.length != 0 {
			r.ContentLength = c.length
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != c.status || !strings.Contains(w.Body.String(), c.reason) {
			t.Errorf("%s %s: %d %q", c.method, c.target, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), c.target) && c.target != "/ok" {
			t.Errorf("the refusal echoed the request: %q", w.Body.String())
		}
	}
	if strings.Count(log.String(), `"decision":"refused"`) != 4 {
		t.Errorf("audit log:\n%s", log)
	}
}

func TestStreams(t *testing.T) {
	release := make(chan struct{})
	p, _ := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: ping\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "event: done\n\n")
	}, Rule{Method: "GET", Host: "example.com", Path: "/stream"})

	pr, pw := io.Pipe()
	w := &flushRecorder{header: http.Header{}, w: pw}
	go func() {
		p.ServeHTTP(w, agentRequest("GET", "https://example.com/stream", nil))
		pw.Close()
	}()
	buf := make([]byte, 64)
	n, _ := io.ReadAtLeast(pr, buf, len("event: ping\n\n"))
	if string(buf[:n]) != "event: ping\n\n" {
		t.Fatalf("first event %q", buf[:n])
	}
	close(release) // the first event arrived before the upstream finished
	rest, _ := io.ReadAll(pr)
	if string(rest) != "event: done\n\n" {
		t.Errorf("rest %q", rest)
	}
}

type flushRecorder struct {
	header http.Header
	w      io.Writer
}

func (f *flushRecorder) Header() http.Header         { return f.header }
func (f *flushRecorder) Write(b []byte) (int, error) { return f.w.Write(b) }
func (f *flushRecorder) WriteHeader(int)             {}
func (f *flushRecorder) Flush()                      {}

// TestServe runs the whole proxy on real sockets: DNS, a certificate for an
// allowed name only, and HTTP/1.1 only.
func TestServe(t *testing.T) {
	p, log := upstream(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") },
		Rule{Method: "GET", Host: "example.com", Path: "/"})
	ca, key := testCA(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close(); ln.Close() })
	go p.Serve(udp, ln, ca, key, netip.MustParseAddr("10.9.8.7"))

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	dial := func(name string, alpn ...string) (*tls.Conn, error) {
		return tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: name, RootCAs: roots, NextProtos: alpn})
	}
	if _, err := dial("evil.example"); err == nil {
		t.Error("a handshake for a name no rule allows succeeded")
	}
	conn, err := dial("example.com", "h2", "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if proto := conn.ConnectionState().NegotiatedProtocol; proto == "h2" {
		t.Error("HTTP/2 was negotiated")
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	if !bytes.HasPrefix(resp, []byte("HTTP/1.1 200")) || !bytes.HasSuffix(resp, []byte("ok")) {
		t.Errorf("response %q", resp)
	}
	if !strings.Contains(log.String(), `"reason":"tls-server-name"`) || !strings.Contains(log.String(), `"host":"evil.example"`) {
		t.Errorf("the refused handshake was not logged: %s", log)
	}
}
