package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Response-side desync: the upstream answers with framing that conflicts,
// lies, or carries more than one answer. The proxy reads it with Go's client
// and frames its own answer to the agent, so the agent never reads anything
// but one well-framed answer per request, and never another request's
// answer.

// parByPath answers each request by its path: the first answer whose key
// starts the request line.
func parByPath(answers map[string]string) func(int, parReq) string {
	return func(_ int, r parReq) string {
		line, _, _ := strings.Cut(r.Head, "\r\n")
		for prefix, a := range answers {
			if strings.HasPrefix(line, prefix+" ") {
				return a
			}
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
	}
}

const parSecond = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"

func TestParResponses(t *testing.T) {
	type rc struct {
		name   string
		answer string // the upstream's raw answer to GET /
		status int
		body   string
		// absent are headers that must not reach the agent.
		absent []string
		// present are headers that must reach the agent, with their value.
		present map[string]string
		// rawAbsent are bytes the agent must never read.
		rawAbsent []string
	}
	cases := []rc{
		{name: "Content-Length and chunked: read as chunked, framed once",
			answer: "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			status: 200, body: "hello", rawAbsent: []string{"Content-Length: 3"}},
		{name: "two different Content-Lengths",
			answer: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
			status: 502, body: parRefused(reasonUpstream)},
		{name: "Content-Length list",
			answer: "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok",
			status: 502, body: parRefused(reasonUpstream)},
		{name: "unknown coding",
			answer: "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
			status: 502, body: parRefused(reasonUpstream), rawAbsent: []string{"gzip"}},
		{name: "an interim 100 Continue is not passed on",
			answer: "HTTP/1.1 100 Continue\r\n\r\n" + parOK(0, parReq{}),
			status: 200, body: "ok", rawAbsent: []string{"100 Continue"}},
		{name: "103 Early Hints are not passed on",
			answer: "HTTP/1.1 103 Early Hints\r\nLink: <https://evil.example/x>; rel=preload\r\n\r\n" + parOK(0, parReq{}),
			status: 200, body: "ok", rawAbsent: []string{"103", "evil.example"}},
		{name: "hop-by-hop headers are dropped",
			answer: "HTTP/1.1 200 OK\r\nConnection: X-Named\r\nX-Named: 1\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nProxy-Connection: keep-alive\r\nUpgrade: h2c\r\nTe: trailers\r\nTrailer: X-T\r\nX-Kept: 1\r\nContent-Length: 2\r\n\r\nok",
			status: 200, body: "ok", absent: []string{"X-Named", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection", "Upgrade", "Te", "Trailer"},
			present: map[string]string{"X-Kept": "1"}},
		{name: "Set-Cookie and Alt-Svc are dropped, in any case",
			answer: "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nALT-SVC: h3=\":443\"\r\nContent-Length: 2\r\n\r\nok",
			status: 200, body: "ok", absent: []string{"Set-Cookie", "Alt-Svc"}, rawAbsent: []string{"a=1", "b=2", "h3="}},
		{name: "trailers are never copied",
			answer: "HTTP/1.1 200 OK\r\nTrailer: X-T\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: secret-trailer\r\n\r\n",
			status: 200, body: "ok", rawAbsent: []string{"secret-trailer", "X-T"}},
		{name: "a folded header is not passed on folded",
			answer: "HTTP/1.1 200 OK\r\nX-A: a\r\n Set-Cookie: x=1\r\nContent-Length: 2\r\n\r\nok",
			status: 200, body: "ok", rawAbsent: []string{"\r\n Set-Cookie", "\r\nSet-Cookie"}},
		{name: "a bare CR in a header is refused",
			answer: "HTTP/1.1 200 OK\r\nX-A: a\rSet-Cookie: x=1\r\nContent-Length: 2\r\n\r\nok",
			status: 502, body: parRefused(reasonUpstream), rawAbsent: []string{"x=1"}},
		{name: "an answer framed by closing is framed again",
			answer: "HTTP/1.0 200 OK\r\n\r\nok",
			status: 200, body: "ok"},
		{name: "bytes past Content-Length are dropped",
			answer: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil",
			status: 200, body: "ok", rawAbsent: []string{"evil"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := parProxy(t, func(n int, r parReq) string {
				if n == 0 {
					return c.answer
				}
				return parSecond
			})
			ex := e.parSend(t, "example.com", parReq1("GET", "/"), 1)
			got := ex.Resps[0]
			if got.Status != c.status || got.Body != c.body {
				t.Errorf("the agent read %v, want %d %q", got, c.status, c.body)
			}
			for _, h := range c.absent {
				if v := got.Header.Values(h); len(v) > 0 {
					t.Errorf("%s reached the agent: %q", h, v)
				}
			}
			for h, v := range c.present {
				if got.Header.Get(h) != v {
					t.Errorf("%s: %q, want %q", h, got.Header.Get(h), v)
				}
			}
			for _, b := range c.rawAbsent {
				if strings.Contains(ex.Raw, b) {
					t.Errorf("the agent read %q in %q", b, ex.Raw)
				}
			}
			if got.Header.Get("Content-Length") != "" && len(got.Header.Values("Transfer-Encoding")) > 0 {
				t.Errorf("the agent's answer has two framings: %v", got.Header)
			}
			if len(ex.Extra) > 0 {
				t.Errorf("extra answers: %v", ex.Extra)
			}
			// A well-framed answer leaves the connection usable, and an
			// upstream error closes it; either way the agent never reads
			// another answer than its own.
			if got.Status == 200 && got.Body == c.body && c.body != "" && !ex.SentinelAnswered {
				t.Errorf("the connection did not read a next request")
			}
		})
	}
}

// TestParResponseQueuePoisoning: an upstream that answers one request with
// two answers, or a HEAD or 204 with a body, must not have the extra bytes
// read as the answer to the agent's next request.
func TestParResponseQueuePoisoning(t *testing.T) {
	evil := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil"
	for name, c := range map[string]struct {
		first  string // the agent's first request
		answer string // the upstream's raw answer to it
		head   bool
	}{
		"two answers to one request":  {parReq1("GET", "/"), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" + evil, false},
		"a body on an answer to HEAD": {parReq1("HEAD", "/"), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" + evil, true},
		"a body on a 204":             {parReq1("GET", "/"), "HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\nok" + evil, false},
		"a body on a 304":             {parReq1("GET", "/"), "HTTP/1.1 304 Not Modified\r\n\r\n" + evil, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := parProxy(t, parByPath(map[string]string{"GET /": c.answer, "HEAD /": c.answer}))
			// Several rounds: the extra bytes and the next request race on
			// the proxy's upstream connection.
			for round := 0; round < 10; round++ {
				heads := []string{""}
				if c.head {
					heads[0] = "HEAD"
				}
				ex := e.parSend(t, "example.com", c.first+parReq1("GET", "/v1/models"), 2, heads...)
				if got := ex.Resps[1]; got.Body != "second" {
					t.Fatalf("round %d: the second request read %v, want the upstream's own answer to it", round, got)
				}
				if strings.Contains(ex.Raw, "evil") {
					t.Fatalf("round %d: the agent read the extra answer: %q", round, ex.Raw)
				}
			}
		})
	}
}

// TestParResponseSwitchingProtocols: an upstream answering 101 to a request
// that asked for no upgrade never switches the agent's connection to raw
// bytes: the next request on it is still read and checked.
func TestParResponseSwitchingProtocols(t *testing.T) {
	e := parProxy(t, parByPath(map[string]string{
		"GET /": "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nRAW-TUNNEL-BYTES",
	}))
	c := e.parDial(t, "example.com")
	io.WriteString(c, parReq1("GET", "/")+parReq1("GET", "/v1/../x"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, _ := io.ReadAll(c)
	s := string(raw)
	if strings.Contains(s, "RAW-TUNNEL-BYTES") || strings.Contains(s, "Upgrade: websocket") {
		t.Errorf("the upstream's tunnel reached the agent: %q", s)
	}
	// The 101 status itself must not reach the agent, as a final answer
	// to a GET that asked for no upgrade: a client would take its
	// connection as switched while the proxy still reads HTTP on it.
	if strings.Contains(s, " 101 ") {
		t.Errorf("the agent read a 101 answer: %q", s)
	}
	if !strings.Contains(s, parRefused(reasonPath)) && !strings.Contains(s, parRefused(reasonUpstream)) {
		t.Errorf("the request after the 101 was not checked: %q", s)
	}
	for _, r := range e.up.requests() {
		if strings.Contains(r.Head, "/x ") {
			t.Errorf("the upstream received %q", r.Head)
		}
	}
}

// TestParResponseShortBody: an upstream that declares more than it sends
// leaves the agent with a cut answer and a closed connection, never with
// the next answer read as the rest of this one.
func TestParResponseShortBody(t *testing.T) {
	e := parProxy(t, func(n int, r parReq) string {
		if n == 0 {
			return "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello"
		}
		return parSecond
	})
	c := e.parDial(t, "example.com")
	io.WriteString(c, parReq1("GET", "/")+parReq1("GET", "/v1/models"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err == nil || string(body) != "hello" {
		t.Errorf("body %q, err %v: want the 5 bytes sent and an unexpected end", body, err)
	}
	rest, _ := io.ReadAll(br)
	if len(rest) > 0 {
		t.Errorf("the agent read more after a cut answer: %q", rest)
	}
}

// TestParHTTP2Upstream: over HTTP/2 to the upstream, the method, path, query,
// authority and headers are the checked bytes, and the body is the same.
func TestParHTTP2Upstream(t *testing.T) {
	type seen struct {
		proto, method, uri, host string
		header                   http.Header
		body                     string
	}
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, seen{r.Proto, r.Method, r.RequestURI, r.Host, r.Header.Clone(), string(b)})
		mu.Unlock()
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	log := &parLog{}
	p, err := newProxy(Config{Placeholder: testPlaceholder, Rules: parRules()}, Secrets{Values: map[string]string{"key": parSecret}}, log, options{
		roots: roots,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, key := testCA(t)
	udp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { udp.Close(); ln.Close() })
	go p.Serve(udp, ln, ca, key, netip.MustParseAddr("10.9.8.7"))
	agentRoots := parPool(ca)
	e := &parEnv{addr: ln.Addr().String(), roots: agentRoots, log: log}

	ex := e.parSend(t, "example.com",
		parReq1("GET", "/repos/o/r/a:b@c~d?q=a%2Fb&x=", "X-Note: n", "Accept: x")+
			parPost+"Content-Type: a/b\r\nX-Note: n\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"+
			parReq1("GET", "/auth", "Authorization: Bearer "+testPlaceholder, "X-Note: n"), 3)
	for _, r := range ex.Resps {
		if r.Status != 200 {
			t.Fatalf("answers %v", ex.Resps)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []seen{
		{"HTTP/2.0", "GET", "/repos/o/r/a:b@c~d?q=a%2Fb&x=", "example.com", http.Header{"User-Agent": {"Go-http-client/2.0"}}, ""},
		{"HTTP/2.0", "POST", "/v1/messages?beta=true", "example.com", http.Header{"User-Agent": {"Go-http-client/2.0"}, "Content-Type": {"a/b"}, "X-Note": {"n"}}, "hello"},
		{"HTTP/2.0", "GET", "/auth", "example.com", http.Header{"User-Agent": {"Go-http-client/2.0"}, "Authorization": {"Bearer " + parSecret}, "X-Note": {"n"}}, ""},
	}
	if len(got) != len(want) {
		t.Fatalf("the upstream received %d requests, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.proto != w.proto || g.method != w.method || g.uri != w.uri || g.host != w.host || g.body != w.body {
			t.Errorf("request %d: %s %s %s %s body %q, want %s %s %s %s body %q", i+1, g.proto, g.method, g.uri, g.host, g.body, w.proto, w.method, w.uri, w.host, w.body)
		}
		if !parSameHeader(g.header, w.header) {
			t.Errorf("request %d: headers %v, want %v", i+1, g.header, w.header)
		}
	}
}

func parSameHeader(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(v, "\x00") != strings.Join(b[k], "\x00") {
			return false
		}
	}
	return true
}

// TestParResponseCutBody: an upstream answer whose body breaks off, by
// malformed chunking or a closed connection, must reach the agent as broken
// too, never as a whole answer that is shorter.
func TestParResponseCutBody(t *testing.T) {
	for name, answer := range map[string]string{
		"malformed chunk":             "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3\nabc\r\n0\r\n\r\n",
		"connection closed mid-body":  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n",
		"chunk longer than announced": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX\r\n0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := parProxy(t, func(int, parReq) string { return answer })
			c := e.parDial(t, "example.com")
			io.WriteString(c, parReq1("GET", "/"))
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			// The proxy must not end its chunked answer cleanly when the
			// upstream's body fails, or the agent reads a whole, shorter
			// answer.
			if err == nil {
				t.Errorf("the agent read a whole answer %d %q from a broken upstream body", resp.StatusCode, body)
			}
		})
	}
}
