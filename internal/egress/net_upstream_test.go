package egress

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNetUpstreamCertificates: the proxy reaches an upstream only over TLS
// it verified: for the rule's host, current, from a trusted root, for
// server authentication. There is no fallback.
func TestNetUpstreamCertificates(t *testing.T) {
	ca := netNewCA(t)
	other := netNewCA(t)
	constrained := func() *netCA {
		c := netNewCA(t)
		tmpl := *c.cert
		tmpl.PermittedDNSDomains = []string{"elsewhere.example"}
		tmpl.PermittedDNSDomainsCritical = true
		der, err := x509.CreateCertificate(nil, &tmpl, &tmpl, &c.key.PublicKey, c.key)
		if err != nil {
			t.Fatal(err)
		}
		c.cert, _ = x509.ParseCertificate(der)
		c.pool = x509.NewCertPool()
		c.pool.AddCert(c.cert)
		return c
	}()
	selfSigned := func() tls.Certificate {
		c := netNewCA(t)
		return tls.Certificate{Certificate: [][]byte{c.cert.Raw}, PrivateKey: c.key}
	}()
	for _, c := range []struct {
		name   string
		cert   tls.Certificate
		roots  *x509.CertPool
		maxTLS uint16
		ok     bool
	}{
		{"valid", ca.netLeaf(t, nil, netHost), ca.pool, 0, true},
		{"wildcard for the host", ca.netLeaf(t, nil, "*.example.com"), ca.pool, 0, true},
		{"for another name", ca.netLeaf(t, nil, "evil.example"), ca.pool, 0, false},
		{"for a parent name", ca.netLeaf(t, nil, "example.com"), ca.pool, 0, false},
		{"wildcard two levels up", ca.netLeaf(t, nil, "*.com"), ca.pool, 0, false},
		{"common name only", ca.netLeaf(t, func(c *x509.Certificate) { c.DNSNames = nil }, netHost), ca.pool, 0, false},
		{"address only", ca.netLeaf(t, func(c *x509.Certificate) { c.DNSNames = nil; c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} }, "127.0.0.1"), ca.pool, 0, false},
		{"expired", ca.netLeaf(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, netHost), ca.pool, 0, false},
		{"not yet valid", ca.netLeaf(t, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, netHost), ca.pool, 0, false},
		{"client authentication only", ca.netLeaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, netHost), ca.pool, 0, false},
		{"code signing only", ca.netLeaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} }, netHost), ca.pool, 0, false},
		{"from an untrusted CA", other.netLeaf(t, nil, netHost), ca.pool, 0, false},
		{"self-signed", selfSigned, ca.pool, 0, false},
		{"outside the CA's name constraints", constrained.netLeaf(t, nil, netHost), constrained.pool, 0, false},
		{"system roots only", ca.netLeaf(t, nil, netHost), nil, 0, false},
		{"TLS 1.1 at most", ca.netLeaf(t, nil, netHost), ca.pool, tls.VersionTLS11, false},
		{"TLS 1.2 at most", ca.netLeaf(t, nil, netHost), ca.pool, tls.VersionTLS12, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var hits atomic.Int32
			var sni atomic.Value
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				io.WriteString(w, "ok")
			}))
			srv.TLS = &tls.Config{
				MaxVersion: c.maxTLS,
				GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					sni.Store(h.ServerName)
					return &c.cert, nil
				},
			}
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.StartTLS()
			defer srv.Close()
			rig := netProxy(t, c.roots, srv.Listener.Addr().String(), Secrets{}, netGet("/x"))
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
			if c.ok != (w.Code == 200) {
				t.Errorf("got %d %q, want success %v", w.Code, w.Body.String(), c.ok)
			}
			if !c.ok && (hits.Load() != 0 || w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), reasonUpstream)) {
				t.Errorf("got %d %q after %d upstream requests", w.Code, w.Body.String(), hits.Load())
			}
			// With TLS 1.1 the handshake fails on the version, before the name.
			if s, ok := sni.Load().(string); (ok || c.maxTLS == 0) && s != netHost {
				t.Errorf("the proxy sent the server name %q", s)
			}
		})
	}
}

// TestNetUpstreamRedirects: a redirect, to anywhere, reaches the agent as
// it is and is never followed, with or without a body. Sources:
// CVE-2023-45289, CVE-2024-45336 (credentials on redirects in Go).
func TestNetUpstreamRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, loc := range []string{
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"https://evil.example/steal", "//evil.example/x", "/x?again=1",
			"https://" + netHost + "@evil.example/", "http://[::1]:443/",
		} {
			t.Run(fmt.Sprintf("%d %s", status, loc), func(t *testing.T) {
				var hits atomic.Int32
				rig := netHTTPRig(t, true, func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					w.Header().Set("Location", loc)
					w.WriteHeader(status)
				}, Rule{Method: "POST", Host: netHost, Path: "/x", Query: AnyQuery})
				r := agentRequest("POST", "https://"+netHost+"/x", strings.NewReader("data"))
				w := httptest.NewRecorder()
				rig.p.ServeHTTP(w, r)
				if w.Code != status || w.Header().Get("Location") != loc || hits.Load() != 1 {
					t.Errorf("got %d to %q after %d upstream requests", w.Code, w.Header().Get("Location"), hits.Load())
				}
				if d := rig.netDials(); len(d) != 1 {
					t.Errorf("dials %v", d)
				}
			})
		}
	}
}

// TestNetUpstreamSwitchingProtocols: an upstream answers 101 to a request
// that asked for no upgrade. The agent must never get a 101, nor any byte
// the upstream sends after it: no tunnel, no WebSocket, ever.
func TestNetUpstreamSwitchingProtocols(t *testing.T) {
	for name, raw := range map[string]string{
		"with Upgrade":    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nTUNNELED",
		"without Upgrade": "HTTP/1.1 101 Switching Protocols\r\n\r\nTUNNELED",
	} {
		t.Run(name, func(t *testing.T) {
			rig := netRawRig(t, netRawReply(raw), netGet("/x"))
			agent := netServe(t, rig.p)
			c, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
			got, _ := io.ReadAll(io.LimitReader(c, 4096))
			if bytes.HasPrefix(got, []byte("HTTP/1.1 101")) || bytes.Contains(got, []byte("TUNNELED")) {
				t.Errorf("the agent got %q", got)
			}
		})
	}
}

// TestNetUpstreamInformational: 1xx responses an upstream sends before its
// answer never reach the agent, and a flood of them ends. Source: RFC 8297
// (103 Early Hints), golang/go issue 65035.
func TestNetUpstreamInformational(t *testing.T) {
	for _, c := range []struct {
		name string
		pre  string
		n    int
	}{
		{"103 Early Hints", "HTTP/1.1 103 Early Hints\r\nLink: <https://evil.example/x>; rel=preload\r\nX-Hint: leak\r\n\r\n", 1},
		{"100 Continue unasked", "HTTP/1.1 100 Continue\r\nX-Hint: leak\r\n\r\n", 1},
		{"102 Processing", "HTTP/1.1 102 Processing\r\nX-Hint: leak\r\n\r\n", 1},
		{"a flood of 103", "HTTP/1.1 103 Early Hints\r\nX-Hint: leak\r\n\r\n", 5000},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := strings.Repeat(c.pre, c.n) + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
			rig := netRawRig(t, netRawReply(raw), netGet("/x"))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil).WithContext(ctx))
			if w.Code != 200 && w.Code != http.StatusBadGateway {
				t.Errorf("got %d", w.Code)
			}
			if w.Header().Get("Link") != "" || w.Header().Get("X-Hint") != "" {
				t.Errorf("a 1xx header reached the agent: %v", w.Header())
			}
		})
	}
}

// TestNetUpstreamResponseHeaders: hop-by-hop headers, headers named in
// Connection, Set-Cookie and Alt-Svc never reach the agent; the others do.
// Sources: CVE-2021-33197 (Go's ReverseProxy and Connection), RFC 9110
// section 7.6.1.
func TestNetUpstreamResponseHeaders(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"ETag: \"v1\"\r\n" +
		"Retry-After: 3\r\n" +
		"X-Request-Id: abc\r\n" +
		"Connection: keep-alive,  x-listed-a , X-LISTED-B,,x-listed-c\r\n" +
		"Connection: x-listed-d\r\n" +
		"X-Listed-A: 1\r\nX-Listed-B: 1\r\nX-Listed-C: 1\r\nX-Listed-D: 1\r\n" +
		"Keep-Alive: timeout=600\r\n" +
		"Proxy-Authenticate: Basic realm=\"x\"\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Te: trailers\r\n" +
		"Trailer: X-Trailer\r\n" +
		"Upgrade: websocket\r\n" +
		"set-cookie: session=attacker; Domain=example.com\r\n" +
		"Set-Cookie: second=1\r\n" +
		"alt-svc: h3=\":443\"; ma=86400\r\n" +
		"Content-Length: 2\r\n\r\nok"
	rig := netRawRig(t, netRawReply(raw), netGet("/x"))
	w := httptest.NewRecorder()
	rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	for _, h := range []string{"Connection", "X-Listed-A", "X-Listed-B", "X-Listed-C", "X-Listed-D", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Connection", "Te", "Trailer", "Upgrade", "Set-Cookie", "Alt-Svc", "Transfer-Encoding"} {
		t.Run("drops "+h, func(t *testing.T) {
			if v, ok := w.Header()[h]; ok {
				t.Errorf("%s: %q reached the agent", h, v)
			}
		})
	}
	for h, v := range map[string]string{"Content-Type": "text/plain", "Etag": `"v1"`, "Retry-After": "3", "X-Request-Id": "abc"} {
		t.Run("keeps "+h, func(t *testing.T) {
			if w.Header().Get(h) != v {
				t.Errorf("%s: %q", h, w.Header().Get(h))
			}
		})
	}
}

// TestNetUpstreamHTTP2Headers: the same over HTTP/2, where Alt-Svc and
// cookies come as HPACK fields.
func TestNetUpstreamHTTP2Headers(t *testing.T) {
	rig := netHTTPRig(t, true, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream spoke %s", r.Proto)
		}
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Set("X-Kept", "1")
		w.Header().Set("Trailer", "X-Trailer")
		io.WriteString(w, "ok")
		w.Header().Set("X-Trailer", "late")
	}, netGet("/x"))
	w := httptest.NewRecorder()
	rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
	if w.Code != 200 || w.Header().Get("X-Kept") != "1" {
		t.Fatalf("got %d %v", w.Code, w.Header())
	}
	for _, h := range []string{"Alt-Svc", "Set-Cookie", "Trailer", "X-Trailer"} {
		if _, ok := w.Header()[h]; ok {
			t.Errorf("%s reached the agent", h)
		}
	}
	if len(w.Result().Trailer) != 0 {
		t.Errorf("trailers reached the agent: %v", w.Result().Trailer)
	}
}

// TestNetUpstreamHeaderSize: an upstream answering with huge headers, or a
// great many, must not have the proxy hold them all for the agent. The
// proxy bounds the agent's headers to 64 KiB; the upstream's are bounded
// only by Go's 10 MiB default, per connection, of up to 256.
func TestNetUpstreamHeaderSize(t *testing.T) {
	for name, headers := range map[string]string{
		"one header of 1 MiB": "X-Big: " + strings.Repeat("a", 1<<20) + "\r\n",
		"20000 headers":       strings.Repeat("X-Many: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 20000),
	} {
		t.Run(name, func(t *testing.T) {
			rig := netRawRig(t, netRawReply("HTTP/1.1 200 OK\r\n"+headers+"Content-Length: 2\r\n\r\nok"), netGet("/x"))
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
			size := 0
			for k, vs := range w.Header() {
				for _, v := range vs {
					size += len(k) + len(v)
				}
			}
			if w.Code != http.StatusBadGateway {
				t.Errorf("got %d with %d bytes of upstream headers passed to the agent, want 502", w.Code, size)
			}
		})
	}
}

// TestNetUpstreamMalformed: a response Go's client cannot read as one
// unambiguous message is a 502, and never reaches the agent half-read.
// Sources: RFC 9112 section 6.3, request smuggling research (Kettle,
// "HTTP/1.1 must die", 2025).
func TestNetUpstreamMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"two different lengths":      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nokk",
		"a negative length":          "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nok",
		"a length that is no number": "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nok",
		"an unknown encoding":        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nok",
		"no status line":             "ok\r\n\r\n",
		"HTTP/2 status line":         "HTTP/2 200\r\nContent-Length: 2\r\n\r\nok",
		"a status of 1000":           "HTTP/1.1 1000 OK\r\nContent-Length: 2\r\n\r\nok",
		"a NUL in a value":           "HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 2\r\n\r\nok",
		"a bare CR in a value":       "HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 2\r\n\r\nok",
		"nothing at all":             "",
	} {
		t.Run(name, func(t *testing.T) {
			rig := netRawRig(t, netRawReply(raw), netGet("/x"))
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
			if w.Code != http.StatusBadGateway {
				t.Errorf("got %d %v %q", w.Code, w.Header(), w.Body.String())
			}
		})
	}
	// RFC 9112 section 5.1: a proxy must remove whitespace between a field
	// name and its colon. Go's client keeps "Content-Length " as a name of
	// its own; Go's server drops such a name on write. Either way the agent
	// must never see it, nor read a length that conflicts with the framing.
	t.Run("whitespace before a colon", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Length : 100\r\nX-A : 1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
		rig := netRawRig(t, netRawReply(raw), netGet("/x"))
		agent := netServe(t, rig.p)
		c, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\nConnection: close\r\n\r\n")
		got, _ := io.ReadAll(c)
		if bytes.Contains(got, []byte(" :")) || bytes.Contains(got, []byte("Content-Length")) {
			t.Errorf("the agent got %q", got)
		}
	})
	// Go reads both framings by the chunked one, as RFC 9112 says, and
	// drops the length: the agent gets the chunked body, framed afresh.
	t.Run("a length and chunked", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nX-Smuggled: 1\r\n\r\n"
		rig := netRawRig(t, netRawReply(raw), netGet("/x"))
		agent := netServe(t, rig.p)
		c, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		resp, body, bodyErr, err := netExchange(c, bufio.NewReader(c), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == 200 && (string(body) != "ok" || bodyErr != nil || resp.Header.Get("X-Smuggled") != "") {
			t.Errorf("got %q %v %v", body, bodyErr, resp.Header)
		}
	})
}

// netTruncated is an upstream that starts an answer and breaks the
// connection in the middle of its body.
func netTruncated(head, partial string) func(net.Conn, *bufio.Reader) {
	return func(c net.Conn, br *bufio.Reader) {
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		io.WriteString(c, head+partial)
		if tc, ok := c.(*tls.Conn); ok {
			tc.NetConn().(*net.TCPConn).SetLinger(0) // a reset, not a clean close
		}
	}
}

// TestNetUpstreamTruncated: when the upstream breaks off in the middle of a
// body, the agent must see the response fail, never a shorter one that
// looks complete: a truncated git pack, file or JSON answer read as whole.
// Source: golang/go issue 23643, ReverseProxy's panic(http.ErrAbortHandler).
func TestNetUpstreamTruncated(t *testing.T) {
	for _, c := range []struct {
		name, head, partial string
	}{
		{"with a length", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", "only part"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "9\r\nonly part\r\n"},
		{"chunked, inside a chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "64\r\nonly part"},
		{"no length, no chunks", "HTTP/1.1 200 OK\r\n\r\n", "only part"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rig := netRawRig(t, netTruncated(c.head, c.partial), netGet("/x"))
			agent := netServe(t, rig.p)
			conn, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			resp, body, bodyErr, err := netExchange(conn, bufio.NewReader(conn), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
			if err != nil {
				return // the response itself failed: the agent knows
			}
			if c.name == "no length, no chunks" {
				// The upstream's end of body is its close: the agent cannot be
				// told more than it was.
				return
			}
			if bodyErr == nil {
				t.Errorf("the agent read a complete %d response of %q from a truncated one", resp.StatusCode, body)
			}
		})
	}
	t.Run("HTTP/2 stream reset", func(t *testing.T) {
		rig := netHTTPRig(t, true, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "only part")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // RST_STREAM
		}, netGet("/x"))
		agent := netServe(t, rig.p)
		conn, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		resp, body, bodyErr, err := netExchange(conn, bufio.NewReader(conn), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
		if err == nil && bodyErr == nil {
			t.Errorf("the agent read a complete %d response of %q from a reset stream", resp.StatusCode, body)
		}
	})
}

// TestNetUpstreamTrailersNeverCopied: trailers, chunked over HTTP/1.1, never
// reach the agent's socket.
func TestNetUpstreamTrailersNeverCopied(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTrailer: X-Trailer\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: sk-secret-trailer\r\n\r\n"
	rig := netRawRig(t, netRawReply(raw), netGet("/x"))
	agent := netServe(t, rig.p)
	c, err := agent.netDial(netHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\nConnection: close\r\n\r\n")
	got, _ := io.ReadAll(c)
	if bytes.Contains(got, []byte("sk-secret-trailer")) || bytes.Contains(bytes.ToLower(got), []byte("trailer:")) {
		t.Errorf("the agent got %q", got)
	}
}

// TestNetUpstreamBodiesUntouched: the proxy asks for no compression and
// passes a compressed body as its bytes, with its Content-Encoding.
func TestNetUpstreamBodiesUntouched(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(bytes.Repeat([]byte("sealroom "), 1000))
	zw.Close()
	rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {
		if ae := r.Header.Get("Accept-Encoding"); ae != "" {
			t.Errorf("the proxy asked for %q", ae)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	}, netGet("/x"))
	w := httptest.NewRecorder()
	rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
	if !bytes.Equal(w.Body.Bytes(), gz.Bytes()) || w.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("got %d bytes, %q", w.Body.Len(), w.Header().Get("Content-Encoding"))
	}
}

// TestNetUpstreamStalls: an upstream that stops answering, before its
// headers or in the middle of its body, is let go as soon as the agent
// goes: the proxy holds no request for an agent that left.
func TestNetUpstreamStalls(t *testing.T) {
	for _, mid := range []bool{false, true} {
		name := map[bool]string{false: "before the headers", true: "in the middle of the body"}[mid]
		t.Run(name, func(t *testing.T) {
			gone := make(chan struct{})
			release := make(chan struct{})
			rig := netHTTPRig(t, true, func(w http.ResponseWriter, r *http.Request) {
				if mid {
					io.WriteString(w, "part")
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
					close(gone)
				case <-release:
				}
			}, netGet("/x"))
			defer close(release)
			agent := netServe(t, rig.p)
			c, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
			if mid {
				br := bufio.NewReader(c)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 4)
				if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "part" {
					t.Fatalf("%q %v", buf, err)
				}
			} else {
				time.Sleep(100 * time.Millisecond)
			}
			c.Close()
			select {
			case <-gone:
			case <-time.After(5 * time.Second):
				t.Error("the upstream request outlived the agent's connection")
			}
		})
	}
	t.Run("an upstream that never speaks TLS", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close() // held open, silent
			}
		}()
		rig := netProxy(t, netNewCA(t).pool, ln.Addr().String(), Secrets{}, netGet("/x"))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int)
		go func() {
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil).WithContext(ctx))
			done <- w.Code
		}()
		time.Sleep(200 * time.Millisecond)
		cancel()
		select {
		case code := <-done:
			if code != http.StatusBadGateway {
				t.Errorf("got %d", code)
			}
		case <-time.After(5 * time.Second):
			t.Error("the handshake outlived the agent's request")
		}
	})
}

// TestNetOneTransportPerHost: two allowed hosts on the same server never
// share an upstream connection, and each is asked for by its own name.
func TestNetOneTransportPerHost(t *testing.T) {
	ca := netNewCA(t)
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.netLeaf(t, nil, netHost, netOther)}}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	rig := netProxy(t, ca.pool, srv.Listener.Addr().String(), Secrets{}, netGet("/x"), Rule{Method: "GET", Host: netOther, Path: "/x"})
	for i, host := range []string{netHost, netOther, netHost, netOther} {
		w := httptest.NewRecorder()
		rig.p.ServeHTTP(w, agentRequest("GET", "https://"+host+"/x", nil))
		if w.Code != 200 || w.Body.String() != host {
			t.Errorf("request %d to %s answered by %q", i, host, w.Body.String())
		}
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("%d upstream connections, want one per host", n)
	}
	d := rig.netDials()
	if len(d) != 2 || d[0] != netHost+":443" || d[1] != netOther+":443" {
		t.Errorf("dials %v", d)
	}
}

// TestNetNoProxyFromEnvironment: HTTPS_PROXY and friends are never used.
func TestNetNoProxyFromEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }, netGet("/x"))
	w := httptest.NewRecorder()
	rig.p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
	if w.Body.String() != "direct" {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
	if d := rig.netDials(); len(d) != 1 || d[0] != netHost+":443" {
		t.Errorf("dials %v", d)
	}
	if tr := upstreamClient(options{}).Transport.(*http.Transport); tr.Proxy != nil {
		t.Error("the proxy's own client has an outbound proxy")
	}
}

// TestNetUpstreamClientNoRedirect: the proxy's own client, for Google's
// tokens, returns a redirect instead of following it, and has a timeout.
func TestNetUpstreamClientNoRedirect(t *testing.T) {
	ca := netNewCA(t)
	var hits atomic.Int32
	srv := netUpstream(t, ca.netLeaf(t, nil, netHost), false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://"+netHost+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	client := upstreamClient(options{roots: ca.pool, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}})
	resp, err := client.Post("https://"+netHost+"/token", "text/plain", strings.NewReader("refresh"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 || hits.Load() != 1 {
		t.Errorf("got %d after %d requests", resp.StatusCode, hits.Load())
	}
	if client.Timeout <= 0 || client.Timeout > 5*time.Minute {
		t.Errorf("timeout %v", client.Timeout)
	}
}
