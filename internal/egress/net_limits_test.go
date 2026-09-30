package egress

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNetServerSettings pins the limits the spec names, on the server the
// agent talks to and on the upstream transports, where waiting for them in
// a test would take minutes.
func TestNetServerSettings(t *testing.T) {
	ca := netNewCA(t)
	rig := netHTTPRig(t, false, nil, netGet("/x"))
	c, _ := newCerts(ca.cert, ca.key, rig.p.allowed)
	srv := rig.p.newServer(c)
	for name, ok := range map[string]bool{
		"headers read within 30 seconds":          srv.ReadHeaderTimeout == 30*time.Second,
		"idle connections closed after 2 minutes": srv.IdleTimeout == 2*time.Minute,
		"headers bounded to 64 KiB":               srv.MaxHeaderBytes == 64<<10,
		"no write timeout, for streams":           srv.WriteTimeout == 0,
		"TLS 1.2 at least":                        srv.TLSConfig.MinVersion == tls.VersionTLS12,
		"HTTP/1.1 only by ALPN":                   slices.Equal(srv.TLSConfig.NextProtos, []string{"http/1.1"}),
		"HTTP/2 off":                              srv.TLSNextProto != nil && len(srv.TLSNextProto) == 0,
		"certificates only from certs.get":        srv.TLSConfig.GetCertificate != nil && len(srv.TLSConfig.Certificates) == 0,
		"no client certificates asked":            srv.TLSConfig.ClientAuth == tls.NoClientCert,
		"connection errors out of the audit log":  srv.ErrorLog != nil,
	} {
		t.Run(name, func(t *testing.T) {
			if !ok {
				t.Error("not so")
			}
		})
	}
	tr := rig.p.clients[netHost]
	for name, ok := range map[string]bool{
		"upstream may take 10 minutes to answer": tr.ResponseHeaderTimeout == 10*time.Minute,
		"upstream handshake bounded":             tr.TLSHandshakeTimeout > 0 && tr.TLSHandshakeTimeout <= time.Minute,
		"no outbound proxy":                      tr.Proxy == nil,
		"no decompression":                       tr.DisableCompression,
		"upstream TLS 1.2 at least":              tr.TLSClientConfig.MinVersion >= tls.VersionTLS12,
		"verification never off":                 !tr.TLSClientConfig.InsecureSkipVerify,
		"the rule's host as server name":         tr.TLSClientConfig.ServerName == netHost,
		"no custom verification":                 tr.TLSClientConfig.VerifyPeerCertificate == nil && tr.TLSClientConfig.VerifyConnection == nil,
		"idle upstream connections expire":       tr.IdleConnTimeout > 0,
	} {
		t.Run(name, func(t *testing.T) {
			if !ok {
				t.Error("not so")
			}
		})
	}
	t.Run("production transport checks addresses", func(t *testing.T) {
		p, err := New(Config{Placeholder: testPlaceholder, Rules: []Rule{netGet("/x")}}, Secrets{}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		tr := p.clients[netHost]
		if tr.TLSClientConfig.RootCAs != nil || tr.DialContext == nil {
			t.Error("production uses other roots, or no dialer")
		}
	})
}

// netServed is a proxy on real sockets whose upstream counts requests and
// the body bytes it got, with rules for GET and POST on /x.
func netServed(t *testing.T) (*netRig, *netAgent, *atomic.Int32, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int32
	var bodyBytes atomic.Int64
	rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		bodyBytes.Add(n)
		io.WriteString(w, "ok "+r.URL.Path)
	}, netGet("/x"), Rule{Method: "POST", Host: netHost, Path: "/x", Headers: []string{"Content-Type"}})
	return rig, netServe(t, rig.p), &hits, &bodyBytes
}

// TestNetRequestSizeLimits: header bombs and long targets end with a 4xx
// before any rule, and nothing reaches the upstream. Sources: RFC 6585
// (431), Envoy's edge best practices, CVE-2023-45288 (header floods).
func TestNetRequestSizeLimits(t *testing.T) {
	rig, agent, hits, _ := netServed(t)
	for _, c := range []struct {
		name, raw string
		want      int
	}{
		// Go's server unfolds obsolete line folding and reads a bare LF; the
		// proxy then rebuilds the request, so neither can be read two ways
		// upstream, and the header is dropped as on no rule's list.
		{"70 KiB of headers", "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\n" + strings.Repeat("X-Pad: "+strings.Repeat("a", 1000)+"\r\n", 70) + "\r\n", 431},
		{"one header of 70 KiB", "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\nX-Big: " + strings.Repeat("a", 70<<10) + "\r\n\r\n", 431},
		{"a 70 KiB target", "GET /x?a=" + strings.Repeat("a", 70<<10) + " HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", 431},
		{"a 3000-byte path", "GET /" + strings.Repeat("a", 3000) + " HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", 403},
		{"a 3000-byte query", "GET /x?a=" + strings.Repeat("a", 3000) + " HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", 403},
		{"a 70 KiB method", strings.Repeat("G", 70<<10) + " /x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", 431},
		{"a 10 KiB method", strings.Repeat("G", 10<<10) + " /x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", 403},
		{"a header name byte above 0x7f", "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\nX-\xc3\xa9: 1\r\n\r\n", 403},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			before := hits.Load()
			resp, _, _, err := netExchange(conn, bufio.NewReader(conn), c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != c.want {
				t.Errorf("got %d, want %d", resp.StatusCode, c.want)
			}
			if hits.Load() != before {
				t.Error("upstream reached")
			}
		})
	}
	for name, raw := range map[string]string{
		"obsolete line folding": "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\nX-A: 1\r\n X-Injected: 2\r\n\r\n",
		"a bare LF":             "GET /x HTTP/1.1\nHost: " + netHost + "\nX-A: 1\n\n",
		"5000 small headers":    "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\n" + strings.Repeat("X-A: 1\r\n", 5000) + "\r\n",
	} {
		t.Run(name+", never forwarded", func(t *testing.T) {
			var got http.Header
			up := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }, netGet("/x"))
			a := netServe(t, up.p)
			conn, err := a.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, _, _, err := netExchange(conn, bufio.NewReader(conn), raw); err != nil {
				t.Fatal(err)
			}
			if got.Get("X-A") != "" || got.Get("X-Injected") != "" {
				t.Errorf("the upstream got %v", got)
			}
		})
	}
	t.Run("100 small headers, all dropped", func(t *testing.T) {
		var b strings.Builder
		for i := range 100 {
			fmt.Fprintf(&b, "X-H%d: v\r\n", i)
		}
		var got http.Header
		up := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) { got = r.Header }, netGet("/x"))
		a := netServe(t, up.p)
		conn, err := a.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		resp, _, _, err := netExchange(conn, bufio.NewReader(conn), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n"+b.String()+"\r\n")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%v %v", err, resp)
		}
		for k := range got {
			if strings.HasPrefix(k, "X-H") {
				t.Fatalf("%s reached the upstream", k)
			}
		}
	})
	_ = rig
}

// TestNetRequestFraming: chunked bodies Go's server must refuse, and the
// classic smuggling shapes, never reach the upstream as anything but one
// checked request. Sources: CVE-2023-39326 (chunk extensions), Squid
// CVE-2026-61642, PortSwigger's request smuggling research.
func TestNetRequestFraming(t *testing.T) {
	rig, agent, hits, bodyBytes := netServed(t)
	post := "POST /x HTTP/1.1\r\nHost: " + netHost + "\r\nContent-Type: text/plain\r\n"
	// reframed: Go's server reads the body by its chunked framing alone, and
	// the proxy sends it upstream framed afresh, so it may be accepted.
	for _, c := range []struct {
		name, raw string
		maxHits   int32
		reframed  bool
	}{
		{"chunk size overflow", post + "Transfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\nx\r\n0\r\n\r\n", 1, false},
		{"chunk size not hex", post + "Transfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n0\r\n\r\n", 1, false},
		{"1 MiB of chunk extensions", post + "Transfer-Encoding: chunked\r\n\r\n" + strings.Repeat("1;"+strings.Repeat("e", 1000)+"\r\nx\r\n", 1024) + "0\r\n\r\n", 1, false},
		{"Transfer-Encoding in capitals", post + "Transfer-Encoding: CHUNKED\r\n\r\n1\r\nx\r\n0\r\n\r\n", 1, true},
		{"Transfer-Encoding with a space", post + "Transfer-Encoding : chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", 0, false},
		{"chunked twice", post + "Transfer-Encoding: chunked, chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", 0, false},
		{"chunked in two headers", post + "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", 0, false},
		{"length and chunked", post + "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG", 1, true},
		{"two lengths", post + "Content-Length: 1\r\nContent-Length: 2\r\n\r\nxx", 0, false},
		{"a signed length", post + "Content-Length: +1\r\n\r\nx", 0, false},
		{"trailers", post + "Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Trailer: 1\r\n\r\n", 1, true},
		{"declared trailers", post + "Trailer: X-Trailer\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Trailer: 1\r\n\r\n", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn, err := agent.netDial(netHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			before := hits.Load()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(conn, c.raw)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				if resp.StatusCode == 200 && !c.reframed {
					t.Errorf("accepted with %d", resp.StatusCode)
				}
			}
			if got := hits.Load() - before; got > c.maxHits {
				t.Errorf("upstream reached %d times", got)
			}
		})
	}
	t.Run("a request after a short length is checked like any other", func(t *testing.T) {
		conn, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		before, beforeBytes := hits.Load(), bodyBytes.Load()
		smuggled := "GET /admin HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n"
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, post+"Content-Length: 2\r\n\r\nok"+smuggled)
		br := bufio.NewReader(conn)
		first, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, first.Body)
		second, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(second.Body)
		if first.StatusCode != 200 || second.StatusCode != 403 || !strings.Contains(string(body), reasonNoRule) {
			t.Errorf("got %d then %d %q", first.StatusCode, second.StatusCode, body)
		}
		if hits.Load()-before != 1 || bodyBytes.Load()-beforeBytes != 2 {
			t.Errorf("upstream got %d requests, %d bytes", hits.Load()-before, bodyBytes.Load()-beforeBytes)
		}
	})
	t.Run("the G after length and chunked never reaches upstream", func(t *testing.T) {
		var bodies []string
		var methods []string
		up := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			methods = append(methods, r.Method+" "+r.URL.Path+" "+fmt.Sprint(r.Trailer))
		}, Rule{Method: "POST", Host: netHost, Path: "/x"})
		a := netServe(t, up.p)
		conn, err := a.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, post+"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
		io.ReadAll(conn)
		// Content-Length with chunked framing is refused whole.
		if len(bodies) != 0 {
			t.Errorf("the upstream got bodies %q, requests %q", bodies, methods)
		}
	})
	_ = rig
}

// netZeros is a body of n zero bytes, made as it is read.
type netZeros struct{ n int64 }

func (z *netZeros) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	k := min(int64(len(p)), z.n)
	clear(p[:k])
	z.n -= k
	return int(k), nil
}

// TestNetBodyOverLimit: a chunked body, with no length to refuse it early,
// ends with 413 once it passes 64 MiB, and the upstream never gets it
// whole. Source: the spec's limits; CVE-2024-27919 (floods past a limit).
func TestNetBodyOverLimit(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprintf("inspected %v", inspect), func(t *testing.T) {
			var got atomic.Int64
			rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				got.Store(n)
			}, Rule{Method: "POST", Host: netHost, Path: "/x", InspectMessages: inspect})
			r := agentRequest("POST", "https://"+netHost+"/x", &netZeros{MaxBodyBytes + 1})
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
			w := httptest.NewRecorder()
			rig.p.ServeHTTP(w, r)
			if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), reasonTooLarge) {
				t.Errorf("got %d %q", w.Code, w.Body.String())
			}
			if got.Load() > MaxBodyBytes {
				t.Errorf("the upstream got %d bytes", got.Load())
			}
		})
	}
}

// TestNetConnectionLimit: 256 connections held open by the agent leave no
// room for one more, and closing one makes room. Source: slowloris, the
// spec's limit.
func TestNetConnectionLimit(t *testing.T) {
	_, agent, _, _ := netServed(t)
	held := make([]net.Conn, 0, maxConnections)
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range maxConnections {
		c, err := net.Dial("tcp", agent.addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond) // the server accepts all of them
	if c, err := agent.netDialTimeout(netHost, time.Second); err == nil {
		c.Close()
		t.Fatal("a connection past the limit was served")
	}
	held[0].Close()
	held = held[1:]
	c, err := agent.netDialTimeout(netHost, 5*time.Second)
	if err != nil {
		t.Fatalf("no room after a connection closed: %v", err)
	}
	c.Close()
}

// netDialTimeout is netDial with a deadline on the whole handshake.
func (a *netAgent) netDialTimeout(name string, d time.Duration) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", a.addr, d)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(d))
	c := tls.Client(raw, &tls.Config{ServerName: name, RootCAs: a.roots, NextProtos: []string{"http/1.1"}})
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// TestNetSlowClients waits the proxy's real 30-second limits out, in
// parallel: a client that never says hello, one that never sends a
// request, one that sends its headers a byte at a time. Each is closed
// after 30 seconds. Skipped with -short. The 2-minute idle limit is only
// pinned, in TestNetServerSettings.
func TestNetSlowClients(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 30 seconds")
	}
	t.Parallel()
	_, agent, hits, _ := netServed(t)
	closedWithin := func(t *testing.T, c net.Conn, start time.Time, drip func()) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(45 * time.Second))
		errc := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(c)
			errc <- err
		}()
		if drip != nil {
			go drip()
		}
		<-errc
		if took := time.Since(start); took < 25*time.Second || took > 40*time.Second {
			t.Errorf("closed after %v, want about 30s", took)
		}
	}
	t.Run("no ClientHello", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		c, err := net.Dial("tcp", agent.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		closedWithin(t, c, start, nil)
	})
	t.Run("no request", func(t *testing.T) {
		t.Parallel()
		c, err := agent.netDialTimeout(netHost, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Time{})
		closedWithin(t, c, time.Now(), nil)
	})
	t.Run("headers a byte at a time", func(t *testing.T) {
		t.Parallel()
		c, err := agent.netDialTimeout(netHost, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Time{})
		req := "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\n" + strings.Repeat("X-Slow: 1\r\n", 100)
		closedWithin(t, c, time.Now(), func() {
			for i := range len(req) {
				if _, err := c.Write([]byte{req[i]}); err != nil {
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		})
		if hits.Load() != 0 {
			t.Error("the slow request reached the upstream")
		}
	})
}

// TestNetNoGoroutineLeak: agents that leave in the middle of a streamed
// answer leave nothing running behind them.
func TestNetNoGoroutineLeak(t *testing.T) {
	release := make(chan struct{})
	rig := netHTTPRig(t, true, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "part")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}, netGet("/x"))
	defer close(release)
	agent := netServe(t, rig.p)
	settle := func() int {
		rig.p.clients[netHost].CloseIdleConnections()
		time.Sleep(50 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	run := func() {
		c, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err == nil {
			buf := make([]byte, 4)
			io.ReadFull(resp.Body, buf)
		}
		c.Close()
	}
	run()
	base := settle()
	for range 40 {
		run()
	}
	var now int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if now = settle(); now <= base+5 {
			return
		}
	}
	t.Errorf("%d goroutines after 40 abandoned streams, %d before", now, base)
}
