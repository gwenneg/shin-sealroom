package egress

// The parsing harness runs the real proxy with Serve on real sockets, talks to
// it as an attacker would, with raw bytes on a TLS connection, and records
// byte for byte what a raw TLS upstream receives. Every helper is prefixed
// with par.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// parSecret is the user's real credential in the harness's proxy.
const parSecret = "par-real-secret-0123456789"

// parRules are the rules every harness proxy serves.
func parRules() []Rule {
	return []Rule{
		{Method: "GET", Host: "example.com", Path: "/"},
		{Method: "HEAD", Host: "example.com", Path: "/"},
		{Method: "GET", Host: "example.com", Path: "/v1/models", Query: AnyQuery, Headers: []string{"Accept", "X-Note"}},
		{Method: "POST", Host: "example.com", Path: "/v1/messages", Query: "beta=true", Headers: []string{"Content-Type", "X-Note"}},
		{Method: "POST", Host: "example.com", Path: "/v1/inspect", Headers: []string{"Content-Type"}, InspectMessages: true},
		{Method: "GET", Host: "example.com", Path: "/repos/o/r/*", Query: AnyQuery},
		{Method: "GET", Host: "example.com", Path: "/raw/**"},
		{Method: "PUT", Host: "example.com", Path: "/upload", Headers: []string{"Content-Type"}},
		{Method: "DELETE", Host: "example.com", Path: "/item"},
		{Method: "GET", Host: "example.com", Path: "/auth", Headers: []string{"X-Note"},
			Credential: &Credential{Secret: "key", Header: "Authorization", Scheme: "Bearer"}},
		{Method: "GET", Host: "api.example.com", Path: "/"},
		// Only on the second host: a Host confusion that reached a rule would
		// reach this one.
		{Method: "GET", Host: "api.example.com", Path: "/admin"},
	}
}

// parLog is the proxy's audit log, safe to read while the proxy writes.
type parLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *parLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(b)
}

func (l *parLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// parReq is one request as the upstream received it.
type parReq struct {
	SNI      string // the TLS server name the proxy connected with
	Head     string // request line and header section, exactly as received, up to and including the empty line
	RawBody  string // the body bytes as received, chunk framing included
	Body     string // the body, chunk framing removed
	Complete bool   // the body was received whole, up to its framing's end
}

// parUpstream is a raw TLS HTTP/1.1 server: it records every request byte for
// byte and answers with respond, or "ok" by default. It closes the connection
// after an HTTP/1.0 answer or one saying Connection: close.
type parUpstream struct {
	ln    net.Listener
	roots *x509.CertPool

	mu    sync.Mutex
	reqs  []parReq
	conns int
	// respond returns the raw bytes to answer the n-th request (from 0) with,
	// or "" to close the connection without an answer.
	respond func(n int, r parReq) string
}

// parOK answers "ok", without the body for HEAD.
func parOK(_ int, r parReq) string {
	if strings.HasPrefix(r.Head, "HEAD ") {
		return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n"
	}
	return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
}

// parLeaf mints a certificate for names, signed by a test CA.
func parLeaf(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	ca, caKey := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func parStartUpstream(t *testing.T, respond func(int, parReq) string) *parUpstream {
	t.Helper()
	cert, roots := parLeaf(t, "example.com", "api.example.com")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if respond == nil {
		respond = parOK
	}
	u := &parUpstream{ln: ln, roots: roots, respond: respond}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.conns++
			u.mu.Unlock()
			go u.serve(c.(*tls.Conn))
		}
	}()
	return u
}

func (u *parUpstream) serve(c *tls.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if c.Handshake() != nil {
		return
	}
	sni := c.ConnectionState().ServerName
	br := bufio.NewReader(c)
	for {
		head, err := parReadHead(br)
		if err != nil {
			return
		}
		u.mu.Lock()
		n := len(u.reqs)
		u.reqs = append(u.reqs, parReq{SNI: sni, Head: head})
		u.mu.Unlock()
		raw, body, err := parReadBody(br, head)
		u.mu.Lock()
		u.reqs[n].RawBody, u.reqs[n].Body, u.reqs[n].Complete = raw, body, err == nil
		r := u.reqs[n]
		u.mu.Unlock()
		if err != nil {
			return
		}
		resp := u.respond(n, r)
		if resp == "" {
			return
		}
		if _, err := io.WriteString(c, resp); err != nil {
			return
		}
		// An answer framed by closing, or that says it closes, ends the
		// connection.
		if head, _, _ := strings.Cut(resp, "\r\n\r\n"); strings.HasPrefix(resp, "HTTP/1.0") || strings.Contains(head, "Connection: close") {
			return
		}
	}
}

// requests returns what the upstream received so far.
func (u *parUpstream) requests() []parReq {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]parReq(nil), u.reqs...)
}

// parReadHead reads a header section, up to and including its empty line.
// Only CRLF ends a line: the proxy's own requests never use anything else.
func parReadHead(br *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			return head.String(), err
		}
		if line == "\r\n" {
			return head.String(), nil
		}
		if head.Len() > 1<<20 {
			return head.String(), errors.New("head too long")
		}
	}
}

// parHeaderValues returns the values of a header in a raw head, by name in
// any case.
func parHeaderValues(head, name string) []string {
	var out []string
	for _, line := range strings.Split(head, "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(k, name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// parReadBody reads a body as the head frames it: chunked, by length, or
// none.
func parReadBody(br *bufio.Reader, head string) (raw, body string, err error) {
	if te := parHeaderValues(head, "Transfer-Encoding"); len(te) > 0 {
		if len(te) != 1 || te[0] != "chunked" {
			return "", "", fmt.Errorf("transfer encoding %q", te)
		}
		var r, b strings.Builder
		for {
			line, err := br.ReadString('\n')
			r.WriteString(line)
			if err != nil {
				return r.String(), b.String(), err
			}
			size, _, _ := strings.Cut(strings.TrimSuffix(line, "\r\n"), ";")
			n, err := strconv.ParseUint(size, 16, 32)
			if err != nil {
				return r.String(), b.String(), err
			}
			if n == 0 {
				trailer, err := parReadHead(br)
				r.WriteString(trailer)
				return r.String(), b.String(), err
			}
			data := make([]byte, n+2)
			k, err := io.ReadFull(br, data)
			r.Write(data[:k])
			if err != nil {
				return r.String(), b.String(), err
			}
			b.Write(data[:n])
		}
	}
	if cl := parHeaderValues(head, "Content-Length"); len(cl) > 0 {
		n, err := strconv.ParseUint(cl[0], 10, 32)
		if err != nil || len(cl) != 1 {
			return "", "", fmt.Errorf("content length %q", cl)
		}
		data := make([]byte, n)
		k, err := io.ReadFull(br, data)
		return string(data[:k]), string(data[:k]), err
	}
	return "", "", nil
}

// parEnv is a running proxy, its upstream and its log.
type parEnv struct {
	addr  string
	roots *x509.CertPool
	log   *parLog
	up    *parUpstream
}

// parProxy starts the real proxy with Serve on real sockets, with the
// harness's rules, forwarding to a raw upstream that answers with respond.
func parProxy(t *testing.T, respond func(int, parReq) string) *parEnv {
	t.Helper()
	return parProxyRules(t, respond, parRules())
}

func parProxyRules(t *testing.T, respond func(int, parReq) string, rules []Rule) *parEnv {
	t.Helper()
	up := parStartUpstream(t, respond)
	log := &parLog{}
	p, err := newProxy(Config{Placeholder: testPlaceholder, Rules: rules},
		Secrets{Values: map[string]string{"key": parSecret}}, log, options{
			roots: up.roots,
			dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, up.ln.Addr().String())
			},
		})
	if err != nil {
		t.Fatal(err)
	}
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
	return &parEnv{addr: ln.Addr().String(), roots: parPool(ca), log: log, up: up}
}

// parPool is a pool of one CA.
func parPool(ca *x509.Certificate) *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots
}

// parDial opens the agent's TLS connection to the proxy for a server name.
func (e *parEnv) parDial(t *testing.T, sni string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: sni, RootCAs: e.roots, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// parResp is one response the agent read.
type parResp struct {
	Status int
	Header http.Header
	Body   string
	Close  bool
}

func (r parResp) String() string {
	return fmt.Sprintf("%d %q", r.Status, r.Body)
}

// parSentinel is a request no rule allows, sent after a case's own bytes:
// its answer must be the next and last thing the agent reads, so any other
// request the proxy read from the case's bytes shows as an extra answer.
const parSentinel = "GET /parsentinel HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"

// parExchange is the result of sending raw bytes to the proxy.
type parExchange struct {
	Resps []parResp // the case's answers
	Extra []parResp // answers read after them, the sentinel's excluded
	Raw   string    // every byte the agent read
	// SentinelAnswered reports whether the sentinel was read and answered as
	// a request of its own.
	SentinelAnswered bool
}

// parSend writes raw on a new connection for sni, reads want answers, then
// checks the connection: closed if the last answer said so, else answering
// a sentinel as the next request and nothing else. heads lists the methods
// of the requests answered, for HEAD answers without a body; it may be nil.
func (e *parEnv) parSend(t *testing.T, sni, raw string, want int, heads ...string) parExchange {
	t.Helper()
	c := e.parDial(t, sni)
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	var rec bytes.Buffer
	br := bufio.NewReader(io.TeeReader(c, &rec))
	var ex parExchange
	read := func(method string) (parResp, error) {
		var req *http.Request
		if method != "" {
			req = &http.Request{Method: method}
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return parResp{}, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		return parResp{Status: resp.StatusCode, Header: resp.Header, Body: string(body), Close: resp.Close}, err
	}
	for i := 0; i < want; i++ {
		method := ""
		if i < len(heads) {
			method = heads[i]
		}
		r, err := read(method)
		if err != nil {
			t.Fatalf("answer %d of %d: %v; read so far %q", i+1, want, err, rec.String())
		}
		ex.Resps = append(ex.Resps, r)
	}
	if want == 0 || !ex.Resps[want-1].Close {
		// Ignore a write error: a connection the proxy closed shows as EOF.
		io.WriteString(c, fmt.Sprintf(parSentinel, sni))
	}
	for {
		r, err := read("")
		if err != nil {
			break
		}
		if r.Status == http.StatusForbidden && r.Body == "sealroom: refused (no-rule)\n" && r.Close && !ex.SentinelAnswered {
			ex.SentinelAnswered = true
			continue
		}
		ex.Extra = append(ex.Extra, r)
	}
	ex.Raw = rec.String()
	return ex
}

// parRefused is the fixed body of a refusal for reason.
func parRefused(reason string) string {
	return "sealroom: refused (" + reason + ")\n"
}

// parHead is the head the proxy's HTTP/1.1 client sends for a request with
// no header but those listed, in the order Go writes them.
func parHead(method, target, host string, headers ...string) string {
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Go-http-client/1.1\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// parWaitIdle waits briefly for the upstream to have received n requests, for
// checks made after the agent read its answers.
func (u *parUpstream) parWaitIdle(n int) []parReq {
	deadline := time.Now().Add(2 * time.Second)
	for {
		reqs := u.requests()
		if len(reqs) >= n || time.Now().After(deadline) {
			return reqs
		}
		time.Sleep(5 * time.Millisecond)
	}
}
