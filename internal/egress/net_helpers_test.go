package egress

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
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The helpers of the network tests. Every name starts with net, so they never
// clash with the helpers of the other test files of the package.

// netHost is the allowed name most network tests use; netOther is a second
// one, for tests of one host against another.
const (
	netHost  = "api.example.com"
	netOther = "other.example.com"
)

// netProxyIP is the address the proxy answers DNS with.
var netProxyIP = netip.MustParseAddr("10.9.8.7")

// netLog is an audit log the proxy and the test may use at the same time.
type netLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *netLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *netLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// netEntries parses every line of the log as one JSON object, and fails the
// test on a line that is not one.
func (l *netLog) netEntries(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(l.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line %q is not one JSON object: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// netCA is a certificate authority for upstream servers or for the agent.
type netCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func netNewCA(t *testing.T) *netCA {
	t.Helper()
	cert, key := testCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &netCA{cert: cert, key: key, pool: pool}
}

var netSerial atomic.Int64

// netLeaf signs a server certificate for names; edit, when set, changes the
// template before it is signed.
func (ca *netCA) netLeaf(t *testing.T, edit func(*x509.Certificate), names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := ""
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(netSerial.Add(1) + 100),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// netUpstream starts a TLS server presenting cert and serving h, offering
// HTTP/2 when h2 is set.
func netUpstream(t *testing.T, cert tls.Certificate, h2 bool, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// netRawUpstream starts a TLS server, HTTP/1.1 by ALPN, that hands each
// connection to serve, which writes whatever bytes a hostile upstream would.
func netRawUpstream(t *testing.T, cert tls.Certificate, serve func(c net.Conn, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				serve(c, bufio.NewReader(c))
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().String()
}

// netRawReply reads one request and answers it with raw bytes, then closes.
func netRawReply(raw string) func(net.Conn, *bufio.Reader) {
	return func(c net.Conn, br *bufio.Reader) {
		r, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		io.Copy(io.Discard, r.Body)
		io.WriteString(c, raw)
	}
}

// netRig is a proxy whose every upstream connection reaches one test
// server, with the address the proxy asked for recorded.
type netRig struct {
	p   *Proxy
	log *netLog

	mu    sync.Mutex
	dials []string
}

func (r *netRig) netDials() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dials...)
}

// netProxy builds a proxy for rules whose upstream connections all reach
// upstreamAddr, trusting roots.
func netProxy(t *testing.T, roots *x509.CertPool, upstreamAddr string, secrets Secrets, rules ...Rule) *netRig {
	t.Helper()
	rig := &netRig{log: &netLog{}}
	p, err := newProxy(Config{Placeholder: testPlaceholder, Rules: rules}, secrets, rig.log, options{
		roots: roots,
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			rig.mu.Lock()
			rig.dials = append(rig.dials, address)
			rig.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.p = p
	t.Cleanup(func() {
		for _, tr := range p.clients {
			tr.CloseIdleConnections()
		}
	})
	return rig
}

// netGet is a rule allowing GET on path of netHost.
func netGet(path string) Rule {
	return Rule{Method: "GET", Host: netHost, Path: path, Query: AnyQuery}
}

// netHTTPRig starts an upstream for netHost and netOther serving h, and a
// proxy reaching it.
func netHTTPRig(t *testing.T, h2 bool, h http.HandlerFunc, rules ...Rule) *netRig {
	t.Helper()
	ca := netNewCA(t)
	srv := netUpstream(t, ca.netLeaf(t, nil, netHost, netOther), h2, h)
	return netProxy(t, ca.pool, srv.Listener.Addr().String(), Secrets{}, rules...)
}

// netRawRig starts a raw upstream for netHost and a proxy reaching it.
func netRawRig(t *testing.T, serve func(net.Conn, *bufio.Reader), rules ...Rule) *netRig {
	t.Helper()
	ca := netNewCA(t)
	addr := netRawUpstream(t, ca.netLeaf(t, nil, netHost), serve)
	return netProxy(t, ca.pool, addr, Secrets{}, rules...)
}

// netAgent is the agent's side of a proxy served on real sockets.
type netAgent struct {
	addr  string
	dns   net.Addr
	ca    *netCA
	roots *x509.CertPool
}

// netServe runs p.Serve on loopback sockets, with a CA of its own, until the
// test ends.
func netServe(t *testing.T, p *Proxy) *netAgent {
	t.Helper()
	ca := netNewCA(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		p.Serve(udp, ln, ca.cert, ca.key, netProxyIP)
		close(done)
	}()
	t.Cleanup(func() {
		ln.Close()
		udp.Close()
		<-done
	})
	return &netAgent{addr: ln.Addr().String(), dns: udp.LocalAddr(), ca: ca, roots: ca.pool}
}

// netDial opens a TLS connection to the proxy as the agent would, for name,
// trusting the run's CA; edit, when set, changes the client's config.
func (a *netAgent) netDial(name string, edit func(*tls.Config)) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: name, RootCAs: a.roots, NextProtos: []string{"http/1.1"}}
	if edit != nil {
		edit(cfg)
	}
	raw, err := net.DialTimeout("tcp", a.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// netDialConn is netDial over a connection of the caller's, such as one
// that rewrites or splits what the client sends.
func (a *netAgent) netDialConn(name string, wrap func(net.Conn) net.Conn, edit func(*tls.Config)) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: name, RootCAs: a.roots, NextProtos: []string{"http/1.1"}}
	if edit != nil {
		edit(cfg)
	}
	raw, err := net.DialTimeout("tcp", a.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	c := tls.Client(wrap(raw), cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// netExchange writes a raw request on c and reads one response, with its
// whole body; bodyErr is the error reading the body, if any.
func netExchange(c net.Conn, br *bufio.Reader, raw string) (resp *http.Response, body []byte, bodyErr error, err error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		return nil, nil, nil, err
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	body, bodyErr = io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body, bodyErr, nil
}

// netHelloConn rewrites the client's first flight, the ClientHello: from is
// replaced by to, of the same length, so the client can send a server name
// Go's client never would; records splits the handshake record into records
// of that many bytes; chunk writes the flight that many bytes at a time.
type netHelloConn struct {
	net.Conn
	from, to string
	records  int
	chunk    int
	done     bool
}

func (c *netHelloConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	out := append([]byte(nil), b...)
	if c.from != "" {
		out = bytes.Replace(out, []byte(c.from), []byte(c.to), 1)
	}
	if c.records > 0 && len(out) > 5 && out[0] == 22 {
		n := int(binary.BigEndian.Uint16(out[3:5]))
		payload, rest := out[5:5+n], out[5+n:]
		var split []byte
		for len(payload) > 0 {
			k := min(c.records, len(payload))
			split = append(split, 22, out[1], out[2], byte(k>>8), byte(k))
			split = append(split, payload[:k]...)
			payload = payload[k:]
		}
		out = append(split, rest...)
	}
	if c.chunk > 0 {
		for len(out) > 0 {
			k := min(c.chunk, len(out))
			if _, err := c.Conn.Write(out[:k]); err != nil {
				return 0, err
			}
			out = out[k:]
		}
		return len(b), nil
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}
