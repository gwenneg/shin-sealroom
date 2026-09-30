package egress

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// netTLSRig is a proxy served on real sockets for netHost and netOther,
// whose upstream answers "ok" and counts the requests it gets.
func netTLSRig(t *testing.T) (*netRig, *netAgent, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok "+r.Host)
	}, netGet("/x"), Rule{Method: "GET", Host: netOther, Path: "/x"})
	return rig, netServe(t, rig.p), &hits
}

// TestNetHandshakeAllowed: the certificate the agent gets is for the exact
// name, from the run's CA, a leaf for server authentication only, short
// lived, and HTTP/1.1 is what is spoken.
func TestNetHandshakeAllowed(t *testing.T) {
	_, agent, _ := netTLSRig(t)
	for _, name := range []string{netHost, netOther} {
		t.Run(name, func(t *testing.T) {
			c, err := agent.netDial(name, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			st := c.ConnectionState()
			leaf := st.PeerCertificates[0]
			switch {
			case len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name:
				t.Errorf("names %v", leaf.DNSNames)
			case len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0:
				t.Errorf("other names %v %v %v", leaf.IPAddresses, leaf.URIs, leaf.EmailAddresses)
			case leaf.IsCA || leaf.BasicConstraintsValid && leaf.IsCA:
				t.Error("the leaf is a CA")
			case len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth:
				t.Errorf("extended key usage %v", leaf.ExtKeyUsage)
			case leaf.KeyUsage&x509.KeyUsageCertSign != 0:
				t.Error("the leaf can sign certificates")
			case leaf.NotAfter.Sub(leaf.NotBefore) > 25*time.Hour:
				t.Errorf("valid for %v", leaf.NotAfter.Sub(leaf.NotBefore))
			case st.NegotiatedProtocol != "http/1.1":
				t.Errorf("protocol %q", st.NegotiatedProtocol)
			case len(st.PeerCertificates) != 1:
				t.Errorf("%d certificates sent", len(st.PeerCertificates))
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: agent.roots, DNSName: "evil.example"}); err == nil {
				t.Error("the leaf is valid for another name")
			}
		})
	}
}

// TestNetHandshakeRefusedNames sends server names the agent's client could
// send, and is refused for each, before any HTTP, with the refusal logged.
// Sources: Smokescreen CVE-2022-24825 and CVE-2022-29188, Traefik
// CVE-2026-48491, Vercel's firewall (SNI and Host).
func TestNetHandshakeRefusedNames(t *testing.T) {
	rig, agent, hits := netTLSRig(t)
	for _, name := range []string{
		"evil.example", "API.example.com", "Api.Example.Com", "API.EXAMPLE.COM",
		"x." + netHost, netHost + ".evil.example", "evil" + netHost, "example.com",
		"*.example.com", "xn--api-example.com", "api.xn--example-xyz.com", "api%2eexample.com",
		"аpi.example.com", // Cyrillic a
		netHost + "\x00.evil.example", netHost + "\n", netHost + " ", " " + netHost,
		"localhost", "metadata.google.internal", strings.Repeat("a", 250) + ".example.com",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := agent.netDial(name, func(c *tls.Config) { c.InsecureSkipVerify = true })
			if err == nil {
				c.Close()
				t.Fatal("the handshake succeeded")
			}
			want := name
			if len(want) > 255 {
				want = want[:255]
			}
			if !netWaitLogHost(t, rig.log, want) {
				t.Errorf("no tls-server-name line for %q: %s", name, rig.log)
			}
		})
	}
	if hits.Load() != 0 {
		t.Errorf("upstream reached %d times", hits.Load())
	}
}

// netWaitLogHost waits for a refused-handshake line naming host.
func netWaitLogHost(t *testing.T, log *netLog, host string) bool {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, e := range log.netEntries(t) {
			if e["reason"] == "tls-server-name" && e["host"] == host {
				return true
			}
		}
	}
	return false
}

// TestNetHandshakeWireNames rewrites the server name on the wire, to send
// what Go's client never would: an address, a trailing dot, no name.
func TestNetHandshakeWireNames(t *testing.T) {
	rig, agent, hits := netTLSRig(t)
	for _, c := range []struct {
		name, from, to string
		logged         bool // false: Go's parser refuses it before the name is looked at
	}{
		{"IPv4 address", "a.b.c.d.example.com", "169.254.169.254.com", true},
		{"IPv4 address alone", "a.b.c.d.e", "127.0.0.1", true},
		{"trailing dot", "api.example.comx", "api.example.com.", false},
		{"uppercase only on the wire", netHost, "API.EXAMPLE.COM", true},
		{"NUL after the name", "api.example.comx", "api.example.com\x00", true},
		{"IPv6 literal", "aaaaaaa", "[::1]:x", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if len(c.from) != len(c.to) {
				t.Fatalf("%q and %q differ in length", c.from, c.to)
			}
			wrap := func(n net.Conn) net.Conn { return &netHelloConn{Conn: n, from: c.from, to: c.to} }
			conn, err := agent.netDialConn(c.from, wrap, func(t *tls.Config) { t.InsecureSkipVerify = true })
			if err == nil {
				conn.Close()
				t.Fatal("the handshake succeeded")
			}
			if c.logged && !netWaitLogHost(t, rig.log, c.to) {
				t.Errorf("no tls-server-name line for %q", c.to)
			}
		})
	}
	t.Run("no server name", func(t *testing.T) {
		raw, err := net.Dial("tcp", agent.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		// An address as ServerName: Go's client then sends no SNI at all.
		c := tls.Client(raw, &tls.Config{ServerName: "10.9.8.7", InsecureSkipVerify: true})
		if c.Handshake() == nil {
			t.Fatal("the handshake succeeded")
		}
		if !netWaitLogHost(t, rig.log, "") {
			t.Error("the refusal was not logged")
		}
	})
	if hits.Load() != 0 {
		t.Errorf("upstream reached %d times", hits.Load())
	}
}

// TestNetHandshakeFragmented splits the ClientHello across many TLS records
// and many TCP writes, as some filters fail to reassemble: the decision is
// the same on the reassembled hello.
func TestNetHandshakeFragmented(t *testing.T) {
	rig, agent, _ := netTLSRig(t)
	for _, f := range []struct {
		name           string
		records, chunk int
	}{
		{"records of 16 bytes", 16, 0},
		{"records of 1 byte", 1, 0},
		{"TCP writes of 1 byte", 0, 1},
		{"both", 7, 3},
	} {
		t.Run(f.name+", allowed", func(t *testing.T) {
			wrap := func(n net.Conn) net.Conn { return &netHelloConn{Conn: n, records: f.records, chunk: f.chunk} }
			c, err := agent.netDialConn(netHost, wrap, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			resp, body, _, err := netExchange(c, bufio.NewReader(c), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\n\r\n")
			if err != nil || resp.StatusCode != 200 || string(body) != "ok "+netHost {
				t.Errorf("%v %v %q", err, resp, body)
			}
		})
		t.Run(f.name+", refused", func(t *testing.T) {
			wrap := func(n net.Conn) net.Conn { return &netHelloConn{Conn: n, records: f.records, chunk: f.chunk} }
			c, err := agent.netDialConn("evil.example", wrap, nil)
			if err == nil {
				c.Close()
				t.Fatal("the handshake succeeded")
			}
			if !netWaitLogHost(t, rig.log, "evil.example") {
				t.Error("not logged")
			}
		})
	}
}

// TestNetHandshakeVersions: TLS 1.0 and 1.1 are refused, 1.2 and 1.3 work.
func TestNetHandshakeVersions(t *testing.T) {
	_, agent, _ := netTLSRig(t)
	for _, v := range []struct {
		name string
		v    uint16
		ok   bool
	}{{"TLS 1.0", tls.VersionTLS10, false}, {"TLS 1.1", tls.VersionTLS11, false}, {"TLS 1.2", tls.VersionTLS12, true}, {"TLS 1.3", tls.VersionTLS13, true}} {
		t.Run(v.name, func(t *testing.T) {
			c, err := agent.netDial(netHost, func(c *tls.Config) { c.MinVersion, c.MaxVersion = v.v, v.v })
			if (err == nil) != v.ok {
				t.Errorf("handshake error %v, want success %v", err, v.ok)
			}
			if err == nil {
				c.Close()
			}
		})
	}
}

// TestNetHandshakeWeakSuites: a client offering only broken or static-RSA
// suites cannot complete a TLS 1.2 handshake.
func TestNetHandshakeWeakSuites(t *testing.T) {
	_, agent, _ := netTLSRig(t)
	for name, suite := range map[string]uint16{
		"RC4 ECDHE-ECDSA":    tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"RC4 static RSA":     tls.TLS_RSA_WITH_RC4_128_SHA,
		"3DES":               tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"3DES ECDHE":         tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"static RSA AES-CBC": tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"static RSA AES-GCM": tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"CBC-SHA256":         tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := agent.netDial(netHost, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12; c.CipherSuites = []uint16{suite} })
			if err == nil {
				t.Errorf("negotiated %s", tls.CipherSuiteName(c.ConnectionState().CipherSuite))
				c.Close()
			}
		})
	}
}

// TestNetALPN: HTTP/2 is never negotiated, whatever the agent offers, and
// a protocol the proxy does not speak ends the handshake.
func TestNetALPN(t *testing.T) {
	_, agent, hits := netTLSRig(t)
	for _, c := range []struct {
		name   string
		protos []string
		ok     bool
	}{
		{"none", nil, true},
		{"http/1.1", []string{"http/1.1"}, true},
		{"h2 first", []string{"h2", "http/1.1"}, true},
		{"h2 only", []string{"h2"}, false},
		{"h2c", []string{"h2c"}, false},
		{"h3", []string{"h3"}, false},
		{"acme-tls/1", []string{"acme-tls/1"}, false},
		{"http/1.0", []string{"http/1.0"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn, err := agent.netDial(netHost, func(cfg *tls.Config) { cfg.NextProtos = c.protos })
			if (err == nil) != c.ok {
				t.Fatalf("handshake error %v, want success %v", err, c.ok)
			}
			if err != nil {
				return
			}
			defer conn.Close()
			if p := conn.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
				t.Errorf("negotiated %q", p)
			}
		})
	}
	t.Run("HTTP/2 preface over HTTP/1.1", func(t *testing.T) {
		conn, err := agent.netDial(netHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		before := hits.Load()
		resp, _, _, err := netExchange(conn, bufio.NewReader(conn), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if err == nil && resp.StatusCode < 400 {
			t.Errorf("status %d", resp.StatusCode)
		}
		if hits.Load() != before {
			t.Error("upstream reached")
		}
	})
}

// netAnyNameCache is a client session cache that offers its one session for
// any server name: what a hostile client does to resume a session made for
// an allowed name under a name no rule allows.
type netAnyNameCache struct {
	mu sync.Mutex
	s  *tls.ClientSessionState
}

func (c *netAnyNameCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s, c.s != nil
}

func (c *netAnyNameCache) Put(_ string, s *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s != nil {
		c.s = s
	}
}

// TestNetResumptionAcrossNames resumes, under the name evil.example, a TLS
// session made for an allowed name. Go's server does not call
// GetCertificate on a resumed handshake, so the name check of certs.get is
// skipped. The spec says the handshake is refused for any name no rule
// allows, and logged. Sources: RFC 8446 section 4.6.1, Apache Traffic
// Server issue 13735, draft-ietf-tls-cross-sni-resumption.
func TestNetResumptionAcrossNames(t *testing.T) {
	for _, v := range []struct {
		name string
		v    uint16
	}{{"TLS 1.3", tls.VersionTLS13}, {"TLS 1.2", tls.VersionTLS12}} {
		t.Run(v.name, func(t *testing.T) {
			rig, agent, hits := netTLSRig(t)
			cache := &netAnyNameCache{}
			edit := func(c *tls.Config) {
				c.ClientSessionCache = cache
				c.InsecureSkipVerify = true // the client's own check of the cached name
				c.MaxVersion = v.v
			}
			first, err := agent.netDial(netHost, edit)
			if err != nil {
				t.Fatal(err)
			}
			resp, _, _, err := netExchange(first, bufio.NewReader(first), "GET /x HTTP/1.1\r\nHost: "+netHost+"\r\nConnection: close\r\n\r\n")
			first.Close()
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("first request: %v %v", err, resp)
			}
			if cache.s == nil {
				t.Skip("the server issued no session ticket")
			}
			before := hits.Load()
			c, err := agent.netDial("evil.example", edit)
			if err == nil {
				defer c.Close()
				t.Errorf("the handshake for evil.example succeeded (resumed: %v)", c.ConnectionState().DidResume)
				if !netWaitLogHost(t, rig.log, "evil.example") {
					t.Error("the handshake for a name no rule allows was not logged")
				}
				br := bufio.NewReader(c)
				for _, host := range []string{"evil.example", netHost} {
					resp, _, _, err := netExchange(c, br, "GET /x HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
					if err == nil && resp.StatusCode != 403 {
						t.Errorf("Host %s on the resumed connection: %d", host, resp.StatusCode)
					}
					if err != nil {
						break
					}
				}
			}
			if hits.Load() != before {
				t.Error("upstream reached from a connection for evil.example")
			}
		})
	}
}

// TestNetHostAgainstServerName: on a connection for one allowed name, a
// request for another allowed name is refused, first or pipelined. Sources:
// Traefik CVE-2026-48491 and CVE-2026-32305, Vercel's firewall.
func TestNetHostAgainstServerName(t *testing.T) {
	rig, agent, hits := netTLSRig(t)
	for _, c := range []struct {
		name, raw string
		want      []int
	}{
		{"other host first", "GET /x HTTP/1.1\r\nHost: " + netOther + "\r\n\r\n", []int{403}},
		{"other host pipelined", "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\nGET /x HTTP/1.1\r\nHost: " + netOther + "\r\n\r\n", []int{200, 403}},
		{"other host on port 443", "GET /x HTTP/1.1\r\nHost: " + netOther + ":443\r\n\r\n", []int{403}},
		{"absolute form for the other host", "GET https://" + netOther + "/x HTTP/1.1\r\nHost: " + netHost + "\r\n\r\n", []int{403}},
		{"no Host", "GET /x HTTP/1.1\r\n\r\n", []int{403}},
		{"two Hosts", "GET /x HTTP/1.1\r\nHost: " + netHost + "\r\nHost: " + netOther + "\r\n\r\n", []int{403}},
		{"empty Host", "GET /x HTTP/1.1\r\nHost:\r\n\r\n", []int{403}},
		{"Host with a userinfo", "GET /x HTTP/1.1\r\nHost: " + netHost + "@" + netOther + "\r\n\r\n", []int{400}},
		{"Host with a trailing dot", "GET /x HTTP/1.1\r\nHost: " + netHost + ".\r\n\r\n", []int{403}},
		{"Host in capitals", "GET /x HTTP/1.1\r\nHost: API.EXAMPLE.COM\r\n\r\n", []int{403}},
		{"Host with port 80", "GET /x HTTP/1.1\r\nHost: " + netHost + ":80\r\n\r\n", []int{403}},
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
			br := bufio.NewReader(conn)
			allowed := int32(0)
			for i, want := range c.want {
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatalf("response %d: %v", i, err)
				}
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != want {
					t.Errorf("response %d: %d %q, want %d", i, resp.StatusCode, body, want)
				}
				if want == 200 {
					allowed++
				}
				if strings.Contains(string(body), netOther) {
					t.Errorf("the other host answered: %q", body)
				}
			}
			if got := hits.Load() - before; got != allowed {
				t.Errorf("upstream reached %d times, want %d", got, allowed)
			}
		})
	}
	_ = rig
}

// TestNetCertsConcurrent mints for one name from many handshakes at once:
// one certificate, no race.
func TestNetCertsConcurrent(t *testing.T) {
	ca := netNewCA(t)
	c, err := newCerts(ca.cert, ca.key, map[string]bool{netHost: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	got := make([]*tls.Certificate, 64)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = c.get(&tls.ClientHelloInfo{ServerName: netHost})
		}()
	}
	wg.Wait()
	for i, cert := range got {
		if cert == nil || cert != got[0] {
			t.Fatalf("handshake %d got another certificate", i)
		}
	}
}

// TestNetCertsLifetime: a leaf never outlives the run's CA, and is valid
// from a minute before it is minted, for clocks slightly behind.
func TestNetCertsLifetime(t *testing.T) {
	ca := netNewCA(t) // valid for one more hour
	c, _ := newCerts(ca.cert, ca.key, map[string]bool{netHost: true})
	cert, err := c.get(&tls.ClientHelloInfo{ServerName: netHost})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.NotAfter.After(ca.cert.NotAfter) {
		t.Errorf("the leaf ends %v, after the CA's %v", cert.Leaf.NotAfter, ca.cert.NotAfter)
	}
	if !cert.Leaf.NotBefore.Before(time.Now()) {
		t.Errorf("the leaf starts %v", cert.Leaf.NotBefore)
	}
	if cert.Leaf.Issuer.CommonName != ca.cert.Subject.CommonName {
		t.Errorf("issued by %v", cert.Leaf.Issuer)
	}
}

// TestNetCertsRefusesWeakCA: a certificate that cannot sign is no CA.
func TestNetCertsRefusesWeakCA(t *testing.T) {
	ca := netNewCA(t)
	leaf := ca.netLeaf(t, nil, netHost)
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	if _, err := newCerts(parsed, ca.key, nil); err == nil {
		t.Error("a leaf accepted as the CA")
	}
	noSign := *ca.cert
	noSign.KeyUsage = x509.KeyUsageDigitalSignature
	if _, err := newCerts(&noSign, ca.key, nil); err == nil {
		t.Error("a CA without certificate signing accepted")
	}
}

// TestNetServeRefusesIPv6Address: the proxy answers DNS with IPv4 only.
func TestNetServeRefusesIPv6Address(t *testing.T) {
	rig := netHTTPRig(t, false, nil, netGet("/x"))
	ca := netNewCA(t)
	for _, a := range []string{"::1", "::ffff:10.9.8.7", "fd00::1"} {
		udp, _ := net.ListenPacket("udp", "127.0.0.1:0")
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		err := rig.p.Serve(udp, ln, ca.cert, ca.key, netip.MustParseAddr(a))
		udp.Close()
		ln.Close()
		if err == nil || errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: %v", a, err)
		}
	}
}
