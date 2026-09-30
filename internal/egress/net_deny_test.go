package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestNetDeniedAddresses holds every address form the dialer can be handed
// for a place the proxy must never reach: private and special ranges, the
// cloud metadata services, and the IPv6 forms that embed or translate them.
// Sources: the IANA special-purpose registries, PayloadsAllTheThings' SSRF
// list, CVE-2024-24790 (mapped addresses in Go), CVE-2026-48782 (IPv6
// transition forms).
func TestNetDeniedAddresses(t *testing.T) {
	for _, c := range []struct{ addr, why string }{
		// IPv4, each range at both ends.
		{"0.0.0.0", "this host, reaches the loopback on Linux"},
		{"0.255.255.255", "this network"},
		{"10.0.0.0", "private"},
		{"10.255.255.255", "private"},
		{"100.64.0.0", "carrier-grade NAT"},
		{"100.127.255.255", "carrier-grade NAT"},
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback, any address of 127/8"},
		{"169.254.0.1", "link-local"},
		{"172.16.0.0", "private"},
		{"172.31.255.255", "private"},
		{"172.17.0.1", "Docker's bridge gateway"},
		{"10.88.0.1", "Podman's bridge gateway"},
		{"192.0.0.1", "IETF protocol assignments"},
		{"192.0.0.170", "NAT64 discovery"},
		{"192.0.2.1", "TEST-NET-1"},
		{"192.168.0.1", "private"},
		{"192.168.255.255", "private"},
		{"198.18.0.1", "benchmarking"},
		{"198.19.255.255", "benchmarking"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"224.0.0.1", "multicast"},
		{"239.255.255.250", "SSDP multicast"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "limited broadcast"},
		// Cloud metadata services.
		{"169.254.169.254", "AWS, GCP, Azure, DigitalOcean, OpenStack, Oracle IMDS"},
		{"169.254.170.2", "AWS ECS task metadata"},
		{"169.254.169.123", "AWS time sync"},
		{"169.254.169.253", "AWS VPC DNS"},
		{"169.254.0.23", "Tencent Cloud metadata"},
		{"100.100.100.200", "Alibaba Cloud metadata"},
		{"192.0.0.192", "Oracle Cloud classic metadata"},
		{"fd00:ec2::254", "AWS IMDS over IPv6"},
		{"fd00:ec2::23", "AWS IPv6 DNS"},
		// IPv6 special addresses.
		{"::", "unspecified"},
		{"::1", "loopback"},
		{"0:0:0:0:0:0:0:1", "loopback, expanded"},
		{"fe80::1", "link-local"},
		{"febf:ffff::1", "link-local, upper end"},
		{"fc00::1", "unique local"},
		{"fdff:ffff::1", "unique local, upper end"},
		{"ff02::1", "multicast, all nodes"},
		{"ff05::1:3", "multicast, DHCP servers"},
		{"2001:db8::1", "documentation"},
		{"100::1", "discard-only"},
		// IPv6 forms embedding the metadata address or the loopback.
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
		{"::ffff:7f00:1", "IPv4-mapped loopback, hex"},
		{"0:0:0:0:0:ffff:a9fe:a9fe", "IPv4-mapped metadata, expanded"},
		{"::ffff:169.254.169.254", "IPv4-mapped metadata"},
		{"::ffff:10.0.0.1", "IPv4-mapped private"},
		{"::ffff:0.0.0.0", "IPv4-mapped this host"},
		{"64:ff9b::a9fe:a9fe", "NAT64 well-known prefix, metadata"},
		{"64:ff9b::127.0.0.1", "NAT64 well-known prefix, loopback"},
		{"64:ff9b::8.8.8.8", "NAT64 of a public address: the translator is local infrastructure"},
		{"64:ff9b:1::a9fe:a9fe", "NAT64 local-use prefix"},
		{"64:ff9b:1:ffff::1", "NAT64 local-use prefix, upper end"},
		{"2002:a9fe:a9fe::1", "6to4 of the metadata address"},
		{"2002:7f00:1::", "6to4 of the loopback"},
		{"2001:0:4136:e378:8000:63bf:56fe:5601", "Teredo, client 169.254.169.254 obfuscated"},
		{"2001::1", "Teredo"},
		// Zones: an address with a zone names an interface, never a public host.
		{"fe80::1%eth0", "link-local with a zone"},
		{"fe80::1%1", "link-local with a numeric zone"},
		{"2606:4700:4700::1111%eth0", "public address with a zone"},
		{"::ffff:1.1.1.1%eth0", "mapped public address with a zone"},
	} {
		t.Run(c.addr, func(t *testing.T) {
			ip, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatal(err)
			}
			if !denied(ip) {
				t.Errorf("%s (%s) is allowed", c.addr, c.why)
			}
		})
	}
	t.Run("the zero Addr", func(t *testing.T) {
		if !denied(netip.Addr{}) {
			t.Error("an invalid address is allowed")
		}
	})
}

// TestNetDeniedGaps holds the special-purpose ranges the deny list does not
// name: each one is not globally reachable per the IANA registries, or
// embeds an IPv4 address the way the forms the spec lists do.
func TestNetDeniedGaps(t *testing.T) {
	for _, c := range []struct{ addr, why string }{
		{"::7f00:1", "IPv4-compatible ::/96 (RFC 4291, deprecated) embedding 127.0.0.1, the bypass of CVE-2026-48782"},
		{"::a9fe:a9fe", "IPv4-compatible ::/96 embedding 169.254.169.254, CVE-2026-48782"},
		{"::ffff:0:a9fe:a9fe", "IPv4-translated ::ffff:0:0:0/96 (RFC 2765 SIIT) embedding the metadata address"},
		{"2001:2::1", "benchmarking 2001:2::/48 (RFC 5180), which the spec says is refused"},
		{"2001:1:ffff::1", "IETF protocol assignments 2001::/23"},
		{"3fff::1", "documentation 3fff::/20 (RFC 9637), which the spec says is refused"},
		{"5f00::1", "SRv6 SIDs 5f00::/16 (RFC 9602), not globally reachable"},
		{"fec0::1", "site-local fec0::/10 (RFC 3879, deprecated), still routed inside some sites"},
		{"100:0:0:1::1", "dummy prefix 100:0:0:1::/64 (RFC 9780), not globally reachable"},
		{"192.88.99.1", "6to4 relay anycast 192.88.99.0/24 (RFC 7526), not globally reachable"},
	} {
		t.Run(c.addr, func(t *testing.T) {
			if !denied(netip.MustParseAddr(c.addr)) {
				t.Errorf("%s is allowed: %s", c.addr, c.why)
			}
		})
	}
}

// TestNetAllowedPublic checks that the deny list is not wider than its
// ranges: the addresses just outside each one, and the services Sealroom
// reaches, stay allowed.
func TestNetAllowedPublic(t *testing.T) {
	for _, s := range []string{
		"1.0.0.0", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0",
		"126.255.255.255", "128.0.0.0", "169.253.255.255", "169.255.0.0",
		"172.15.255.255", "172.32.0.0", "192.0.1.0", "192.0.3.0", "192.167.255.255",
		"192.169.0.0", "198.17.255.255", "198.20.0.0", "198.51.99.255", "198.51.101.0",
		"203.0.112.255", "203.0.114.0", "223.255.255.255",
		"1.1.1.1", "8.8.8.8", "140.82.112.3", "160.79.104.10", "142.250.80.10",
		"::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888",
		"2a00:1450:4001:80b::200e", "2003::1", "2001:200::1", "2620:1ec:c11::200",
	} {
		t.Run(s, func(t *testing.T) {
			if denied(netip.MustParseAddr(s)) {
				t.Errorf("%s is denied", s)
			}
		})
	}
}

// TestNetControlDial drives controlDial with the address strings a dialer
// hands it: always an address and a port, after resolution.
func TestNetControlDial(t *testing.T) {
	for _, a := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443", "[::ffff:1.1.1.1]:443", "140.82.112.3:443"} {
		t.Run("allowed "+a, func(t *testing.T) {
			if err := controlDial("tcp", a, nil); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
	for _, a := range []string{
		"127.0.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "[::ffff:7f00:1]:443",
		"169.254.169.254:443", "[fd00:ec2::254]:443", "100.100.100.200:443",
		"[fe80::1%en0]:443", "[2606:4700:4700::1111%eth0]:443", "0.0.0.0:443", "[::]:443",
		"[64:ff9b::a9fe:a9fe]:443", "[2002:a9fe:a9fe::]:443",
		"1.1.1.1:80", "1.1.1.1:0", "1.1.1.1:8443", "1.1.1.1:22", "[2606:4700:4700::1111]:80",
	} {
		t.Run("refused "+a, func(t *testing.T) {
			err := controlDial("tcp", a, nil)
			var ref *refusal
			if !errors.As(err, &ref) || ref.reason != reasonForbidden {
				t.Errorf("got %v, want a %s refusal", err, reasonForbidden)
			}
		})
	}
	// Anything but an address and a port is an error too: a name never
	// reaches the dialer's Control, and an odd form is never guessed at.
	for _, a := range []string{"localhost:443", "2130706433:443", "0x7f000001:443", "0177.0.0.1:443",
		"127.1:443", "1.1.1.1", "[::1]", "", "1.1.1.1:65536", "1.1.1.1:-1", "1.1.1.1:0x1bb",
		"[1.1.1.1]:443", "::1:443", "1.1.1.1 :443"} {
		t.Run("malformed "+a, func(t *testing.T) {
			if controlDial("tcp", a, nil) == nil {
				t.Errorf("%q accepted", a)
			}
		})
	}
}

// TestNetAddressEncodings feeds the classic SSRF encodings of the loopback
// and the metadata address to Go's address parsers and to the rules: none
// may be read as a public address, and none may be a rule's host. Sources:
// PayloadsAllTheThings, CVE-2021-29923 (leading zeros in Go's net.ParseIP).
func TestNetAddressEncodings(t *testing.T) {
	for _, s := range []string{
		"2130706433", "0x7f000001", "017700000001", "0177.0.0.1", "0177.0000.0000.0001",
		"0x7f.0x0.0x0.0x1", "0x7f.1", "127.1", "127.0.1", "127.000.000.001", "0127.0.0.1",
		"2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "169.254.43518", "0xa9.0xfe.0xa9.0xfe",
		"0", "0.0", "[::1]", "[::ffff:a9fe:a9fe]", "::ffff:169.254.169.254", "fe80::1%25eth0",
		"127.0.0.1.", "1２７.0.0.1", "①②⑦.⓪.⓪.①", "127.0.0.1%00", "127%2e0%2e0%2e1",
		"127.0.0.1:443", "localhost", "LOCALHOST", "169.254.169.254.nip.io.",
	} {
		t.Run(s, func(t *testing.T) {
			if ip, err := netip.ParseAddr(s); err == nil && !denied(ip) {
				t.Errorf("netip reads %q as the public address %s", s, ip)
			}
			if ip := net.ParseIP(s); ip != nil {
				if a, _ := netip.AddrFromSlice(ip); !denied(a.Unmap()) {
					t.Errorf("net.ParseIP reads %q as the public address %s", s, ip)
				}
			}
			r := Rule{Method: "GET", Host: s, Path: "/"}
			if (Config{Placeholder: testPlaceholder, Rules: []Rule{r}}).Validate() == nil {
				t.Errorf("%q accepted as a rule's host", s)
			}
		})
	}
}

// TestNetDialChecksResolvedAddress runs the production dialer: the address
// check is made on the resolved address, before connecting, so the
// listener on the loopback never sees a connection.
func TestNetDialChecksResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	client := upstreamClient(options{control: controlDial})
	for _, u := range []string{
		"https://127.0.0.1:" + port + "/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://localhost/",
		"https://localhost:" + port + "/",
		"https://[::ffff:127.0.0.1]/",
		"https://0.0.0.0/",
	} {
		t.Run(u, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				t.Fatal("connected")
			}
			var ref *refusal
			if !errors.As(err, &ref) || ref.reason != reasonForbidden {
				t.Errorf("got %v, want a %s refusal", err, reasonForbidden)
			}
		})
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the loopback listener accepted %d connections", n)
	}
}

// netRebindDial returns a dial function that sends the n-th connection
// (from zero) to addrs[n], or the last one, checking each with controlDial
// unless it is the trusted test upstream: a resolver whose answers change
// between connections, as in DNS rebinding.
func netRebindDial(trusted string, addrs ...string) func(ctx context.Context, network, address string) (net.Conn, error) {
	var n atomic.Int32
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		i := min(int(n.Add(1))-1, len(addrs)-1)
		d := &net.Dialer{Control: func(nw, a string, c syscall.RawConn) error {
			if a == trusted {
				return nil
			}
			return controlDial(nw, a, c)
		}}
		return d.DialContext(ctx, network, addrs[i])
	}
}

// TestNetRebinding: a rule's host that resolves to a private address, at
// once or only on a later connection, is refused when the connection is
// made, with forbidden-address, and the refusal is logged.
func TestNetRebinding(t *testing.T) {
	ca := netNewCA(t)
	var hits atomic.Int32
	srv := netUpstream(t, ca.netLeaf(t, nil, netHost), false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Connection", "close") // the next request needs a new connection
		io.WriteString(w, "ok")
	}))
	up := srv.Listener.Addr().String()
	for _, c := range []struct {
		name  string
		addrs []string
		want  []int
	}{
		{"loopback at once", []string{"127.0.0.1:443"}, []int{403}},
		{"metadata at once", []string{"169.254.169.254:443"}, []int{403}},
		{"mapped metadata at once", []string{"[::ffff:169.254.169.254]:443"}, []int{403}},
		{"public, then private", []string{up, "10.0.0.1:443"}, []int{200, 403}},
		{"public, then loopback", []string{up, "127.0.0.1:443"}, []int{200, 403}},
	} {
		t.Run(c.name, func(t *testing.T) {
			log := &netLog{}
			p, err := newProxy(Config{Placeholder: testPlaceholder, Rules: []Rule{netGet("/x")}}, Secrets{}, log,
				options{roots: ca.pool, dial: netRebindDial(up, c.addrs...)})
			if err != nil {
				t.Fatal(err)
			}
			defer p.clients[netHost].CloseIdleConnections()
			before := hits.Load()
			for i, want := range c.want {
				w := httptest.NewRecorder()
				p.ServeHTTP(w, agentRequest("GET", "https://"+netHost+"/x", nil))
				if w.Code != want {
					t.Errorf("request %d: %d %q, want %d", i, w.Code, w.Body.String(), want)
				}
				if want == 403 && !strings.Contains(w.Body.String(), reasonForbidden) {
					t.Errorf("request %d: body %q", i, w.Body.String())
				}
			}
			if got, want := hits.Load()-before, int32(strings.Count(fmt.Sprint(c.want), "200")); got != want {
				t.Errorf("upstream reached %d times, want %d", got, want)
			}
			if !strings.Contains(log.String(), `"reason":"`+reasonForbidden+`"`) {
				t.Errorf("no forbidden-address line: %s", log)
			}
		})
	}
}

// TestNetUpstreamAddressIsTheRule: the proxy always asks for the rule's
// host on port 443, whatever port or name the agent's request carries.
func TestNetUpstreamAddressIsTheRule(t *testing.T) {
	rig := netHTTPRig(t, false, func(w http.ResponseWriter, r *http.Request) {}, netGet("/x"))
	for _, host := range []string{netHost, netHost + ":443"} {
		r := agentRequest("GET", "https://"+netHost+"/x", nil)
		r.Host = host
		w := httptest.NewRecorder()
		rig.p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("Host %s: %d", host, w.Code)
		}
	}
	for _, d := range rig.netDials() {
		if d != netHost+":443" {
			t.Errorf("the proxy dialed %q", d)
		}
	}
}
