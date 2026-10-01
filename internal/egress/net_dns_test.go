package egress

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// netAllowed is the allowed set of the DNS tests.
var netAllowed = map[string]bool{netHost: true, netOther: true}

// netDNSPack builds a query; edit, when set, changes the header.
func netDNSPack(t *testing.T, name string, typ dnsmessage.Type, class dnsmessage.Class, edit func(*dnsmessage.Header)) []byte {
	t.Helper()
	h := dnsmessage.Header{ID: 0x1234, RecursionDesired: true}
	if edit != nil {
		edit(&h)
	}
	b := dnsmessage.NewBuilder(nil, h)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: class}); err != nil {
		t.Fatal(err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// netDNSAsk answers query and parses the answer, which must exist.
func netDNSAsk(t *testing.T, query []byte) dnsmessage.Message {
	t.Helper()
	out, ok := dnsAnswer(query, netAllowed, netProxyIP)
	if !ok {
		t.Fatal("no answer")
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatalf("the answer does not parse: %v", err)
	}
	if !m.Header.Response || m.Header.ID != 0x1234 || m.Header.RecursionAvailable || len(m.Authorities) != 0 || len(m.Additionals) != 0 {
		t.Errorf("header or sections %+v", m)
	}
	if len(m.Questions) != 1 {
		t.Errorf("questions %+v", m.Questions)
	}
	return m
}

// TestNetDNSAllowed: an allowed name has one A answer, the proxy's address,
// and no answer of any other type, so no record can carry data in.
func TestNetDNSAllowed(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		m := netDNSAsk(t, netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, nil))
		if m.Header.RCode != dnsmessage.RCodeSuccess || !m.Header.Authoritative || !m.Header.RecursionDesired || len(m.Answers) != 1 {
			t.Fatalf("%+v", m)
		}
		a, ok := m.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || a.A != netProxyIP.As4() || m.Answers[0].Header.TTL != 60 || m.Answers[0].Header.Name.String() != netHost+"." {
			t.Errorf("answer %+v", m.Answers[0])
		}
	})
	t.Run("0x20 case kept in the question", func(t *testing.T) {
		m := netDNSAsk(t, netDNSPack(t, "aPi.ExAmPlE.cOm.", dnsmessage.TypeA, dnsmessage.ClassINET, nil))
		if len(m.Answers) != 1 || m.Questions[0].Name.String() != "aPi.ExAmPlE.cOm." {
			t.Errorf("%+v", m)
		}
	})
	t.Run("recursion not desired", func(t *testing.T) {
		m := netDNSAsk(t, netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.RecursionDesired = false }))
		if len(m.Answers) != 1 || m.Header.RecursionDesired {
			t.Errorf("%+v", m)
		}
	})
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypeCNAME,
		dnsmessage.TypeNS, dnsmessage.TypeSOA, dnsmessage.TypePTR, dnsmessage.TypeSRV, dnsmessage.TypeALL,
		dnsmessage.Type(64) /* SVCB */, dnsmessage.Type(65) /* HTTPS */, dnsmessage.Type(99) /* SPF */} {
		t.Run(typ.String(), func(t *testing.T) {
			m := netDNSAsk(t, netDNSPack(t, netHost+".", typ, dnsmessage.ClassINET, nil))
			if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
				t.Errorf("%+v", m)
			}
		})
	}
}

// TestNetDNSOtherNames: any name not exactly allowed does not exist, however
// close to an allowed one, so DNS can neither reach nor carry anything out.
func TestNetDNSOtherNames(t *testing.T) {
	for _, name := range []string{
		"evil.example.", "x." + netHost + ".", "data-0123456789abcdef.x." + netHost + ".",
		netHost + ".evil.example.", "evilapi.example.com.", "api-example.com.", "example.com.",
		"com.", ".", "localhost.", "metadata.google.internal.", "instance-data.ec2.internal.",
		"254.169.254.169.in-addr.arpa.", "1.0.0.127.in-addr.arpa.", "_acme-challenge." + netHost + ".",
		"xn--pi-example-xyz.com.", "*.example.com.", "api\\.example.com.",
	} {
		t.Run(name, func(t *testing.T) {
			for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeTXT} {
				m := netDNSAsk(t, netDNSPack(t, name, typ, dnsmessage.ClassINET, nil))
				if m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
					t.Errorf("%v: %+v", typ, m)
				}
			}
		})
	}
	// A label holding bytes no hostname has, built on the wire.
	for name, label := range map[string]string{
		"NUL byte":       netHost[:3] + "\x00",
		"newline":        "api\n",
		"high bytes":     "\xd0\xb0pi",
		"space":          "a pi",
		"63-byte label":  string(bytes.Repeat([]byte{'a'}, 63)),
		"escaped quotes": `a"b`,
	} {
		t.Run(name, func(t *testing.T) {
			q := netDNSWire(0, 1, [][]byte{[]byte(label), []byte("example"), []byte("com")}, 1, 1)
			m := netDNSAsk(t, q)
			if m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
				t.Errorf("%+v", m)
			}
		})
	}
}

// netDNSWire builds a query by hand: flags, the question count, the labels
// of the name, its type and class.
func netDNSWire(flags uint16, qdcount uint16, labels [][]byte, typ, class uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, 0x1234)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, qdcount)
	b = append(b, 0, 0, 0, 0, 0, 0)
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, typ)
	return binary.BigEndian.AppendUint16(b, class)
}

// TestNetDNSNotImplemented: other classes and opcodes get no address.
func TestNetDNSNotImplemented(t *testing.T) {
	for name, q := range map[string][]byte{
		"CHAOS version.bind":  netDNSPack(t, "version.bind.", dnsmessage.TypeTXT, dnsmessage.ClassCHAOS, nil),
		"CHAOS allowed name":  netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassCHAOS, nil),
		"HESIOD allowed name": netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassHESIOD, nil),
		"class ANY":           netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassANY, nil),
		"opcode IQUERY":       netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.OpCode = 1 }),
		"opcode STATUS":       netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.OpCode = 2 }),
		"opcode NOTIFY":       netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.OpCode = 4 }),
		"opcode UPDATE":       netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.OpCode = 5 }),
	} {
		t.Run(name, func(t *testing.T) {
			m := netDNSAsk(t, q)
			if m.Header.RCode != dnsmessage.RCodeNotImplemented || len(m.Answers) != 0 {
				t.Errorf("%+v", m)
			}
		})
	}
}

// TestNetDNSMalformed: a packet that is not one well-formed query gets no
// answer at all, and never a panic.
func TestNetDNSMalformed(t *testing.T) {
	valid := netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, nil)
	loop := append([]byte(nil), valid[:12]...)
	loop = append(loop, 0xc0, 12, 0, 1, 0, 1) // a name pointing at itself
	forward := append([]byte(nil), valid[:12]...)
	forward = append(forward, 0xc0, 0x40, 0, 1, 0, 1) // a pointer past the end
	long := [][]byte{}
	for range 5 {
		long = append(long, bytes.Repeat([]byte{'a'}, 63))
	}
	for name, q := range map[string][]byte{
		"empty":                   {},
		"one byte":                {0},
		"short header":            valid[:11],
		"header only":             valid[:12],
		"no question":             netDNSWire(0, 0, nil, 1, 1)[:12],
		"truncated name":          valid[:20],
		"no type or class":        valid[:len(valid)-4],
		"no class":                valid[:len(valid)-2],
		"label past the end":      append(append([]byte(nil), valid[:12]...), 60, 'a', 'b'),
		"pointer loop":            loop,
		"pointer past the end":    forward,
		"reserved label type":     append(append([]byte(nil), valid[:12]...), 0x40, 'a', 0, 0, 1, 0, 1),
		"dot inside a label":      netDNSWire(0, 1, [][]byte{[]byte("api.example"), []byte("com")}, 1, 1),
		"name over 255 bytes":     netDNSWire(0, 1, long, 1, 1),
		"a response":              netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.Response = true }),
		"a response, other name":  netDNSPack(t, "evil.example.", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.Response = true }),
		"question count too high": netDNSWire(0, 2, [][]byte{[]byte("api"), []byte("example"), []byte("com")}, 1, 1)[:12],
	} {
		t.Run(name, func(t *testing.T) {
			if out, ok := dnsAnswer(q, netAllowed, netProxyIP); ok {
				var m dnsmessage.Message
				m.Unpack(out)
				t.Errorf("answered %+v", m)
			}
		})
	}
}

// TestNetDNSOddButValid: queries that parse get one answer to their first
// question only, and nothing they carry besides is echoed.
func TestNetDNSOddButValid(t *testing.T) {
	t.Run("two questions", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234})
		b.StartQuestions()
		b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("evil.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(netHost + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		m := netDNSAsk(t, q)
		if m.Header.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Errorf("%+v", m)
		}
	})
	t.Run("answers, authorities and EDNS in the query", func(t *testing.T) {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234})
		b.StartQuestions()
		name := dnsmessage.MustNewName(netHost + ".")
		b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		b.StartAnswers()
		b.TXTResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, dnsmessage.TXTResource{TXT: []string{"smuggled"}})
		b.StartAdditionals()
		var opt dnsmessage.ResourceHeader
		opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, true)
		b.OPTResource(opt, dnsmessage.OPTResource{})
		q, _ := b.Finish()
		out, ok := dnsAnswer(q, netAllowed, netProxyIP)
		if !ok {
			t.Fatal("no answer")
		}
		if bytes.Contains(out, []byte("smuggled")) {
			t.Error("the query's own records were echoed")
		}
		m := netDNSAsk(t, q)
		if len(m.Answers) != 1 || m.Answers[0].Header.Type != dnsmessage.TypeA {
			t.Errorf("%+v", m)
		}
	})
	t.Run("the answer is never much larger than the query", func(t *testing.T) {
		for _, name := range []string{netHost + ".", "evil.example."} {
			q := netDNSPack(t, name, dnsmessage.TypeA, dnsmessage.ClassINET, nil)
			out, _ := dnsAnswer(q, netAllowed, netProxyIP)
			if len(out) > len(q)+16 {
				t.Errorf("%s: %d bytes for a %d-byte query", name, len(out), len(q))
			}
		}
	})
}

// TestNetDNSRandom sends deterministic random packets, and mutations of a
// valid query: no panic, and any answer holds at most the proxy's address.
func TestNetDNSRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	valid := netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, nil)
	for i := range 20000 {
		var q []byte
		if i%2 == 0 {
			q = make([]byte, rng.IntN(600))
			for j := range q {
				q[j] = byte(rng.Uint32())
			}
		} else {
			q = append([]byte(nil), valid...)
			for range 1 + rng.IntN(4) {
				q[rng.IntN(len(q))] = byte(rng.Uint32())
			}
		}
		out, ok := dnsAnswer(q, netAllowed, netProxyIP)
		if !ok {
			continue
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatalf("answer to %x does not parse: %v", q, err)
		}
		for _, a := range m.Answers {
			if r, ok := a.Body.(*dnsmessage.AResource); !ok || r.A != netProxyIP.As4() {
				t.Fatalf("answer to %x: %+v", q, a)
			}
		}
	}
}

// netDNSClient is a UDP socket that asks the served DNS.
func netDNSClient(t *testing.T, server net.Addr) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// netDNSRead waits up to d for an answer.
func netDNSRead(c net.PacketConn, d time.Duration) ([]byte, bool) {
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(d))
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// TestNetServeDNS runs serveDNS on a real socket: it answers, ignores what
// it must, and keeps answering after floods, oversize datagrams and
// clients that went away.
func TestNetServeDNS(t *testing.T) {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveDNS(srv, netAllowed, netProxyIP); close(done) }()
	t.Cleanup(func() { srv.Close(); <-done })
	query := netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, nil)
	ask := func(t *testing.T, c net.PacketConn) {
		t.Helper()
		if _, err := c.WriteTo(query, srv.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		out, ok := netDNSRead(c, 3*time.Second)
		if !ok {
			t.Fatal("no answer")
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil || len(m.Answers) != 1 {
			t.Fatalf("answer %+v %v", m, err)
		}
	}
	c := netDNSClient(t, srv.LocalAddr())
	t.Run("answers", func(t *testing.T) { ask(t, c) })
	t.Run("no answer to a response", func(t *testing.T) {
		resp := netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, func(h *dnsmessage.Header) { h.Response = true })
		c.WriteTo(resp, srv.LocalAddr())
		if out, ok := netDNSRead(c, 300*time.Millisecond); ok {
			t.Errorf("answered a response: %x", out)
		}
	})
	t.Run("a flood of malformed packets", func(t *testing.T) {
		flood := netDNSClient(t, srv.LocalAddr())
		rng := rand.New(rand.NewPCG(3, 4))
		for range 3000 {
			junk := make([]byte, 3+rng.IntN(100))
			for j := range junk {
				junk[j] = byte(rng.Uint32())
			}
			junk[2] |= 0x80 // marked a response: never answered
			flood.WriteTo(junk, srv.LocalAddr())
		}
		ask(t, c)
	})
	t.Run("an oversize datagram", func(t *testing.T) {
		big := append(append([]byte(nil), query...), make([]byte, 4000)...)
		c.WriteTo(big, srv.LocalAddr())
		netDNSRead(c, 300*time.Millisecond)
		ask(t, c)
	})
	t.Run("a client gone before the answer", func(t *testing.T) {
		gone, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		for range 50 {
			gone.WriteTo(query, srv.LocalAddr())
		}
		gone.Close() // the answers meet a closed port, and ICMP errors
		time.Sleep(100 * time.Millisecond)
		ask(t, c)
	})
}

// TestNetServeDNSThroughServe: Serve answers DNS on its packet socket.
func TestNetServeDNSThroughServe(t *testing.T) {
	rig := netHTTPRig(t, false, nil, netGet("/x"))
	agent := netServe(t, rig.p)
	c := netDNSClient(t, agent.dns)
	c.WriteTo(netDNSPack(t, netHost+".", dnsmessage.TypeA, dnsmessage.ClassINET, nil), agent.dns)
	out, ok := netDNSRead(c, 3*time.Second)
	if !ok {
		t.Fatal("no answer")
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != netProxyIP.As4() {
		t.Errorf("%+v %v", m, err)
	}
	c.WriteTo(netDNSPack(t, "evil.example.", dnsmessage.TypeA, dnsmessage.ClassINET, nil), agent.dns)
	out, _ = netDNSRead(c, 3*time.Second)
	if m.Unpack(out) != nil || m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("%+v", m)
	}
}
