package egress

import (
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAnswer answers one DNS query from the agent. An allowed name resolves to
// the proxy, and only as an IPv4 address; any other name does not exist. No
// query is ever forwarded, so DNS carries nothing out.
func dnsAnswer(query []byte, allowed map[string]bool, proxy netip.Addr) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	resp := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RCode: dnsmessage.RCodeSuccess}
	// Names are compared lowercased, without the root dot DNS always carries.
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	switch {
	case q.Class != dnsmessage.ClassINET || h.OpCode != 0:
		resp.RCode = dnsmessage.RCodeNotImplemented
	case !allowed[name]:
		resp.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 128), resp)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil, false
	}
	if resp.RCode == dnsmessage.RCodeSuccess && q.Type == dnsmessage.TypeA {
		if b.StartAnswers() != nil ||
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: proxy.As4()}) != nil {
			return nil, false
		}
	}
	out, err := b.Finish()
	return out, err == nil
}

// serveDNS answers the agent's DNS queries over UDP until conn is closed.
func serveDNS(conn net.PacketConn, allowed map[string]bool, proxy netip.Addr) {
	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if out, ok := dnsAnswer(buf[:n], allowed, proxy); ok {
			conn.WriteTo(out, addr)
		}
	}
}
