package egress

import (
	"fmt"
	"net/netip"
	"syscall"
)

// deniedPrefixes are the address ranges the proxy never connects to: its own
// machine, private networks, the cloud metadata service, and the forms that
// embed or translate them.
var deniedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // this network
		"10.0.0.0/8",      // private
		"100.64.0.0/10",   // carrier-grade NAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, the metadata service
		"172.16.0.0/12",   // private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"192.88.99.0/24",  // 6to4 relay anycast
		"192.168.0.0/16",  // private
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, broadcast
		"::/96",           // unspecified, loopback, IPv4-compatible
		"::ffff:0:0:0/96", // IPv4-translated (SIIT)
		"64:ff9b::/96",    // NAT64
		"64:ff9b:1::/48",  // local NAT64
		"100::/64",        // discard
		"100:0:0:1::/64",  // dummy prefix
		"2001::/23",       // IETF protocol assignments: Teredo, benchmarking, ORCHID
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4
		"3fff::/20",       // documentation
		"5f00::/16",       // segment routing (SRv6) SIDs
		"fc00::/7",        // unique local
		"fec0::/10",       // site-local, deprecated
		"fe80::/10",       // link-local
		"ff00::/8",        // multicast
		"::ffff:0:0/96",   // IPv4-mapped, checked again once unmapped
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// denied reports whether the proxy must refuse to connect to ip.
func denied(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	ip = ip.Unmap()
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// controlDial runs as each upstream connection is made, on the address it is
// actually made to, so no resolver answer given earlier, or changed since,
// can steer it elsewhere.
func controlDial(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("upstream address %q: %w", address, err)
	}
	if denied(ap.Addr()) {
		return &refusal{reasonForbidden, fmt.Errorf("address %s is not a public one", ap.Addr())}
	}
	if ap.Port() != 443 {
		return &refusal{reasonForbidden, fmt.Errorf("port %d", ap.Port())}
	}
	return nil
}
