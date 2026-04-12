// proxyprotocol.go wraps a net.Listener with PROXY protocol v1/v2 support.
package service

import (
	"log/slog"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

// newProxyProtocolListener wraps a net.Listener with PROXY protocol v1/v2 support.
// When trustedCIDRs is empty, all upstream sources are trusted to send PROXY headers.
// When trustedCIDRs is non-empty, only connections from those CIDRs have PROXY headers
// applied; all other connections have the PROXY header ignored.
func newProxyProtocolListener(ln net.Listener, trustedCIDRs []string) net.Listener {
	var policy proxyproto.ConnPolicyFunc

	if len(trustedCIDRs) > 0 {
		nets := make([]*net.IPNet, 0, len(trustedCIDRs))
		for _, cidr := range trustedCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				slog.Warn("invalid PROXY protocol trusted CIDR, skipping", "cidr", cidr, "error", err)
				continue
			}
			nets = append(nets, ipNet)
		}
		policy = func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			tcpAddr, ok := opts.Upstream.(*net.TCPAddr)
			if !ok {
				return proxyproto.IGNORE, nil
			}
			for _, ipNet := range nets {
				if ipNet.Contains(tcpAddr.IP) {
					return proxyproto.USE, nil
				}
			}
			return proxyproto.IGNORE, nil
		}
	} else {
		policy = func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.USE, nil
		}
	}

	return &proxyproto.Listener{
		Listener:   ln,
		ConnPolicy: policy,
	}
}
