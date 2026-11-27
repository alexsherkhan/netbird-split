package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// RuntimeInputs is the daemon data a split policy needs. Endpoint fields hold
// URLs or host names; PrivatePrefixes holds overlay and management routes.
type RuntimeInputs struct {
	Options         backend.PolicyOptions
	ManagementURL   string
	SignalURL       string
	RelayURLs       []string
	STUNHosts       []string
	TURNHosts       []string
	PeerEndpoints   []string
	PrivatePrefixes []netip.Prefix
	// PrivateRoutesReady reports that the route manager had produced its first
	// map. An empty route set is still complete; an absent manager is not.
	PrivateRoutesReady bool
	// DNSResolvers are the configured upstream resolvers. DNSReady reports
	// whether the live DNS server is available for observation.
	DNSResolvers []netip.Prefix
	DNSReady     bool
}

// HostResolver resolves a host name to addresses. It is injectable so the
// runtime wiring can be tested without DNS.
type HostResolver func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemResolver is the production host resolver.
func SystemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// BuildWiring turns live daemon inputs into policy constraints and route
// targets. It never fails: unresolvable or missing endpoints leave
// TransportConfigured false and are reported in the returned problem list, so
// the controller refuses a policy whose transport or private routes are not
// yet known instead of applying it with an incomplete safety picture.
func BuildWiring(ctx context.Context, inputs RuntimeInputs, resolve HostResolver) (Wiring, []string) {
	if resolve == nil {
		resolve = SystemResolver
	}

	wiring := Wiring{
		Options:     inputs.Options,
		Constraints: policy.Constraints{},
	}
	wiring.Options.DNSResolvers = normalizePrefixes(inputs.DNSResolvers)

	seen := make(map[netip.Prefix]struct{})
	var problems []string
	addControl := func(prefixes []netip.Prefix) {
		for _, prefix := range prefixes {
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			wiring.Constraints.ControlPrefixes = append(wiring.Constraints.ControlPrefixes, prefix)
		}
	}

	management, missing := resolveEndpoints(ctx, []string{inputs.ManagementURL}, resolve)
	addControl(management)
	if len(management) == 0 {
		problems = append(problems, "management endpoint is not resolved")
	}
	problems = append(problems, missing...)

	signal, missing := resolveEndpoints(ctx, []string{inputs.SignalURL}, resolve)
	addControl(signal)
	if len(signal) == 0 {
		problems = append(problems, "signal endpoint is not resolved")
	}
	problems = append(problems, missing...)

	relay, missing := resolveEndpoints(ctx, inputs.RelayURLs, resolve)
	addControl(relay)
	problems = append(problems, missing...)

	stun, missing := resolveEndpoints(ctx, inputs.STUNHosts, resolve)
	addControl(stun)
	problems = append(problems, missing...)

	turn, missing := resolveEndpoints(ctx, inputs.TURNHosts, resolve)
	addControl(turn)
	problems = append(problems, missing...)

	peers, missing := resolveEndpoints(ctx, inputs.PeerEndpoints, resolve)
	addControl(peers)
	problems = append(problems, missing...)

	if len(relay)+len(stun)+len(turn) == 0 {
		problems = append(problems, "no relay or STUN transport endpoint is configured")
	}
	if !inputs.PrivateRoutesReady {
		problems = append(problems, "private route sources are unavailable")
	}
	if !inputs.DNSReady {
		problems = append(problems, "DNS observation is unavailable")
	}

	wiring.Constraints.PrivatePrefixes = normalizePrefixes(inputs.PrivatePrefixes)
	wiring.TransportConfigured = len(problems) == 0
	wiring.Missing = problems
	return wiring, problems
}

func resolveEndpoints(ctx context.Context, values []string, resolve HostResolver) ([]netip.Prefix, []string) {
	var prefixes []netip.Prefix
	var problems []string
	seen := make(map[netip.Prefix]struct{})
	for _, value := range values {
		host := endpointHost(value)
		if host == "" {
			continue
		}
		addrs, err := resolveHost(ctx, host, resolve)
		if err != nil {
			problems = append(problems, fmt.Sprintf("resolve transport endpoint %q: %v", host, err))
			continue
		}
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.IsValid() {
				continue
			}
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, problems
}

func resolveHost(ctx context.Context, host string, resolve HostResolver) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	return resolve(ctx, host)
}

func endpointHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	if _, rest, ok := strings.Cut(raw, "://"); ok {
		raw = rest
	} else if scheme, rest, ok := strings.Cut(raw, ":"); ok && isTransportScheme(scheme) {
		raw = rest
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return strings.Trim(raw, "[]")
}

func isTransportScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "stun", "stuns", "turn", "turns":
		return true
	default:
		return false
	}
}

func normalizePrefixes(values []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(values))
	out := make([]netip.Prefix, 0, len(values))
	for _, prefix := range values {
		if !prefix.IsValid() {
			continue
		}
		addr := prefix.Addr()
		bits := prefix.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				continue
			}
			addr = addr.Unmap()
			bits -= 96
		} else {
			addr = addr.Unmap()
		}
		prefix = netip.PrefixFrom(addr, bits).Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}
