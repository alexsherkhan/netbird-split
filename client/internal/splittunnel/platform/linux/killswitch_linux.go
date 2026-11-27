//go:build linux && !android

package linux

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// The kill switch runs in the owned killswitch chain after classification, so
// it can match the mark the route chain already set. It never inspects the
// outgoing interface: a route-type output hook changes the egress route after
// the output hook, and the kernel keeps reporting the original interface
// through meta oif/oifname. Protection therefore relies on two invariants:
//
//   - Traffic marked VPN or exit is routed through a protected table that has
//     an unreachable default, so a missing or down target cannot fall through
//     to the physical gateway. M04 applies that table and M09 reconciles it.
//   - A destination selected for VPN, exit or block is dropped when it is not
//     allowed to leave, so losing classification rules cannot leak it.
//
// Mode behavior:
//
//   - disabled: the chain is empty and policy routing alone applies.
//   - selective: VPN and exit traffic and their destination sets are blocked
//     unless they carry the protected mark; DIRECT and unmatched traffic is
//     untouched.
//   - global: only loopback/local traffic, control and transport prefixes,
//     configured DNS resolvers, and protected marks may leave. Every other
//     egress is dropped, so a physical path is never used for protected
//     traffic. Direct destinations are intentionally not exempt.
//   - strict: global plus explicitly configured DIRECT prefixes and resolved
//     DIRECT domains. A DIRECT default action is not an explicit grant.
//
// The kernel cannot observe tunnel liveness by itself, so global and strict
// treat any non-exempt egress as a failed protected path. Allowing physical
// DIRECT traffic only while the tunnel is up would require the daemon and boot
// integration to toggle a gate, which is not wired yet.

type nftVerdict uint8

const (
	verdictReturn nftVerdict = iota
	verdictAccept
	verdictDrop
)

// nftKillRule is one ordered rule in the owned killswitch chain.
type nftKillRule struct {
	family  nftFamily
	mark    *uint32
	matches []nftMatch
	verdict nftVerdict
}

func compileKillSwitch(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	allocations allocations,
	enableIPv6 bool,
) ([]nftKillRule, map[setName][]netip.Prefix, error) {
	if compiled == nil {
		return nil, nil, fmt.Errorf("%w: compiled policy is nil", backend.ErrInvalidPolicyOption)
	}
	if !compiled.Enabled {
		return nil, nil, nil
	}

	mode := compiled.KillSwitch
	if mode == "" {
		mode = config.KillSwitchDisabled
	}
	switch mode {
	case config.KillSwitchDisabled:
		return nil, nil, nil
	case config.KillSwitchSelective, config.KillSwitchGlobal, config.KillSwitchStrict:
	default:
		return nil, nil, fmt.Errorf("unsupported kill switch mode %q: %w",
			mode, backend.ErrInvalidPolicyOption)
	}

	control, err := compileKillSwitchControl(compiled.Control, enableIPv6)
	if err != nil {
		return nil, nil, err
	}
	dns, err := compileKillSwitchDNS(options.DNSResolvers, enableIPv6)
	if err != nil {
		return nil, nil, err
	}

	var rules []nftKillRule
	rules = append(rules,
		compileKillSwitchFamily(mode, family4, control[family4], dns[family4], allocations)...)
	if enableIPv6 {
		rules = append(rules,
			compileKillSwitchFamily(mode, family6, control[family6], dns[family6], allocations)...)
	}

	sets := make(map[setName][]netip.Prefix, 2)
	if prefixes := control[family4]; len(prefixes) > 0 {
		sets[setKillSwitchControl4] = prefixes
	}
	if prefixes := control[family6]; len(prefixes) > 0 {
		sets[setKillSwitchControl6] = prefixes
	}
	return rules, normalizeSetPrefixes(sets), nil
}

func compileKillSwitchControl(
	constraints []policy.PrefixRule,
	enableIPv6 bool,
) (map[nftFamily][]netip.Prefix, error) {
	byFamily := make(map[nftFamily][]netip.Prefix, 2)
	for i, constraint := range constraints {
		if err := validateCIDRPrefix(constraint.Prefix); err != nil {
			return nil, fmt.Errorf("%w: kill switch control prefix %d: %w",
				backend.ErrInvalidPolicyOption, i, err)
		}
		family := familyOfPrefix(constraint.Prefix)
		if family == family6 && !enableIPv6 {
			continue
		}
		byFamily[family] = append(byFamily[family], constraint.Prefix)
	}
	return byFamily, nil
}

func compileKillSwitchDNS(
	resolvers []netip.Prefix,
	enableIPv6 bool,
) (map[nftFamily][]netip.Prefix, error) {
	byFamily := make(map[nftFamily][]netip.Prefix, 2)
	for i, resolver := range resolvers {
		if err := validateCIDRPrefix(resolver); err != nil {
			return nil, fmt.Errorf("%w: kill switch DNS resolver %d: %w",
				backend.ErrInvalidPolicyOption, i, err)
		}
		family := familyOfPrefix(resolver)
		if family == family6 && !enableIPv6 {
			continue
		}
		byFamily[family] = append(byFamily[family], resolver)
	}
	return byFamily, nil
}

func compileKillSwitchFamily(
	mode config.KillSwitchMode,
	family nftFamily,
	control []netip.Prefix,
	dns []netip.Prefix,
	allocations allocations,
) []nftKillRule {
	var rules []nftKillRule

	add := func(rule nftKillRule) {
		rule.family = family
		rules = append(rules, rule)
	}
	acceptPrefixes := func(prefixes []netip.Prefix) {
		for _, prefix := range prefixes {
			add(nftKillRule{matches: []nftMatch{{prefix: prefix}}, verdict: verdictAccept})
		}
	}

	// Loopback, link-local and multicast are not Internet egress. They are
	// needed for neighbor discovery and local services even while protection
	// is active, and none of them can reach the physical gateway.
	acceptPrefixes(localKillSwitchPrefixes(family))

	// Marked protected traffic is routed through a protected table that fails
	// closed, so the kill switch lets it reach that table.
	for _, class := range []routeClass{classVPN, classExit} {
		allocation, ok := allocations.get(class)
		if !ok {
			continue
		}
		mark := allocation.mark.Value
		add(nftKillRule{mark: &mark, verdict: verdictAccept})
	}

	switch mode {
	case config.KillSwitchSelective:
		for _, set := range killSwitchDropSets(family) {
			add(nftKillRule{matches: []nftMatch{{set: set}}, verdict: verdictDrop})
		}
	case config.KillSwitchGlobal:
		add(nftKillRule{
			matches: []nftMatch{{set: killSwitchControlSet(family)}},
			verdict: verdictAccept,
		})
		addDNSKillSwitchRules(add, dns)
		add(nftKillRule{verdict: verdictDrop})
	case config.KillSwitchStrict:
		add(nftKillRule{
			matches: []nftMatch{{set: killSwitchControlSet(family)}},
			verdict: verdictAccept,
		})
		add(nftKillRule{
			matches: []nftMatch{{set: setForClassFamily(classDirect, family)}},
			verdict: verdictAccept,
		})
		add(nftKillRule{
			matches: []nftMatch{{set: domainSetForClassFamily(classDirect, family)}},
			verdict: verdictAccept,
		})
		addDNSKillSwitchRules(add, dns)
		add(nftKillRule{verdict: verdictDrop})
	}
	return rules
}

func addDNSKillSwitchRules(add func(nftKillRule), resolvers []netip.Prefix) {
	for _, resolver := range resolvers {
		for _, protocol := range []config.Protocol{config.ProtocolUDP, config.ProtocolTCP} {
			add(nftKillRule{
				matches: []nftMatch{{
					prefix:   resolver,
					protocol: protocol,
					port:     53,
				}},
				verdict: verdictAccept,
			})
		}
	}
}

func killSwitchControlSet(family nftFamily) setName {
	if family == family6 {
		return setKillSwitchControl6
	}
	return setKillSwitchControl4
}

func domainSetForClassFamily(class routeClass, family nftFamily) setName {
	set, ok := domainSetFor(class, family)
	if !ok {
		return ""
	}
	return set
}

func killSwitchDropSets(family nftFamily) []setName {
	return []setName{
		setForClassFamily(classVPN, family),
		setForClassFamily(classExit, family),
		setForClassFamily(classBlock, family),
		domainSetForClassFamily(classVPN, family),
		domainSetForClassFamily(classBlock, family),
	}
}

func localKillSwitchPrefixes(family nftFamily) []netip.Prefix {
	if family == family6 {
		return bypassPrefixes6
	}
	return bypassPrefixes
}
