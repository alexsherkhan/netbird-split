//go:build linux && !android

package linux

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// maxPolicyConjunctions bounds a disjunctive-normal-form expansion so a
// pathological any/all tree cannot explode the classification rule count.
const maxPolicyConjunctions = 4096

// bypassPrefixes are IPv4 destinations that must never be rerouted by split
// classification: loopback, link-local, multicast and the limited broadcast.
var bypassPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// bypassPrefixes6 are the IPv6 equivalents. Link-local and multicast traffic
// carries neighbor discovery, so it must not be marked or dropped.
var bypassPrefixes6 = []netip.Prefix{
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type policyPlan struct {
	nft   nftPolicy
	route routePlan
}

func compilePolicy(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	allocations allocations,
) (*policyPlan, error) {
	enableIPv6 := compiled != nil && compiled.IPv6
	return compilePolicyFor(compiled, options, allocations, enableIPv6)
}

func compilePolicyFor(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	allocations allocations,
	enableIPv6 bool,
) (*policyPlan, error) {
	if compiled == nil {
		return nil, fmt.Errorf("%w: compiled policy is nil", backend.ErrInvalidPolicyOption)
	}
	if !compiled.Enabled {
		return &policyPlan{}, nil
	}
	if compiled.KillSwitch != "" && compiled.KillSwitch != config.KillSwitchDisabled {
		return nil, fmt.Errorf("kill switch mode %q: %w",
			compiled.KillSwitch, backend.ErrNotImplemented)
	}
	if compiled.DNS.TrackingEnabled {
		return nil, fmt.Errorf("DNS tracking: %w", backend.ErrNotImplemented)
	}

	sets := make(map[setName][]netip.Prefix, len(policySetNames()))
	used4 := make(map[routeClass]bool, len(splitClasses))
	used6 := make(map[routeClass]bool, len(splitClasses))
	var rules []nftRule

	for _, prefix := range bypassPrefixes {
		rules = append(rules, nftRule{
			family:  family4,
			matches: []nftMatch{{prefix: prefix}},
			bypass:  true,
		})
	}
	if enableIPv6 {
		for _, prefix := range bypassPrefixes6 {
			rules = append(rules, nftRule{
				family:  family6,
				matches: []nftMatch{{prefix: prefix}},
				bypass:  true,
			})
		}
	}

	controlRules, control4, control6, err := compileConstraints(
		compiled.Control, allocations, enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("compile control prefixes: %w", err)
	}
	rules = append(rules, controlRules...)
	addPrefixes(sets, classDirect, family4, control4)
	markUsed(used4, classDirect, controlRules, family4)
	if enableIPv6 {
		addPrefixes(sets, classDirect, family6, control6)
		markUsed(used6, classDirect, controlRules, family6)
	}

	mandatoryRules, mandatory4, mandatory6, err := compileConstraints(
		compiled.Mandatory, allocations, enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("compile mandatory prefixes: %w", err)
	}
	rules = append(rules, mandatoryRules...)
	addPrefixes(sets, classVPN, family4, mandatory4)
	markUsed(used4, classVPN, mandatoryRules, family4)
	if enableIPv6 {
		addPrefixes(sets, classVPN, family6, mandatory6)
		markUsed(used6, classVPN, mandatoryRules, family6)
	}

	for _, blockRule := range compiled.BlockRules {
		compiledRules, prefixes4, prefixes6, err := compileCompiledRule(
			blockRule, classBlock, allocations, enableIPv6)
		if err != nil {
			return nil, fmt.Errorf("compile block rule %q: %w", blockRule.ID, err)
		}
		rules = append(rules, compiledRules...)
		addPrefixes(sets, classBlock, family4, prefixes4)
		addPrefixes(sets, classBlock, family6, prefixes6)
		markUsed(used4, classBlock, compiledRules, family4)
		if enableIPv6 {
			markUsed(used6, classBlock, compiledRules, family6)
		}
	}

	for _, userRule := range compiled.Rules {
		class, ok := classForAction(userRule.Action)
		if !ok {
			return nil, fmt.Errorf("rule %q: unsupported action %q", userRule.ID, userRule.Action)
		}
		compiledRules, prefixes4, prefixes6, err := compileCompiledRule(
			userRule, class, allocations, enableIPv6)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", userRule.ID, err)
		}
		rules = append(rules, compiledRules...)
		addPrefixes(sets, class, family4, prefixes4)
		addPrefixes(sets, class, family6, prefixes6)
		markUsed(used4, class, compiledRules, family4)
		if enableIPv6 {
			markUsed(used6, class, compiledRules, family6)
		}
	}

	defaultClass, ok := classForAction(compiled.DefaultAction)
	if !ok {
		return nil, fmt.Errorf("unsupported default action %q", compiled.DefaultAction)
	}
	allocation, ok := allocations.get(defaultClass)
	if !ok {
		return nil, fmt.Errorf("no allocation for class %q", defaultClass)
	}
	rules = append(rules, nftRule{family: family4, mark: allocation.mark.Value})
	used4[defaultClass] = true
	if enableIPv6 {
		rules = append(rules, nftRule{family: family6, mark: allocation.mark.Value})
		used6[defaultClass] = true
	}

	routeClasses4, err := compileRoutePlan(
		compiled, options, allocations, used4, family4)
	if err != nil {
		return nil, err
	}
	var routeClasses6 []classRoute
	if enableIPv6 {
		routeClasses6, err = compileRoutePlan(
			compiled, options, allocations, used6, family6)
		if err != nil {
			return nil, err
		}
	}

	return &policyPlan{
		nft: nftPolicy{
			sets:  normalizeSetPrefixes(sets),
			rules: rules,
		},
		route: routePlan{classes: routeClasses4, classes6: routeClasses6},
	}, nil
}

func markUsed(used map[routeClass]bool, class routeClass, rules []nftRule, family nftFamily) {
	for _, rule := range rules {
		if rule.family == family {
			used[class] = true
			return
		}
	}
}

func compileConstraints(
	prefixes []policy.PrefixRule,
	allocations allocations,
	enableIPv6 bool,
) ([]nftRule, []netip.Prefix, []netip.Prefix, error) {
	rules := make([]nftRule, 0, len(prefixes))
	var compiled4 []netip.Prefix
	var compiled6 []netip.Prefix
	for _, prefixRule := range prefixes {
		if err := validateCIDRPrefix(prefixRule.Prefix); err != nil {
			return nil, nil, nil, err
		}
		family := familyOfPrefix(prefixRule.Prefix)
		if family == family6 && !enableIPv6 {
			continue
		}
		class, ok := classForAction(prefixRule.Action)
		if !ok {
			return nil, nil, nil, fmt.Errorf("unsupported constraint action %q", prefixRule.Action)
		}
		allocation, ok := allocations.get(class)
		if !ok {
			return nil, nil, nil, fmt.Errorf("no allocation for class %q", class)
		}
		rules = append(rules, nftRule{
			family:  family,
			matches: []nftMatch{{prefix: prefixRule.Prefix}},
			mark:    allocation.mark.Value,
		})
		if family == family6 {
			compiled6 = append(compiled6, prefixRule.Prefix)
			continue
		}
		compiled4 = append(compiled4, prefixRule.Prefix)
	}
	return rules, compiled4, compiled6, nil
}

func compileCompiledRule(
	rule policy.CompiledRule,
	class routeClass,
	allocations allocations,
	enableIPv6 bool,
) ([]nftRule, []netip.Prefix, []netip.Prefix, error) {
	allocation, ok := allocations.get(class)
	if !ok {
		return nil, nil, nil, fmt.Errorf("no allocation for class %q", class)
	}

	conjunctions, err := ruleConjunctions(rule)
	if err != nil {
		return nil, nil, nil, err
	}

	var rules []nftRule
	var prefixes4 []netip.Prefix
	var prefixes6 []netip.Prefix
	for _, conjunction := range conjunctions {
		prefixes, hasProtocol, err := classifyConjunction(conjunction)
		if err != nil {
			return nil, nil, nil, err
		}
		families, err := conjunctionFamilies(prefixes, hasProtocol, enableIPv6)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, family := range families {
			familyPrefixes := prefixesOfFamily(prefixes, family)
			matches, err := conjunctionMatches(
				class, family, familyPrefixes, conjunction, hasProtocol)
			if err != nil {
				return nil, nil, nil, err
			}
			if !hasProtocol {
				if family == family6 {
					prefixes6 = append(prefixes6, familyPrefixes...)
				} else {
					prefixes4 = append(prefixes4, familyPrefixes...)
				}
			}
			rules = append(rules, nftRule{
				family:  family,
				matches: matches,
				mark:    allocation.mark.Value,
			})
		}
	}
	return rules, prefixes4, prefixes6, nil
}

// conjunctionFamilies selects the address families a conjunction can match. A
// conjunction mixing IPv4 and IPv6 CIDRs is unsatisfiable, because one packet
// has a single family, so it is rejected instead of silently widening a rule.
// When IPv6 is disabled, IPv6-only and mixed conjunctions are skipped so the
// IPv4 path is unaffected.
func conjunctionFamilies(
	prefixes []netip.Prefix,
	hasProtocol bool,
	enableIPv6 bool,
) ([]nftFamily, error) {
	var has4, has6 bool
	for _, prefix := range prefixes {
		if familyOfPrefix(prefix) == family6 {
			has6 = true
			continue
		}
		has4 = true
	}

	switch {
	case has4 && has6:
		if !enableIPv6 {
			return []nftFamily{}, nil
		}
		return nil, fmt.Errorf(
			"match-all conjunction mixes IPv4 and IPv6 CIDRs: %w", backend.ErrUnsupportedCondition)
	case has6:
		if !enableIPv6 {
			return []nftFamily{}, nil
		}
		return []nftFamily{family6}, nil
	case has4:
		return []nftFamily{family4}, nil
	case !hasProtocol:
		return []nftFamily{}, nil
	case enableIPv6:
		return []nftFamily{family4, family6}, nil
	default:
		return []nftFamily{family4}, nil
	}
}

func conjunctionMatches(
	class routeClass,
	family nftFamily,
	prefixes []netip.Prefix,
	conjunction []config.Condition,
	hasProtocol bool,
) ([]nftMatch, error) {
	if !hasProtocol && len(prefixes) > 0 {
		set := setForClassFamily(class, family)
		if set == "" {
			return nil, fmt.Errorf("no prefix set for class %q family %v", class, family)
		}
		return []nftMatch{{set: set}}, nil
	}

	matches := make([]nftMatch, 0, len(prefixes)+1)
	for _, prefix := range prefixes {
		matches = append(matches, nftMatch{prefix: prefix})
	}
	for _, condition := range conjunction {
		if condition.Type != config.ConditionProtocolPort {
			continue
		}
		matches = append(matches, nftMatch{
			protocol: condition.Protocol,
			port:     condition.Port,
		})
	}
	return matches, nil
}

func prefixesOfFamily(prefixes []netip.Prefix, family nftFamily) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if familyOfPrefix(prefix) == family {
			out = append(out, prefix)
		}
	}
	return out
}

func classifyConjunction(conjunction []config.Condition) ([]netip.Prefix, bool, error) {
	var prefixes []netip.Prefix
	hasProtocol := false
	for _, condition := range conjunction {
		switch condition.Type {
		case config.ConditionCIDR:
			if err := validateCIDRPrefix(condition.Prefix); err != nil {
				return nil, false, err
			}
			prefixes = append(prefixes, condition.Prefix)
		case config.ConditionProtocolPort:
			if err := validateProtocolPort(condition.Protocol, condition.Port); err != nil {
				return nil, false, err
			}
			hasProtocol = true
		default:
			return nil, false, &backend.UnsupportedConditionError{
				Condition: condition.Type,
				Reason:    "condition is not implemented for split tunnel policy enforcement",
			}
		}
	}
	return prefixes, hasProtocol, nil
}

func ruleConjunctions(rule policy.CompiledRule) ([][]config.Condition, error) {
	mode := rule.MatchMode
	if mode == "" {
		mode = config.MatchAll
	}

	root := config.Condition{Type: config.ConditionAll, Children: rule.Conditions}
	if mode == config.MatchAny {
		root.Type = config.ConditionAny
	}
	return conditionConjunctions(&root, 0)
}

func conditionConjunctions(condition *config.Condition, count int) ([][]config.Condition, error) {
	if count > maxPolicyConjunctions {
		return nil, fmt.Errorf("policy expands to more than %d classification rules",
			maxPolicyConjunctions)
	}

	switch condition.Type {
	case config.ConditionAll:
		result := [][]config.Condition{{}}
		for i := range condition.Children {
			child, err := conditionConjunctions(&condition.Children[i], count)
			if err != nil {
				return nil, err
			}
			result = crossProduct(result, child)
			count = len(result)
			if count > maxPolicyConjunctions {
				return nil, fmt.Errorf("policy expands to more than %d classification rules",
					maxPolicyConjunctions)
			}
		}
		return result, nil
	case config.ConditionAny:
		var result [][]config.Condition
		for i := range condition.Children {
			child, err := conditionConjunctions(&condition.Children[i], count)
			if err != nil {
				return nil, err
			}
			result = append(result, child...)
			if len(result) > maxPolicyConjunctions {
				return nil, fmt.Errorf("policy expands to more than %d classification rules",
					maxPolicyConjunctions)
			}
		}
		return result, nil
	case config.ConditionCIDR:
		if err := validateCIDRPrefix(condition.Prefix); err != nil {
			return nil, err
		}
		return [][]config.Condition{{{Type: condition.Type, Prefix: condition.Prefix}}}, nil
	case config.ConditionProtocolPort:
		if err := validateProtocolPort(condition.Protocol, condition.Port); err != nil {
			return nil, err
		}
		return [][]config.Condition{{
			{Type: condition.Type, Protocol: condition.Protocol, Port: condition.Port},
		}}, nil
	default:
		return nil, &backend.UnsupportedConditionError{
			Condition: condition.Type,
			Reason:    "condition is not implemented for split tunnel policy enforcement",
		}
	}
}

func crossProduct(left, right [][]config.Condition) [][]config.Condition {
	result := make([][]config.Condition, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			merged := make([]config.Condition, 0, len(a)+len(b))
			merged = append(merged, a...)
			merged = append(merged, b...)
			result = append(result, merged)
		}
	}
	return result
}

func validateCIDRPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid CIDR: %w", backend.ErrUnsupportedCondition)
	}
	if prefix.Addr().Zone() != "" {
		return fmt.Errorf("CIDR must not contain a zone: %w", backend.ErrUnsupportedCondition)
	}
	if prefix.Addr().Is4In6() {
		return fmt.Errorf("CIDR must use a plain IP address: %w", backend.ErrUnsupportedCondition)
	}
	if prefix.Masked() != prefix {
		return fmt.Errorf("CIDR has host bits set: %w", backend.ErrUnsupportedCondition)
	}
	return nil
}

func validateProtocolPort(protocol config.Protocol, port uint16) error {
	if protocol != config.ProtocolTCP && protocol != config.ProtocolUDP {
		return &backend.UnsupportedConditionError{
			Condition: config.ConditionProtocolPort,
			Reason:    fmt.Sprintf("protocol %q is not implemented", protocol),
		}
	}
	if port == 0 {
		return fmt.Errorf("protocol port must be between 1 and 65535: %w",
			backend.ErrUnsupportedCondition)
	}
	return nil
}

func familyOfPrefix(prefix netip.Prefix) nftFamily {
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return family6
	}
	return family4
}

func addPrefixes(sets map[setName][]netip.Prefix, class routeClass, family nftFamily, prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}
	set := setForClassFamily(class, family)
	if set == "" {
		return
	}
	sets[set] = append(sets[set], prefixes...)
}

func normalizeSetPrefixes(sets map[setName][]netip.Prefix) map[setName][]netip.Prefix {
	normalized := make(map[setName][]netip.Prefix, len(sets))
	for name, prefixes := range sets {
		normalized[name] = normalizePrefixes(prefixes)
	}
	return normalized
}

func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}

	unique := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		unique[prefix.Masked()] = struct{}{}
	}

	list := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		list = append(list, prefix)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Bits() != list[j].Bits() {
			return list[i].Bits() < list[j].Bits()
		}
		return list[i].Addr().Less(list[j].Addr())
	})

	result := make([]netip.Prefix, 0, len(list))
	for _, prefix := range list {
		covered := false
		for _, existing := range result {
			if existing.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, prefix)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})
	return result
}

func compileRoutePlan(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	allocations allocations,
	used map[routeClass]bool,
	family nftFamily,
) ([]classRoute, error) {
	var routeClasses []classRoute
	for _, class := range splitClasses {
		if !used[class] {
			continue
		}
		allocation, ok := allocations.get(class)
		if !ok {
			return nil, fmt.Errorf("no allocation for class %q", class)
		}

		switch class {
		case classBlock:
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				family:     routeFamilyOf(family),
				blackhole:  true,
				protected:  true,
			})
		case classVPN:
			target, err := vpnTarget(options, family)
			if err != nil {
				return nil, err
			}
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				family:     routeFamilyOf(family),
				target:     target,
				protected:  true,
			})
		case classDirect:
			target, err := directTarget(options, family)
			if err != nil {
				return nil, err
			}
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				family:     routeFamilyOf(family),
				target:     target,
			})
		case classExit:
			classRoute, err := exitRoute(compiled, options, allocation, family)
			if err != nil {
				return nil, err
			}
			routeClasses = append(routeClasses, classRoute)
		default:
			return nil, fmt.Errorf("unsupported route class %q", class)
		}
	}
	return routeClasses, nil
}

func vpnTarget(options backend.PolicyOptions, family nftFamily) (backend.RouteTarget, error) {
	if family == family6 {
		target, present, err := resolveTarget6(options.VPN6, "vpn6")
		if err != nil {
			return backend.RouteTarget{}, err
		}
		if !present {
			return backend.RouteTarget{}, nil
		}
		return backend.RouteTarget(target), nil
	}
	if err := options.VPN.Validate(); err != nil {
		return backend.RouteTarget{}, fmt.Errorf("%w: vpn target: %w", backend.ErrInvalidPolicyOption, err)
	}
	return options.VPN, nil
}

func directTarget(options backend.PolicyOptions, family nftFamily) (backend.RouteTarget, error) {
	if family == family6 {
		target, present, err := resolveTarget6(options.Direct6, "direct6")
		if err != nil {
			return backend.RouteTarget{}, err
		}
		if !present {
			return backend.RouteTarget{}, fmt.Errorf(
				"%w: direct6 target is required when IPv6 direct routing is enabled",
				backend.ErrInvalidPolicyOption)
		}
		return backend.RouteTarget(target), nil
	}
	if err := options.Direct.Validate(); err != nil {
		return backend.RouteTarget{}, fmt.Errorf("%w: direct target: %w", backend.ErrInvalidPolicyOption, err)
	}
	return options.Direct, nil
}

func resolveTarget6(target backend.RouteTarget6, name string) (backend.RouteTarget6, bool, error) {
	if target.Interface == "" {
		if target.IsZero() {
			return backend.RouteTarget6{}, false, nil
		}
		return backend.RouteTarget6{}, false, fmt.Errorf(
			"%w: %s target: interface is empty", backend.ErrInvalidPolicyOption, name)
	}
	if err := target.Validate(); err != nil {
		return backend.RouteTarget6{}, false, fmt.Errorf(
			"%w: %s target: %w", backend.ErrInvalidPolicyOption, name, err)
	}
	return target, true, nil
}

func exitRoute(
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
	allocation classAllocation,
	family nftFamily,
) (classRoute, error) {
	if options.ExitNode == nil {
		return classRoute{
			class:      classExit,
			allocation: allocation,
			family:     routeFamilyOf(family),
			protected:  true,
		}, nil
	}
	if options.ExitNode.ID == "" {
		return classRoute{}, fmt.Errorf("%w: exit node ID is empty",
			backend.ErrInvalidPolicyOption)
	}
	if family == family4 {
		if err := options.ExitNode.Validate(); err != nil {
			return classRoute{}, fmt.Errorf("%w: exit node target: %w",
				backend.ErrInvalidPolicyOption, err)
		}
	}
	for _, rule := range compiled.Rules {
		if rule.Action != config.ActionExitNode || rule.ExitNodeID == "" {
			continue
		}
		if rule.ExitNodeID != options.ExitNode.ID {
			return classRoute{}, &backend.ExitNodeUnavailableError{
				Requested: rule.ExitNodeID,
				Active:    options.ExitNode.ID,
			}
		}
	}

	route := classRoute{
		class:      classExit,
		allocation: allocation,
		family:     routeFamilyOf(family),
		protected:  true,
	}
	if family == family6 {
		if options.ExitNode.Target6 == nil {
			return route, nil
		}
		if err := options.ExitNode.Target6.Validate(); err != nil {
			return classRoute{}, fmt.Errorf("%w: exit node IPv6 target: %w",
				backend.ErrInvalidPolicyOption, err)
		}
		route.target = backend.RouteTarget(*options.ExitNode.Target6)
		return route, nil
	}

	route.target = options.ExitNode.Target
	return route, nil
}
