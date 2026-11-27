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

// bypassPrefixes are destinations that must never be rerouted by split
// classification: loopback, link-local, multicast and the limited broadcast.
// Without these a catch-all default action would send local traffic to a
// physical or overlay egress path.
var bypassPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
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
	if compiled == nil {
		return nil, fmt.Errorf("%w: compiled policy is nil", backend.ErrInvalidPolicyOption)
	}
	if !compiled.Enabled {
		return &policyPlan{}, nil
	}
	if compiled.IPv6 {
		return nil, fmt.Errorf("compiled policy enables IPv6: %w", backend.ErrIPv6Unsupported)
	}
	if compiled.KillSwitch != "" && compiled.KillSwitch != config.KillSwitchDisabled {
		return nil, fmt.Errorf("kill switch mode %q: %w",
			compiled.KillSwitch, backend.ErrNotImplemented)
	}
	if compiled.DNS.TrackingEnabled {
		return nil, fmt.Errorf("DNS tracking: %w", backend.ErrNotImplemented)
	}

	sets := make(map[setName][]netip.Prefix, len(policySetNames()))
	used := make(map[routeClass]bool, len(splitClasses))
	var rules []nftRule

	for _, prefix := range bypassPrefixes {
		rules = append(rules, nftRule{
			matches: []nftMatch{{prefix: prefix}},
			bypass:  true,
		})
	}

	controlRules, controlPrefixes, err := compileConstraints(compiled.Control, allocations)
	if err != nil {
		return nil, fmt.Errorf("compile control prefixes: %w", err)
	}
	rules = append(rules, controlRules...)
	addPrefixes(sets, classDirect, controlPrefixes)
	if len(controlRules) > 0 {
		used[classDirect] = true
	}

	mandatoryRules, mandatoryPrefixes, err := compileConstraints(compiled.Mandatory, allocations)
	if err != nil {
		return nil, fmt.Errorf("compile mandatory prefixes: %w", err)
	}
	rules = append(rules, mandatoryRules...)
	addPrefixes(sets, classVPN, mandatoryPrefixes)
	if len(mandatoryRules) > 0 {
		used[classVPN] = true
	}

	for _, blockRule := range compiled.BlockRules {
		compiledRules, prefixes, err := compileCompiledRule(blockRule, classBlock, allocations)
		if err != nil {
			return nil, fmt.Errorf("compile block rule %q: %w", blockRule.ID, err)
		}
		rules = append(rules, compiledRules...)
		addPrefixes(sets, classBlock, prefixes)
		if len(compiledRules) > 0 {
			used[classBlock] = true
		}
	}

	for _, userRule := range compiled.Rules {
		class, ok := classForAction(userRule.Action)
		if !ok {
			return nil, fmt.Errorf("rule %q: unsupported action %q", userRule.ID, userRule.Action)
		}
		compiledRules, prefixes, err := compileCompiledRule(userRule, class, allocations)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", userRule.ID, err)
		}
		rules = append(rules, compiledRules...)
		addPrefixes(sets, class, prefixes)
		if len(compiledRules) > 0 {
			used[class] = true
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
	rules = append(rules, nftRule{mark: allocation.mark.Value})
	used[defaultClass] = true

	routeClasses, err := compileRoutePlan(compiled, options, allocations, used)
	if err != nil {
		return nil, err
	}

	return &policyPlan{
		nft: nftPolicy{
			sets:  normalizeSetPrefixes(sets),
			rules: rules,
		},
		route: routePlan{classes: routeClasses},
	}, nil
}

func compileConstraints(
	prefixes []policy.PrefixRule,
	allocations allocations,
) ([]nftRule, []netip.Prefix, error) {
	rules := make([]nftRule, 0, len(prefixes))
	compiledPrefixes := make([]netip.Prefix, 0, len(prefixes))
	for _, prefixRule := range prefixes {
		if err := validateIPv4Prefix(prefixRule.Prefix); err != nil {
			return nil, nil, err
		}
		class, ok := classForAction(prefixRule.Action)
		if !ok {
			return nil, nil, fmt.Errorf("unsupported constraint action %q", prefixRule.Action)
		}
		allocation, ok := allocations.get(class)
		if !ok {
			return nil, nil, fmt.Errorf("no allocation for class %q", class)
		}
		rules = append(rules, nftRule{
			matches: []nftMatch{{prefix: prefixRule.Prefix}},
			mark:    allocation.mark.Value,
		})
		compiledPrefixes = append(compiledPrefixes, prefixRule.Prefix)
	}
	return rules, compiledPrefixes, nil
}

func compileCompiledRule(
	rule policy.CompiledRule,
	class routeClass,
	allocations allocations,
) ([]nftRule, []netip.Prefix, error) {
	allocation, ok := allocations.get(class)
	if !ok {
		return nil, nil, fmt.Errorf("no allocation for class %q", class)
	}
	set := setForClass(class)
	if set == "" {
		return nil, nil, fmt.Errorf("no prefix set for class %q", class)
	}

	conjunctions, err := ruleConjunctions(rule)
	if err != nil {
		return nil, nil, err
	}

	var rules []nftRule
	var prefixes []netip.Prefix
	for _, conjunction := range conjunctions {
		prefixesInConjunction, hasProtocol, err := classifyConjunction(conjunction)
		if err != nil {
			return nil, nil, err
		}
		// Only prefixes matched through the action set belong in that set.
		// A protocol-qualified rule matches its prefixes literally, and adding
		// them to the aggregate set would let an unrelated prefix-only rule of
		// the same action match the narrower rule's addresses.
		if !hasProtocol {
			prefixes = append(prefixes, prefixesInConjunction...)
		}

		var matches []nftMatch
		if !hasProtocol && len(prefixesInConjunction) > 0 {
			matches = []nftMatch{{set: set}}
		} else {
			for _, prefix := range prefixesInConjunction {
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
		}
		rules = append(rules, nftRule{matches: matches, mark: allocation.mark.Value})
	}
	return rules, prefixes, nil
}

func classifyConjunction(conjunction []config.Condition) ([]netip.Prefix, bool, error) {
	var prefixes []netip.Prefix
	hasProtocol := false
	for _, condition := range conjunction {
		switch condition.Type {
		case config.ConditionCIDR:
			if err := validateIPv4Prefix(condition.Prefix); err != nil {
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
				Reason:    "condition is not implemented for IPv4 policy enforcement",
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
		if err := validateIPv4Prefix(condition.Prefix); err != nil {
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
			Reason:    "condition is not implemented for IPv4 policy enforcement",
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

func validateIPv4Prefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid CIDR: %w", backend.ErrUnsupportedCondition)
	}
	if prefix.Addr().Zone() != "" {
		return fmt.Errorf("CIDR must not contain a zone: %w", backend.ErrUnsupportedCondition)
	}
	if prefix.Addr().Is4In6() {
		return fmt.Errorf("CIDR must use a plain IPv4 address: %w", backend.ErrUnsupportedCondition)
	}
	if !prefix.Addr().Is4() {
		return &backend.UnsupportedConditionError{
			Condition: config.ConditionCIDR,
			Reason:    "IPv6 CIDR conditions are out of scope for this milestone",
			IPv6:      true,
		}
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

func addPrefixes(sets map[setName][]netip.Prefix, class routeClass, prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}
	set := setForClass(class)
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
				blackhole:  true,
				protected:  true,
			})
		case classVPN:
			if err := options.VPN.Validate(); err != nil {
				return nil, fmt.Errorf("%w: vpn target: %w", backend.ErrInvalidPolicyOption, err)
			}
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				target:     options.VPN,
				protected:  true,
			})
		case classDirect:
			if err := options.Direct.Validate(); err != nil {
				return nil, fmt.Errorf("%w: direct target: %w", backend.ErrInvalidPolicyOption, err)
			}
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				target:     options.Direct,
			})
		case classExit:
			if options.ExitNode == nil {
				routeClasses = append(routeClasses, classRoute{
					class:      class,
					allocation: allocation,
					protected:  true,
				})
				break
			}
			if err := options.ExitNode.Validate(); err != nil {
				return nil, fmt.Errorf("%w: exit node target: %w",
					backend.ErrInvalidPolicyOption, err)
			}
			for _, rule := range compiled.Rules {
				if rule.Action != config.ActionExitNode || rule.ExitNodeID == "" {
					continue
				}
				if rule.ExitNodeID != options.ExitNode.ID {
					return nil, &backend.ExitNodeUnavailableError{
						Requested: rule.ExitNodeID,
						Active:    options.ExitNode.ID,
					}
				}
			}
			routeClasses = append(routeClasses, classRoute{
				class:      class,
				allocation: allocation,
				target:     options.ExitNode.Target,
				protected:  true,
			})
		default:
			return nil, fmt.Errorf("unsupported route class %q", class)
		}
	}
	return routeClasses, nil
}
