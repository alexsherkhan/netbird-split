// Package policy compiles a validated split tunnel configuration into a
// deterministic routing policy.
//
// Precedence follows the product specification: control and transport traffic,
// mandatory security constraints, matching block rules, user rules ordered by
// priority and stable rule ID, then the global default action. Compilation also
// reports structural conflicts so callers can warn before applying a policy.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// Constraints are non-user routing constraints supplied by the caller. Control
// prefixes are always routed directly to avoid routing loops; private prefixes
// always use the overlay so an excluded resource cannot leak.
type Constraints struct {
	ControlPrefixes []netip.Prefix
	PrivatePrefixes []netip.Prefix
}

// PrefixRule is a compiled prefix constraint with the action it forces.
type PrefixRule struct {
	Prefix netip.Prefix
	Action config.Action
}

// CompiledRule is a rule in evaluation order. Conditions are deep-copied from
// the configuration so later mutations cannot change a compiled policy.
type CompiledRule struct {
	ID         config.RuleID
	Priority   int
	Action     config.Action
	ExitNodeID config.ExitNodeID
	MatchMode  config.MatchMode
	Conditions []config.Condition

	signature string
}

// CompiledPolicy is a deterministic policy ready for a network backend.
// Callers must not mutate it after compilation. Enabled reports whether the
// split engine should be applied; rules remain compiled when the engine is
// temporarily disabled.
type CompiledPolicy struct {
	Enabled       bool
	Mode          config.Mode
	DefaultAction config.Action
	KillSwitch    config.KillSwitchMode
	IPv6          bool
	DNS           config.DNSSettings
	Control       []PrefixRule
	Mandatory     []PrefixRule
	BlockRules    []CompiledRule
	Rules         []CompiledRule
	Conflicts     []Conflict
}

// Compile validates and compiles a configuration without caller constraints.
func Compile(cfg *config.Config) (*CompiledPolicy, error) {
	return CompileWith(cfg, Constraints{})
}

// CompileWith validates and compiles a configuration with caller constraints.
func CompileWith(cfg *config.Config, constraints Constraints) (*CompiledPolicy, error) {
	if cfg == nil {
		return nil, errors.New("compile policy: config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	if err := constraints.validate(); err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	settings := &cfg.SplitTunnel
	defaultAction := settings.DefaultAction
	if defaultAction == "" {
		defaultAction = config.ActionDefault
	}
	killSwitch := settings.KillSwitch
	if killSwitch == "" {
		killSwitch = config.KillSwitchDisabled
	}
	dns := settings.DNS
	if dns.ConflictPolicy == "" {
		dns.ConflictPolicy = config.ConflictVPN
	}

	policy := &CompiledPolicy{
		Enabled:       settings.Enabled && settings.Mode != config.ModeStandard,
		Mode:          settings.Mode,
		DefaultAction: defaultAction,
		KillSwitch:    killSwitch,
		IPv6:          settings.IPv6,
		DNS:           dns,
		Control:       compilePrefixes(constraints.ControlPrefixes, config.ActionDirect),
		Mandatory:     compilePrefixes(constraints.PrivatePrefixes, config.ActionVPN),
	}

	for i := range settings.Rules {
		rule := &settings.Rules[i]
		if !rule.Enabled {
			continue
		}
		action := rule.Action
		if action == config.ActionDefault {
			action = defaultAction
		}
		compiled := CompiledRule{
			ID:         rule.ID,
			Priority:   rule.Priority,
			Action:     action,
			ExitNodeID: rule.ExitNodeID,
			MatchMode:  rule.MatchMode,
			Conditions: cloneConditions(rule.Conditions),
		}
		if compiled.MatchMode == "" {
			compiled.MatchMode = config.MatchAll
		}
		compiled.signature = ruleSignature(compiled.MatchMode, compiled.Conditions)

		if action == config.ActionBlock {
			policy.BlockRules = append(policy.BlockRules, compiled)
		} else {
			policy.Rules = append(policy.Rules, compiled)
		}
	}
	sortRules(policy.BlockRules)
	sortRules(policy.Rules)

	policy.Conflicts = detectConflicts(policy)
	return policy, nil
}

func (c Constraints) validate() error {
	for i, prefix := range c.ControlPrefixes {
		if err := validateConstraintPrefix(prefix); err != nil {
			return fmt.Errorf("control prefix %d: %w", i, err)
		}
	}
	for i, prefix := range c.PrivatePrefixes {
		if err := validateConstraintPrefix(prefix); err != nil {
			return fmt.Errorf("private prefix %d: %w", i, err)
		}
	}
	// Control and private prefixes may overlap at runtime: a management or
	// transport endpoint can live inside a private route. Compilation emits
	// control rules first, so control precedence resolves the overlap while the
	// rest of the private route still uses the overlay.
	return nil
}

func validateConstraintPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return errors.New("prefix is invalid")
	}
	if prefix.Addr().Is4In6() {
		return errors.New("prefix must use a plain IPv4 address")
	}
	if prefix.Masked() != prefix {
		return errors.New("prefix has host bits set")
	}
	return nil
}

func compilePrefixes(prefixes []netip.Prefix, action config.Action) []PrefixRule {
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]PrefixRule, 0, len(prefixes))
	for _, prefix := range prefixes {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, PrefixRule{Prefix: prefix, Action: action})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Prefix.String() < out[j].Prefix.String()
	})
	return out
}

func sortRules(rules []CompiledRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}

func cloneConditions(in []config.Condition) []config.Condition {
	if in == nil {
		return nil
	}
	out := make([]config.Condition, len(in))
	for i := range in {
		out[i] = in[i]
		if in[i].UID != nil {
			uid := *in[i].UID
			out[i].UID = &uid
		}
		out[i].Children = cloneConditions(in[i].Children)
	}
	return out
}

func ruleSignature(mode config.MatchMode, conditions []config.Condition) string {
	parts := make([]string, len(conditions))
	for i := range conditions {
		parts[i] = conditionSignature(&conditions[i])
	}
	sort.Strings(parts)

	var canonical strings.Builder
	canonical.WriteString(string(mode))
	canonical.WriteByte('|')
	writeSignatureParts(&canonical, parts)
	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:])
}

func conditionSignature(condition *config.Condition) string {
	switch condition.Type {
	case config.ConditionAll, config.ConditionAny:
		parts := make([]string, len(condition.Children))
		for i := range condition.Children {
			parts[i] = conditionSignature(&condition.Children[i])
		}
		sort.Strings(parts)
		var canonical strings.Builder
		canonical.WriteString(string(condition.Type))
		canonical.WriteByte('(')
		writeSignatureParts(&canonical, parts)
		canonical.WriteByte(')')
		return canonical.String()
	default:
		return string(condition.Type) + "=" + strconv.Quote(conditionValue(condition))
	}
}

func writeSignatureParts(builder *strings.Builder, parts []string) {
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
		builder.WriteByte(';')
	}
}

func conditionValue(condition *config.Condition) string {
	switch condition.Type {
	case config.ConditionDesktopID:
		return string(condition.DesktopID)
	case config.ConditionExecutable:
		return string(condition.Executable)
	case config.ConditionFlatpakID:
		return string(condition.FlatpakID)
	case config.ConditionSnapID:
		return string(condition.SnapID)
	case config.ConditionDomain:
		return string(condition.Domain)
	case config.ConditionWildcardDomain:
		return "*." + string(condition.Wildcard)
	case config.ConditionCIDR:
		return condition.Prefix.String()
	case config.ConditionProtocolPort:
		return string(condition.Protocol) + "/" + strconv.FormatUint(uint64(condition.Port), 10)
	case config.ConditionUID:
		if condition.UID == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*condition.UID), 10)
	default:
		return ""
	}
}

// UsesApplications reports whether any enabled rule selects traffic by an
// application identity. The classifier only needs to create cgroup scopes for
// policies that use these conditions.
func (p *CompiledPolicy) UsesApplications() bool {
	if p == nil || !p.Enabled {
		return false
	}
	for i := range p.BlockRules {
		if conditionsUseApplications(p.BlockRules[i].Conditions) {
			return true
		}
	}
	for i := range p.Rules {
		if conditionsUseApplications(p.Rules[i].Conditions) {
			return true
		}
	}
	return false
}

func conditionsUseApplications(conditions []config.Condition) bool {
	for i := range conditions {
		switch conditions[i].Type {
		case config.ConditionDesktopID, config.ConditionExecutable,
			config.ConditionFlatpakID, config.ConditionSnapID:
			return true
		case config.ConditionAll, config.ConditionAny:
			if conditionsUseApplications(conditions[i].Children) {
				return true
			}
		}
	}
	return false
}

// UsesDomains reports whether any enabled rule selects traffic by a domain.
// The DNS tracker only needs to observe answers for policies that use these
// conditions.
func (p *CompiledPolicy) UsesDomains() bool {
	if p == nil || !p.Enabled {
		return false
	}
	for i := range p.BlockRules {
		if conditionsUseDomains(p.BlockRules[i].Conditions) {
			return true
		}
	}
	for i := range p.Rules {
		if conditionsUseDomains(p.Rules[i].Conditions) {
			return true
		}
	}
	return false
}

func conditionsUseDomains(conditions []config.Condition) bool {
	for i := range conditions {
		switch conditions[i].Type {
		case config.ConditionDomain, config.ConditionWildcardDomain:
			return true
		case config.ConditionAll, config.ConditionAny:
			if conditionsUseDomains(conditions[i].Children) {
				return true
			}
		}
	}
	return false
}
