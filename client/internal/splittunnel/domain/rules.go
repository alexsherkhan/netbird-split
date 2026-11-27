package domain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// Rule maps one canonical exact or wildcard name to the action resolved by the
// compiled policy. RuleID is kept for diagnostics.
type Rule struct {
	Pattern Pattern
	Action  config.Action
	RuleID  config.RuleID
}

// RuleConflict reports the same pattern selecting different actions. The
// earliest rule in evaluation order is kept, matching policy precedence.
type RuleConflict struct {
	Pattern string
	Actions []config.Action
	RuleIDs []config.RuleID
}

type ruleEntry struct {
	rule  Rule
	order int
}

// Rules is an ordered exact and wildcard matcher compiled from a policy.
type Rules struct {
	exact    map[Name]ruleEntry
	wildcard map[Name]ruleEntry
	count    int
}

// NewRules returns an empty matcher.
func NewRules() *Rules {
	return &Rules{
		exact:    make(map[Name]ruleEntry),
		wildcard: make(map[Name]ruleEntry),
	}
}

// RulesFromPolicy extracts every domain and wildcard condition from a compiled
// policy. Block rules are considered before user rules, and within each list the
// order is the compiled evaluation order. A rule with more than one domain
// condition is rejected because resolving the intersection of several names is
// not supported.
func RulesFromPolicy(compiled *policy.CompiledPolicy) (*Rules, []RuleConflict, error) {
	rules := NewRules()
	if compiled == nil {
		return rules, nil, nil
	}

	ordered := make([]policy.CompiledRule, 0, len(compiled.BlockRules)+len(compiled.Rules))
	ordered = append(ordered, compiled.BlockRules...)
	ordered = append(ordered, compiled.Rules...)

	var conflicts []RuleConflict
	for i := range ordered {
		rule := &ordered[i]
		domains := domainConditions(rule.Conditions)
		if len(domains) == 0 {
			continue
		}
		if len(domains) > 1 {
			return nil, nil, fmt.Errorf("rule %q: multiple domain conditions are not supported",
				rule.ID)
		}

		action := rule.Action
		if action == config.ActionDefault {
			action = compiled.DefaultAction
		}
		switch action {
		case config.ActionVPN, config.ActionDirect, config.ActionBlock:
		case config.ActionExitNode:
			return nil, nil, fmt.Errorf("rule %q: domain rules with action %q are not supported",
				rule.ID, action)
		default:
			return nil, nil, fmt.Errorf("rule %q: unsupported domain action %q", rule.ID, action)
		}

		pattern, err := patternForCondition(domains[0])
		if err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		candidate := Rule{Pattern: pattern, Action: action, RuleID: rule.ID}
		if !rules.add(candidate, i) {
			existing := rules.mustEntry(pattern)
			if existing.Action != candidate.Action {
				conflicts = append(conflicts, ruleConflict(existing, candidate))
			}
		}
	}
	return rules, conflicts, nil
}

// Match returns the earliest rule whose pattern matches the canonical name.
// Exact and wildcard candidates are compared in policy evaluation order.
func (r *Rules) Match(name Name) (Rule, bool) {
	if r == nil || name == "" {
		return Rule{}, false
	}
	best := ruleEntry{order: -1}
	if entry, ok := r.exact[name]; ok {
		best = entry
	}

	text := string(name)
	for offset := 0; offset < len(text); {
		// A wildcard never matches the apex, so the full name is skipped.
		if offset > 0 {
			if entry, ok := r.wildcard[Name(text[offset:])]; ok {
				if best.order < 0 || entry.order < best.order {
					best = entry
				}
			}
		}
		dot := strings.IndexByte(text[offset:], '.')
		if dot < 0 {
			break
		}
		offset += dot + 1
	}

	if best.order < 0 {
		return Rule{}, false
	}
	return best.rule, true
}

// Count returns the number of distinct patterns.
func (r *Rules) Count() int {
	if r == nil {
		return 0
	}
	return r.count
}

func (r *Rules) add(rule Rule, order int) bool {
	pattern := rule.Pattern
	entry := ruleEntry{rule: rule, order: order}
	if pattern.Wildcard {
		if _, exists := r.wildcard[pattern.Name]; exists {
			return false
		}
		r.wildcard[pattern.Name] = entry
		r.count++
		return true
	}
	if _, exists := r.exact[pattern.Name]; exists {
		return false
	}
	r.exact[pattern.Name] = entry
	r.count++
	return true
}

func (r *Rules) mustEntry(pattern Pattern) Rule {
	if pattern.Wildcard {
		return r.wildcard[pattern.Name].rule
	}
	return r.exact[pattern.Name].rule
}

func ruleConflict(existing, candidate Rule) RuleConflict {
	return RuleConflict{
		Pattern: existing.Pattern.String(),
		Actions: []config.Action{existing.Action, candidate.Action},
		RuleIDs: []config.RuleID{existing.RuleID, candidate.RuleID},
	}
}

func patternForCondition(condition config.Condition) (Pattern, error) {
	switch condition.Type {
	case config.ConditionDomain:
		name, err := Normalize(string(condition.Domain))
		if err != nil {
			return Pattern{}, fmt.Errorf("domain: %w", err)
		}
		return Pattern{Name: name}, nil
	case config.ConditionWildcardDomain:
		base, err := NormalizeWildcard("*." + string(condition.Wildcard))
		if err != nil {
			return Pattern{}, fmt.Errorf("wildcard domain: %w", err)
		}
		return Pattern{Name: Name(base), Wildcard: true}, nil
	default:
		return Pattern{}, fmt.Errorf("condition type %q is not a domain", condition.Type)
	}
}

func domainConditions(conditions []config.Condition) []config.Condition {
	var found []config.Condition
	var walk func([]config.Condition)
	walk = func(items []config.Condition) {
		for i := range items {
			switch items[i].Type {
			case config.ConditionDomain, config.ConditionWildcardDomain:
				found = append(found, items[i])
			case config.ConditionAll, config.ConditionAny:
				walk(items[i].Children)
			}
		}
	}
	walk(conditions)
	return found
}

// SortedRuleConflicts returns a defensive, deterministic copy of conflicts.
func SortedRuleConflicts(conflicts []RuleConflict) []RuleConflict {
	out := make([]RuleConflict, len(conflicts))
	copy(out, conflicts)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Pattern < out[j].Pattern
	})
	for i := range out {
		out[i].Actions = append([]config.Action(nil), out[i].Actions...)
		out[i].RuleIDs = append([]config.RuleID(nil), out[i].RuleIDs...)
	}
	return out
}
