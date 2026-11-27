package policy

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// ConflictReason explains why a rule cannot take effect or disagrees with
// another rule.
type ConflictReason string

const (
	// ConflictSameMatchDifferentAction marks rules with identical conditions
	// that select different actions or exit nodes.
	ConflictSameMatchDifferentAction ConflictReason = "same_match_different_action"
	// ConflictBlockOverrides marks a rule shadowed by a block rule with the
	// same match.
	ConflictBlockOverrides ConflictReason = "block_overrides"
	// ConflictMandatoryOverrides marks a rule that conflicts with a mandatory
	// private-network constraint.
	ConflictMandatoryOverrides ConflictReason = "mandatory_overrides"
	// ConflictControlOverrides marks a rule that conflicts with control or
	// transport traffic that must never follow user routing.
	ConflictControlOverrides ConflictReason = "control_overrides"
)

// Conflict pairs two rules, or a rule and a mandatory constraint, that cannot
// both take effect as written.
type Conflict struct {
	RuleID      config.RuleID
	OtherRuleID config.RuleID
	Reason      ConflictReason
	Detail      string
}

// detectConflicts finds structural conflicts in a compiled policy. Runtime
// conflicts caused by a specific flow are reported in Decision.Conflicts.
func detectConflicts(policy *CompiledPolicy) []Conflict {
	conflicts := append(
		detectSignatureConflicts(policy.BlockRules, policy.Rules),
		detectConstraintConflicts(policy.Control, policy.Mandatory,
			policy.BlockRules, policy.Rules)...,
	)
	sort.SliceStable(conflicts, func(i, j int) bool {
		if conflicts[i].RuleID != conflicts[j].RuleID {
			return conflicts[i].RuleID < conflicts[j].RuleID
		}
		if conflicts[i].OtherRuleID != conflicts[j].OtherRuleID {
			return conflicts[i].OtherRuleID < conflicts[j].OtherRuleID
		}
		return conflicts[i].Reason < conflicts[j].Reason
	})
	return dedupeConflicts(conflicts)
}

func detectSignatureConflicts(blocks, rules []CompiledRule) []Conflict {
	groups := make(map[string][]CompiledRule, len(blocks)+len(rules))
	for i := range blocks {
		rule := blocks[i]
		groups[rule.signature] = append(groups[rule.signature], rule)
	}
	for i := range rules {
		rule := rules[i]
		groups[rule.signature] = append(groups[rule.signature], rule)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var conflicts []Conflict
	for _, key := range keys {
		group := groups[key]
		if len(group) < 2 {
			continue
		}
		lead := group[0]
		for i := 1; i < len(group); i++ {
			other := group[i]
			if lead.Action == other.Action && lead.ExitNodeID == other.ExitNodeID {
				continue
			}
			reason := ConflictSameMatchDifferentAction
			if lead.Action == config.ActionBlock {
				reason = ConflictBlockOverrides
			}
			conflicts = append(conflicts, Conflict{
				RuleID:      other.ID,
				OtherRuleID: lead.ID,
				Reason:      reason,
				Detail: fmt.Sprintf(
					"rules %q and %q have identical conditions but different outcomes (%s and %s)",
					lead.ID, other.ID, outcome(lead), outcome(other)),
			})
		}
	}
	return conflicts
}

// detectConstraintConflicts reports rules that are a single CIDR condition and
// overlap a constraint. Composite rules are checked per flow during evaluation
// because their overlap cannot be decided structurally.
func detectConstraintConflicts(
	control, mandatory []PrefixRule,
	blocks, rules []CompiledRule,
) []Conflict {
	ordered := make([]CompiledRule, 0, len(blocks)+len(rules))
	ordered = append(ordered, blocks...)
	ordered = append(ordered, rules...)

	var conflicts []Conflict
	for i := range ordered {
		rule := &ordered[i]
		prefix, ok := singleCIDR(rule.Conditions)
		if !ok {
			continue
		}
		for _, constraint := range mandatory {
			if !prefix.Overlaps(constraint.Prefix) || rule.Action == config.ActionVPN {
				continue
			}
			conflicts = append(conflicts, Conflict{
				RuleID: rule.ID,
				Reason: ConflictMandatoryOverrides,
				Detail: fmt.Sprintf(
					"rule %q would select %s for private prefix %s",
					rule.ID, rule.Action, constraint.Prefix),
			})
		}
		for _, constraint := range control {
			if !prefix.Overlaps(constraint.Prefix) || rule.Action == config.ActionDirect {
				continue
			}
			conflicts = append(conflicts, Conflict{
				RuleID: rule.ID,
				Reason: ConflictControlOverrides,
				Detail: fmt.Sprintf(
					"rule %q would select %s for control prefix %s",
					rule.ID, rule.Action, constraint.Prefix),
			})
		}
	}
	return conflicts
}

func singleCIDR(conditions []config.Condition) (netip.Prefix, bool) {
	if len(conditions) != 1 || conditions[0].Type != config.ConditionCIDR {
		return netip.Prefix{}, false
	}
	return conditions[0].Prefix, true
}

func outcome(rule CompiledRule) string {
	if rule.ExitNodeID == "" {
		return string(rule.Action)
	}
	return string(rule.Action) + ":" + string(rule.ExitNodeID)
}

func dedupeConflicts(conflicts []Conflict) []Conflict {
	if len(conflicts) < 2 {
		return conflicts
	}
	out := conflicts[:0]
	var previous Conflict
	for i, conflict := range conflicts {
		if i > 0 && conflict.RuleID == previous.RuleID &&
			conflict.OtherRuleID == previous.OtherRuleID &&
			conflict.Reason == previous.Reason {
			continue
		}
		out = append(out, conflict)
		previous = conflict
	}
	return out
}
