package policy

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// Layer is the precedence layer that selected a decision.
type Layer string

const (
	// LayerControl is NetBird control and transport traffic that must never be
	// rerouted by user rules.
	LayerControl Layer = "control"
	// LayerMandatory is a mandatory private-network constraint.
	LayerMandatory Layer = "mandatory"
	// LayerBlock is an explicit block rule.
	LayerBlock Layer = "block"
	// LayerRule is a user routing rule.
	LayerRule Layer = "rule"
	// LayerDefault is the global default action.
	LayerDefault Layer = "default"
)

const (
	maxTraceEntries      = 64
	maxDecisionConflicts = 64
)

// TraceEntry describes one matched candidate in precedence order. Exactly one
// entry has Won set. Conflict is populated when the entry lost to a higher
// precedence layer for a reason that indicates a conflicting configuration.
type TraceEntry struct {
	Layer    Layer
	RuleID   config.RuleID
	Action   config.Action
	Won      bool
	Conflict ConflictReason
	Detail   string
}

// Decision is the routing outcome for one flow together with its trace.
type Decision struct {
	Action             config.Action
	Layer              Layer
	RuleID             config.RuleID
	ExitNodeID         config.ExitNodeID
	Trace              []TraceEntry
	Conflicts          []Conflict
	TraceTruncated     bool
	ConflictsTruncated bool
}

type candidate struct {
	layer      Layer
	ruleID     config.RuleID
	action     config.Action
	exitNodeID config.ExitNodeID
	detail     string
}

// Evaluate applies the policy to a flow. It is pure: the policy is not
// modified and repeated calls with the same flow produce the same decision.
func (p *CompiledPolicy) Evaluate(flow Flow) Decision {
	if p == nil {
		return Decision{Action: config.ActionDefault, Layer: LayerDefault}
	}
	flow = normalizeFlow(flow)

	control := matchPrefix(p.Control, flow.Destination)
	mandatory := matchPrefix(p.Mandatory, flow.Destination)
	blocks := p.matchRules(p.BlockRules, &flow)
	rules := p.matchRules(p.Rules, &flow)

	winner := p.selectWinner(control, mandatory, blocks, rules)
	trace := &traceBuilder{}
	buildTrace(trace, p, winner, control, mandatory, blocks, rules)

	return Decision{
		Action:             winner.action,
		Layer:              winner.layer,
		RuleID:             winner.ruleID,
		ExitNodeID:         winner.exitNodeID,
		Trace:              trace.entries,
		Conflicts:          trace.conflicts,
		TraceTruncated:     trace.truncated,
		ConflictsTruncated: trace.conflictsTruncated,
	}
}

func matchPrefix(rules []PrefixRule, addr netip.Addr) *PrefixRule {
	if !addr.IsValid() {
		return nil
	}
	for i := range rules {
		if rules[i].Prefix.Contains(addr) {
			return &rules[i]
		}
	}
	return nil
}

func (p *CompiledPolicy) matchRules(rules []CompiledRule, flow *Flow) []*CompiledRule {
	var matches []*CompiledRule
	for i := range rules {
		if rules[i].matches(flow) {
			matches = append(matches, &rules[i])
		}
	}
	return matches
}

func (p *CompiledPolicy) selectWinner(
	control, mandatory *PrefixRule,
	blocks, rules []*CompiledRule,
) candidate {
	switch {
	case control != nil:
		return candidate{
			layer:  LayerControl,
			action: control.Action,
			detail: fmt.Sprintf("control prefix %s", control.Prefix),
		}
	case mandatory != nil:
		return candidate{
			layer:  LayerMandatory,
			action: mandatory.Action,
			detail: fmt.Sprintf("mandatory private prefix %s", mandatory.Prefix),
		}
	case len(blocks) > 0:
		rule := blocks[0]
		return candidate{
			layer:  LayerBlock,
			ruleID: rule.ID,
			action: rule.Action,
			detail: fmt.Sprintf("block rule %q", rule.ID),
		}
	case len(rules) > 0:
		rule := rules[0]
		return candidate{
			layer:      LayerRule,
			ruleID:     rule.ID,
			action:     rule.Action,
			exitNodeID: rule.ExitNodeID,
			detail:     fmt.Sprintf("rule %q", rule.ID),
		}
	default:
		return candidate{
			layer:  LayerDefault,
			action: p.DefaultAction,
			detail: "global default action",
		}
	}
}

func buildTrace(
	trace *traceBuilder,
	p *CompiledPolicy,
	winner candidate,
	control, mandatory *PrefixRule,
	blocks, rules []*CompiledRule,
) {
	if control != nil {
		trace.addEntry(TraceEntry{
			Layer:  LayerControl,
			Action: control.Action,
			Won:    winner.layer == LayerControl,
			Detail: fmt.Sprintf("control prefix %s", control.Prefix),
		})
	}
	if mandatory != nil {
		entry := TraceEntry{
			Layer:  LayerMandatory,
			Action: mandatory.Action,
			Won:    winner.layer == LayerMandatory,
			Detail: fmt.Sprintf("mandatory private prefix %s", mandatory.Prefix),
		}
		if !entry.Won {
			entry.Detail += ", overridden by control traffic"
		}
		trace.addEntry(entry)
	}

	buildBlockTrace(trace, winner, blocks)
	buildRuleTrace(trace, winner, rules)

	entry := TraceEntry{
		Layer:  LayerDefault,
		Action: p.DefaultAction,
		Won:    winner.layer == LayerDefault,
		Detail: "global default action",
	}
	if !entry.Won {
		entry.Detail += ", overridden by " + winner.detail
	}
	trace.addEntry(entry)
}

func buildBlockTrace(trace *traceBuilder, winner candidate, blocks []*CompiledRule) {
	for i, rule := range blocks {
		entry := TraceEntry{
			Layer:  LayerBlock,
			RuleID: rule.ID,
			Action: rule.Action,
			Won:    winner.layer == LayerBlock && i == 0,
		}
		switch {
		case entry.Won:
			entry.Detail = fmt.Sprintf("block rule %q", rule.ID)
		case i > 0 && winner.layer == LayerBlock:
			entry.Detail = "lower priority block rule"
		case winner.layer == LayerControl:
			entry.Conflict = ConflictControlOverrides
			entry.Detail = "control traffic cannot be blocked by user rules"
		case winner.layer == LayerMandatory:
			entry.Conflict = ConflictMandatoryOverrides
			entry.Detail = "mandatory private route cannot be blocked"
		default:
			entry.Detail = "overridden by " + winner.detail
		}
		trace.addEntry(entry)
		if entry.Conflict != "" {
			trace.addConflict(Conflict{
				RuleID: rule.ID,
				Reason: entry.Conflict,
				Detail: entry.Detail,
			})
		}
	}
}

func buildRuleTrace(trace *traceBuilder, winner candidate, rules []*CompiledRule) {
	for i, rule := range rules {
		entry := TraceEntry{
			Layer:  LayerRule,
			RuleID: rule.ID,
			Action: rule.Action,
			Won:    winner.layer == LayerRule && i == 0,
		}
		switch {
		case entry.Won:
			entry.Detail = fmt.Sprintf("rule %q", rule.ID)
		case winner.layer == LayerControl:
			entry.Detail = "control traffic is not routed by user rules"
			if rule.Action != winner.action {
				entry.Conflict = ConflictControlOverrides
			}
		case winner.layer == LayerMandatory:
			entry.Detail = "mandatory private route takes precedence"
			if rule.Action != config.ActionVPN {
				entry.Conflict = ConflictMandatoryOverrides
			}
		case winner.layer == LayerBlock:
			entry.Conflict = ConflictBlockOverrides
			entry.Detail = fmt.Sprintf("block rule %q takes precedence", winner.ruleID)
		default:
			entry.Detail = ruleOverrideDetail(rule, rules[0])
			if sameSignature(rule, rules[0]) &&
				(rule.Action != rules[0].Action || rule.ExitNodeID != rules[0].ExitNodeID) {
				entry.Conflict = ConflictSameMatchDifferentAction
			}
		}
		trace.addEntry(entry)
		if entry.Conflict != "" {
			trace.addConflict(Conflict{
				RuleID:      rule.ID,
				OtherRuleID: winner.ruleID,
				Reason:      entry.Conflict,
				Detail:      entry.Detail,
			})
		}
	}
}

func ruleOverrideDetail(loser, winner *CompiledRule) string {
	if loser.Priority == winner.Priority {
		return fmt.Sprintf("same priority as rule %q; rule ID tie-break", winner.ID)
	}
	return fmt.Sprintf("lower priority than rule %q", winner.ID)
}

func sameSignature(a, b *CompiledRule) bool {
	return a.signature == b.signature
}

type traceBuilder struct {
	entries            []TraceEntry
	conflicts          []Conflict
	truncated          bool
	conflictsTruncated bool
}

func (b *traceBuilder) addEntry(entry TraceEntry) {
	if len(b.entries) >= maxTraceEntries {
		b.truncated = true
		return
	}
	b.entries = append(b.entries, entry)
}

func (b *traceBuilder) addConflict(conflict Conflict) {
	if len(b.conflicts) >= maxDecisionConflicts {
		b.conflictsTruncated = true
		return
	}
	b.conflicts = append(b.conflicts, conflict)
}
