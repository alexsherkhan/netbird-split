//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/netbirdio/netbird/client/internal/splittunnel/diagnostics"
)

// trafficCounterReader is the optional part of the nftables manager used by
// diagnostics. Keeping it optional lets test managers omit counters.
type trafficCounterReader interface {
	TrafficCounters(context.Context, map[uint32]diagnostics.TrafficClass) (diagnostics.CounterSample, error)
}

// withClassificationCounter inserts an owned counter immediately before the
// rule verdict. Bypass rules carry no class and are left uncounted.
func withClassificationCounter(rule nftRule, exprs []expr.Any) []expr.Any {
	if rule.bypass || rule.mark == 0 {
		return exprs
	}
	for i := len(exprs) - 1; i >= 0; i-- {
		if _, ok := exprs[i].(*expr.Verdict); !ok {
			continue
		}
		out := make([]expr.Any, 0, len(exprs)+1)
		out = append(out, exprs[:i]...)
		out = append(out, &expr.Counter{})
		out = append(out, exprs[i:]...)
		return out
	}
	return exprs
}

// TrafficCounters reads the owned classification counters and maps each rule
// mark to a traffic class. A missing or foreign table is an error, so callers
// report the metric as unavailable instead of returning zeros.
func (m *nftablesManager) TrafficCounters(
	ctx context.Context,
	marks map[uint32]diagnostics.TrafficClass,
) (diagnostics.CounterSample, error) {
	if err := ctx.Err(); err != nil {
		return diagnostics.CounterSample{}, err
	}
	table, found, err := m.findTable()
	if err != nil {
		return diagnostics.CounterSample{}, err
	}
	if !found {
		return diagnostics.CounterSample{}, errors.New("owned nftables table is missing")
	}
	m.table = table

	chains, err := m.chainsInTable()
	if err != nil {
		return diagnostics.CounterSample{}, err
	}
	if err := verifyExistingChains(chains); err != nil {
		return diagnostics.CounterSample{}, err
	}
	rules, err := m.rulesByChain(chains)
	if err != nil {
		return diagnostics.CounterSample{}, err
	}

	classify, ok := rules[string(chainClassifyOutput)]
	if !ok {
		return diagnostics.CounterSample{}, fmt.Errorf("owned chain %q is missing", chainClassifyOutput)
	}

	sample := diagnostics.CounterSample{
		Classes: make(map[diagnostics.TrafficClass]diagnostics.ClassCounter),
	}
	for _, rule := range classify {
		counter := ruleCounter(rule)
		if counter == nil {
			continue
		}
		mark, ok := ruleMark(rule)
		if !ok {
			continue
		}
		class, ok := marks[mark]
		if !ok {
			continue
		}
		classCounter := sample.Classes[class]
		classCounter.Packets += counter.Packets
		classCounter.Bytes += counter.Bytes
		sample.Classes[class] = classCounter
		sample.RuleHits += counter.Packets
	}
	return sample, nil
}

func ruleCounter(rule *nftables.Rule) *expr.Counter {
	for _, expression := range rule.Exprs {
		if counter, ok := expression.(*expr.Counter); ok {
			return counter
		}
	}
	return nil
}

func ruleMark(rule *nftables.Rule) (uint32, bool) {
	for i, expression := range rule.Exprs {
		meta, ok := expression.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyMARK || !meta.SourceRegister {
			continue
		}
		if i == 0 {
			return 0, false
		}
		immediate, ok := rule.Exprs[i-1].(*expr.Immediate)
		if !ok || len(immediate.Data) != 4 {
			return 0, false
		}
		return binaryutil.NativeEndian.Uint32(immediate.Data), true
	}
	return 0, false
}
