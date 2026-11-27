package policy

import (
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

// Application identifies the process a flow belongs to. Unset fields never
// match an application condition.
type Application struct {
	DesktopID  config.DesktopID
	Executable config.Executable
	FlatpakID  config.FlatpakID
	SnapID     config.SnapID
}

// Flow describes the traffic being classified. Destination and Domain are
// optional; a condition only matches when the corresponding flow field is set.
type Flow struct {
	Application Application
	Domain      config.Domain
	Destination netip.Addr
	Protocol    config.Protocol
	Port        uint16
	UID         *config.UID
}

// normalizeFlow canonicalizes optional values so typed aliases constructed by
// callers cannot bypass matching rules.
func normalizeFlow(flow Flow) Flow {
	flow.Destination = flow.Destination.Unmap()
	if flow.Domain != "" {
		domain := strings.TrimSuffix(strings.ToLower(string(flow.Domain)), ".")
		flow.Domain = config.Domain(domain)
	}
	flow.Protocol = config.Protocol(strings.ToLower(string(flow.Protocol)))
	return flow
}

func (r *CompiledRule) matches(flow *Flow) bool {
	if r.MatchMode == config.MatchAny {
		for i := range r.Conditions {
			if matchCondition(&r.Conditions[i], flow) {
				return true
			}
		}
		return false
	}
	for i := range r.Conditions {
		if !matchCondition(&r.Conditions[i], flow) {
			return false
		}
	}
	return true
}

func matchCondition(condition *config.Condition, flow *Flow) bool {
	switch condition.Type {
	case config.ConditionDesktopID:
		return condition.DesktopID != "" && condition.DesktopID == flow.Application.DesktopID
	case config.ConditionExecutable:
		return condition.Executable != "" && condition.Executable == flow.Application.Executable
	case config.ConditionFlatpakID:
		return condition.FlatpakID != "" && condition.FlatpakID == flow.Application.FlatpakID
	case config.ConditionSnapID:
		return condition.SnapID != "" && condition.SnapID == flow.Application.SnapID
	case config.ConditionDomain:
		return condition.Domain != "" && condition.Domain == flow.Domain
	case config.ConditionWildcardDomain:
		return matchWildcard(condition.Wildcard, flow.Domain)
	case config.ConditionCIDR:
		return flow.Destination.IsValid() && condition.Prefix.Contains(flow.Destination)
	case config.ConditionProtocolPort:
		return flow.Protocol != "" && flow.Port != 0 &&
			condition.Protocol == flow.Protocol && condition.Port == flow.Port
	case config.ConditionUID:
		return condition.UID != nil && flow.UID != nil && *condition.UID == *flow.UID
	case config.ConditionAll:
		for i := range condition.Children {
			if !matchCondition(&condition.Children[i], flow) {
				return false
			}
		}
		return len(condition.Children) > 0
	case config.ConditionAny:
		for i := range condition.Children {
			if matchCondition(&condition.Children[i], flow) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchWildcard(base config.WildcardDomain, domain config.Domain) bool {
	if base == "" || domain == "" {
		return false
	}
	suffix := "." + string(base)
	return len(domain) > len(suffix) && strings.HasSuffix(string(domain), suffix)
}
