//go:build !android && !ios && !freebsd && !js

package services

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	maxRuleNameLength        = 256
	maxRuleDescriptionLength = 1024
	maxRulePriority          = 1_000_000
	maxRuleIDLength          = 128
	maxConditionValueLength  = 512
	maxConditionDepth        = 4
	generatedRuleIDPrefix    = "gui-rule-"
)

// SplitTunnelCondition mirrors the canonical condition the rule editor can
// round-trip. Composite all/any conditions carry children and no value.
type SplitTunnelCondition struct {
	Type     string                 `json:"type"`
	Value    string                 `json:"value"`
	Children []SplitTunnelCondition `json:"children"`
}

// SplitTunnelRuleInput is one rule the editor wants to store. An empty ID asks
// the daemon-side service to allocate an ID for a new rule.
type SplitTunnelRuleInput struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Enabled     bool                   `json:"enabled"`
	Priority    int32                  `json:"priority"`
	MatchMode   string                 `json:"matchMode"`
	Action      string                 `json:"action"`
	ExitNodeID  string                 `json:"exitNodeId"`
	Description string                 `json:"description"`
	Conditions  []SplitTunnelCondition `json:"conditions"`
}

var supportedRuleActions = map[string]struct{}{
	string(config.ActionVPN):      {},
	string(config.ActionDirect):   {},
	string(config.ActionBlock):    {},
	string(config.ActionExitNode): {},
	string(config.ActionDefault):  {},
}

// applyRules replaces every rule this build can edit with the editor's rule set
// and keeps unsupported rules untouched. A supported rule omitted from the input
// is a deletion; an unsupported rule omitted from the input is preserved because
// the editor never showed it.
func (s *SplitTunnel) applyRules(settings *proto.SplitTunnelSettings, inputs []SplitTunnelRuleInput) *ClientError {
	existing := settings.GetRules()
	existingByID := make(map[string]*proto.SplitTunnelRule, len(existing))
	reservedIDs := make(map[string]struct{}, len(existing))
	for _, rule := range existing {
		existingByID[rule.GetId()] = rule
		reservedIDs[rule.GetId()] = struct{}{}
	}

	converted := make(map[string]*proto.SplitTunnelRule, len(inputs))
	order := make([]string, 0, len(inputs))
	for i, input := range inputs {
		rule, err := s.ruleFromInput(input, i, reservedIDs)
		if err != nil {
			return err
		}
		id := rule.GetId()
		if _, duplicate := converted[id]; duplicate {
			return s.invalidRule(fmt.Sprintf("splitTunnel.rules[%d].id", i),
				fmt.Sprintf("duplicate rule ID %q", id))
		}
		if existingRule, ok := existingByID[id]; ok {
			if supported, reason := ruleSupported(existingRule); !supported {
				return s.invalidRule(fmt.Sprintf("splitTunnel.rules[%d]", i),
					fmt.Sprintf("rule %q is not editable: %s", id, reason))
			}
		}
		converted[id] = rule
		order = append(order, id)
	}

	merged := make([]*proto.SplitTunnelRule, 0, len(existing)+len(converted))
	seen := make(map[string]struct{}, len(existing)+len(converted))
	for _, rule := range existing {
		id := rule.GetId()
		if replacement, ok := converted[id]; ok {
			merged = append(merged, replacement)
			seen[id] = struct{}{}
			continue
		}
		if supported, _ := ruleSupported(rule); supported {
			continue
		}
		merged = append(merged, rule)
		seen[id] = struct{}{}
	}
	for _, id := range order {
		if _, ok := seen[id]; ok {
			continue
		}
		merged = append(merged, converted[id])
	}
	settings.Rules = merged
	return nil
}

func (s *SplitTunnel) ruleFromInput(input SplitTunnelRuleInput, index int, reserved map[string]struct{}) (*proto.SplitTunnelRule, *ClientError) {
	path := fmt.Sprintf("splitTunnel.rules[%d]", index)
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, s.invalidRule(path+".name", "is required")
	}
	if len(name) > maxRuleNameLength {
		return nil, s.invalidRule(path+".name",
			fmt.Sprintf("is longer than %d characters", maxRuleNameLength))
	}
	if len(input.Description) > maxRuleDescriptionLength {
		return nil, s.invalidRule(path+".description",
			fmt.Sprintf("is longer than %d characters", maxRuleDescriptionLength))
	}
	if input.Priority < 0 || input.Priority > maxRulePriority {
		return nil, s.invalidRule(path+".priority",
			fmt.Sprintf("must be between 0 and %d", maxRulePriority))
	}
	matchMode := strings.ToLower(strings.TrimSpace(input.MatchMode))
	switch config.MatchMode(matchMode) {
	case "", config.MatchAll, config.MatchAny:
	default:
		return nil, s.invalidRule(path+".matchMode",
			fmt.Sprintf("unsupported match mode %q", input.MatchMode))
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if _, ok := supportedRuleActions[action]; !ok {
		return nil, s.invalidRule(path+".action",
			fmt.Sprintf("unsupported action %q", input.Action))
	}
	exitNodeID := strings.TrimSpace(input.ExitNodeID)
	if action == string(config.ActionExitNode) {
		if exitNodeID == "" {
			return nil, s.invalidRule(path+".exitNodeId",
				"is required for the exit_node action")
		}
		if err := validRuleID(exitNodeID); err != nil {
			return nil, s.invalidRule(path+".exitNodeId", err.Error())
		}
	} else if exitNodeID != "" {
		return nil, s.invalidRule(path+".exitNodeId",
			"is only valid with the exit_node action")
	}
	if len(input.Conditions) == 0 {
		return nil, s.invalidRule(path+".conditions", "must have at least one condition")
	}

	id := strings.TrimSpace(input.ID)
	if id == "" {
		id = nextRuleID(reserved)
	} else if err := validRuleID(id); err != nil {
		return nil, s.invalidRule(path+".id", err.Error())
	}
	reserved[id] = struct{}{}

	conditions := make([]*proto.SplitTunnelCondition, 0, len(input.Conditions))
	for i, condition := range input.Conditions {
		converted, err := s.conditionFromInput(condition,
			fmt.Sprintf("%s.conditions[%d]", path, i), 0)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, converted)
	}

	return &proto.SplitTunnelRule{
		Id:          id,
		Name:        name,
		Enabled:     input.Enabled,
		Priority:    input.Priority,
		MatchMode:   matchMode,
		Action:      action,
		ExitNodeId:  exitNodeID,
		Description: input.Description,
		Conditions:  conditions,
	}, nil
}

func (s *SplitTunnel) conditionFromInput(input SplitTunnelCondition, path string, depth int) (*proto.SplitTunnelCondition, *ClientError) {
	typ := config.ConditionType(strings.ToLower(strings.TrimSpace(input.Type)))
	switch typ {
	case config.ConditionAll, config.ConditionAny:
		return s.compositeConditionFromInput(input, typ, path, depth)
	case config.ConditionDesktopID, config.ConditionExecutable, config.ConditionFlatpakID,
		config.ConditionSnapID, config.ConditionDomain, config.ConditionWildcardDomain,
		config.ConditionCIDR, config.ConditionProtocolPort, config.ConditionUID:
	default:
		return nil, s.invalidRule(path+".type",
			fmt.Sprintf("unsupported condition type %q", input.Type))
	}
	if len(input.Children) > 0 {
		return nil, s.invalidRule(path+".children",
			"is only valid for all or any conditions")
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return nil, s.invalidRule(path+".value", "is required")
	}
	if len(value) > maxConditionValueLength {
		return nil, s.invalidRule(path+".value",
			fmt.Sprintf("is longer than %d characters", maxConditionValueLength))
	}
	normalized, err := normalizeConditionValue(typ, value)
	if err != nil {
		return nil, s.invalidRule(path+".value", err.Error())
	}
	return &proto.SplitTunnelCondition{Type: string(typ), Value: normalized}, nil
}

func (s *SplitTunnel) compositeConditionFromInput(input SplitTunnelCondition, typ config.ConditionType, path string, depth int) (*proto.SplitTunnelCondition, *ClientError) {
	if strings.TrimSpace(input.Value) != "" {
		return nil, s.invalidRule(path+".value",
			fmt.Sprintf("%s condition must not have a value", typ))
	}
	if depth >= maxConditionDepth {
		return nil, s.invalidRule(path,
			fmt.Sprintf("composite nesting exceeds depth %d", maxConditionDepth))
	}
	if len(input.Children) == 0 {
		return nil, s.invalidRule(path+".children", "must have at least one child")
	}
	children := make([]*proto.SplitTunnelCondition, 0, len(input.Children))
	for i, child := range input.Children {
		converted, err := s.conditionFromInput(child,
			fmt.Sprintf("%s.children[%d]", path, i), depth+1)
		if err != nil {
			return nil, err
		}
		children = append(children, converted)
	}
	return &proto.SplitTunnelCondition{Type: string(typ), Children: children}, nil
}

func normalizeConditionValue(typ config.ConditionType, value string) (string, error) {
	switch typ {
	case config.ConditionDomain:
		domain, err := config.NormalizeDomain(value)
		if err != nil {
			return "", err
		}
		return string(domain), nil
	case config.ConditionWildcardDomain:
		base, err := config.NormalizeWildcardDomain(value)
		if err != nil {
			return "", err
		}
		return "*." + string(base), nil
	case config.ConditionCIDR:
		prefix, err := parseCIDRCondition(value)
		if err != nil {
			return "", err
		}
		return prefix.String(), nil
	case config.ConditionProtocolPort:
		protocol, port, err := parseProtocolPortCondition(value)
		if err != nil {
			return "", err
		}
		return protocol + "/" + strconv.FormatUint(uint64(port), 10), nil
	case config.ConditionUID:
		uid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return "", fmt.Errorf("invalid uid %q", value)
		}
		return strconv.FormatUint(uid, 10), nil
	case config.ConditionDesktopID:
		if err := validateDesktopIDCondition(value); err != nil {
			return "", err
		}
		return value, nil
	default:
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("value is not valid UTF-8")
		}
		return value, nil
	}
}

func parseCIDRCondition(value string) (netip.Prefix, error) {
	var prefix netip.Prefix
	if strings.Contains(value, "/") {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q", value)
		}
		prefix = parsed
	} else {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid ip %q", value)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid cidr %q", value)
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("cidr must not contain a zone")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("cidr must use a plain IPv4 address")
	}
	if prefix.Masked() != prefix {
		return netip.Prefix{}, fmt.Errorf("cidr %q has host bits set", value)
	}
	return prefix, nil
}

func parseProtocolPortCondition(value string) (string, uint16, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("protocol_port must use \"<protocol>/<port>\"")
	}
	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	if protocol != string(config.ProtocolTCP) && protocol != string(config.ProtocolUDP) {
		return "", 0, fmt.Errorf("unsupported protocol %q; use tcp or udp", parts[0])
	}
	port, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid port %q; use 1-65535", parts[1])
	}
	return protocol, uint16(port), nil
}

func validateDesktopIDCondition(value string) error {
	if !strings.HasSuffix(value, ".desktop") || len(value) == len(".desktop") {
		return fmt.Errorf("desktop ID must end with .desktop and have a name")
	}
	if strings.ContainsAny(value, `/\`) || strings.Contains(value, "..") {
		return fmt.Errorf("desktop ID must not contain a path separator or \"..\"")
	}
	return nil
}

func validRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("is required")
	}
	if len(id) > maxRuleIDLength {
		return fmt.Errorf("is longer than %d characters", maxRuleIDLength)
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '.' || ch == '_' || ch == ':' || ch == '-' {
			continue
		}
		return fmt.Errorf("contains invalid character %q", ch)
	}
	return nil
}

func nextRuleID(reserved map[string]struct{}) string {
	for i := 1; ; i++ {
		id := generatedRuleIDPrefix + strconv.Itoa(i)
		if _, exists := reserved[id]; exists {
			continue
		}
		return id
	}
}

func (s *SplitTunnel) invalidRule(field, message string) *ClientError {
	return &ClientError{
		Code:  "split_tunnel_invalid_config",
		Short: s.classifier.translateShort("split_tunnel_invalid_config"),
		Long:  field + ": " + message,
		Field: field,
	}
}
