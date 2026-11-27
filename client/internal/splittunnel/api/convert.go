package api

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

// Redacted field names reported to unprivileged callers.
const (
	redactedDiagnostics       = "diagnostics"
	redactedProcessPID        = "processes.pid"
	redactedProcessExecutable = "processes.executable"
	redactedProcessUID        = "processes.uid"
	redactedProcessCgroup     = "processes.cgroup"
	redactedApplicationExec   = "applications.executable"
	redactedApplicationIcon   = "applications.icon_path"
	redactedApplicationSource = "applications.source_path"
	redactedTraceDetails      = "stages.forwarding_details"
)

func configFromProto(in *proto.SplitTunnelConfig) (*config.Config, error) {
	if in == nil {
		return nil, errors.New("config is required")
	}
	settings := in.GetSplitTunnel()
	if settings == nil {
		return nil, errors.New("splitTunnel is required")
	}

	cfg := &config.Config{
		SchemaVersion: in.GetSchemaVersion(),
		SplitTunnel: config.SplitTunnel{
			Enabled:       settings.GetEnabled(),
			Mode:          config.Mode(settings.GetMode()),
			DefaultAction: config.Action(settings.GetDefaultAction()),
			KillSwitch:    config.KillSwitchMode(settings.GetKillSwitch()),
			IPv6:          settings.GetIpv6(),
			DNS:           dnsFromProto(settings.GetDns()),
			Rules:         make([]config.Rule, 0, len(settings.GetRules())),
		},
	}
	for i, rule := range settings.GetRules() {
		converted, err := ruleFromProto(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, converted)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func dnsFromProto(in *proto.SplitTunnelDNSSettings) config.DNSSettings {
	if in == nil {
		return config.DNSSettings{}
	}
	return config.DNSSettings{
		TrackingEnabled: in.GetTrackingEnabled(),
		RespectTTL:      in.GetRespectTtl(),
		ConflictPolicy:  config.ConflictPolicy(in.GetConflictPolicy()),
		StrictMode:      in.GetStrictMode(),
	}
}

func ruleFromProto(in *proto.SplitTunnelRule) (config.Rule, error) {
	if in == nil {
		return config.Rule{}, errors.New("rule is required")
	}
	rule := config.Rule{
		ID:          config.RuleID(in.GetId()),
		Name:        in.GetName(),
		Enabled:     in.GetEnabled(),
		Priority:    int(in.GetPriority()),
		MatchMode:   config.MatchMode(in.GetMatchMode()),
		Action:      config.Action(in.GetAction()),
		ExitNodeID:  config.ExitNodeID(in.GetExitNodeId()),
		Description: in.GetDescription(),
		Conditions:  make([]config.Condition, 0, len(in.GetConditions())),
	}
	for i, condition := range in.GetConditions() {
		converted, err := conditionFromProto(condition)
		if err != nil {
			return config.Rule{}, fmt.Errorf("condition %d: %w", i, err)
		}
		rule.Conditions = append(rule.Conditions, converted)
	}
	return rule, nil
}

func conditionFromProto(in *proto.SplitTunnelCondition) (config.Condition, error) {
	if in == nil {
		return config.Condition{}, errors.New("condition is required")
	}
	typ := config.ConditionType(in.GetType())
	value := in.GetValue()

	switch typ {
	case config.ConditionAll, config.ConditionAny:
		if value != "" {
			return config.Condition{}, fmt.Errorf("%s condition must not have a value", typ)
		}
		children := make([]config.Condition, 0, len(in.GetChildren()))
		for i, child := range in.GetChildren() {
			converted, err := conditionFromProto(child)
			if err != nil {
				return config.Condition{}, fmt.Errorf("child %d: %w", i, err)
			}
			children = append(children, converted)
		}
		return config.Condition{Type: typ, Children: children}, nil
	case config.ConditionDesktopID:
		return config.Condition{Type: typ, DesktopID: config.DesktopID(value)}, nil
	case config.ConditionExecutable:
		return config.Condition{Type: typ, Executable: config.Executable(value)}, nil
	case config.ConditionFlatpakID:
		return config.Condition{Type: typ, FlatpakID: config.FlatpakID(value)}, nil
	case config.ConditionSnapID:
		return config.Condition{Type: typ, SnapID: config.SnapID(value)}, nil
	case config.ConditionDomain:
		domain, err := config.NormalizeDomain(value)
		if err != nil {
			return config.Condition{}, err
		}
		return config.Condition{Type: typ, Domain: domain}, nil
	case config.ConditionWildcardDomain:
		wildcard, err := config.NormalizeWildcardDomain(value)
		if err != nil {
			return config.Condition{}, err
		}
		return config.Condition{Type: typ, Wildcard: wildcard}, nil
	case config.ConditionCIDR:
		prefix, err := parsePrefix(value)
		if err != nil {
			return config.Condition{}, err
		}
		return config.Condition{Type: typ, Prefix: prefix}, nil
	case config.ConditionProtocolPort:
		protocol, port, err := parseProtocolPort(value)
		if err != nil {
			return config.Condition{}, err
		}
		return config.Condition{Type: typ, Protocol: protocol, Port: port}, nil
	case config.ConditionUID:
		uid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return config.Condition{}, fmt.Errorf("invalid uid %q", value)
		}
		parsed := config.UID(uid)
		return config.Condition{Type: typ, UID: &parsed}, nil
	default:
		return config.Condition{}, fmt.Errorf("unsupported condition type %q", typ)
	}
}

func parsePrefix(value string) (netip.Prefix, error) {
	if value == "" {
		return netip.Prefix{}, errors.New("cidr is empty")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: %w", value, err)
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid ip %q: %w", value, err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseProtocolPort(value string) (config.Protocol, uint16, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("protocol_port %q must use \"<protocol>/<port>\"", value)
	}
	protocol := config.Protocol(strings.ToLower(parts[0]))
	if protocol != config.ProtocolTCP && protocol != config.ProtocolUDP {
		return "", 0, fmt.Errorf("unsupported protocol %q", parts[0])
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid port %q", parts[1])
	}
	return protocol, uint16(port), nil
}

func configToProto(cfg *config.Config) *proto.SplitTunnelConfig {
	if cfg == nil {
		return nil
	}
	settings := &proto.SplitTunnelSettings{
		Enabled:       cfg.SplitTunnel.Enabled,
		Mode:          string(cfg.SplitTunnel.Mode),
		DefaultAction: string(cfg.SplitTunnel.DefaultAction),
		KillSwitch:    string(cfg.SplitTunnel.KillSwitch),
		Ipv6:          cfg.SplitTunnel.IPv6,
		Dns: &proto.SplitTunnelDNSSettings{
			TrackingEnabled: cfg.SplitTunnel.DNS.TrackingEnabled,
			RespectTtl:      cfg.SplitTunnel.DNS.RespectTTL,
			ConflictPolicy:  string(cfg.SplitTunnel.DNS.ConflictPolicy),
			StrictMode:      cfg.SplitTunnel.DNS.StrictMode,
		},
		Rules: make([]*proto.SplitTunnelRule, 0, len(cfg.SplitTunnel.Rules)),
	}
	for i := range cfg.SplitTunnel.Rules {
		settings.Rules = append(settings.Rules, ruleToProto(&cfg.SplitTunnel.Rules[i]))
	}
	return &proto.SplitTunnelConfig{
		SchemaVersion: cfg.SchemaVersion,
		SplitTunnel:   settings,
	}
}

func ruleToProto(rule *config.Rule) *proto.SplitTunnelRule {
	out := &proto.SplitTunnelRule{
		Id:          string(rule.ID),
		Name:        rule.Name,
		Enabled:     rule.Enabled,
		Priority:    int32(rule.Priority),
		MatchMode:   string(rule.MatchMode),
		Action:      string(rule.Action),
		ExitNodeId:  string(rule.ExitNodeID),
		Description: rule.Description,
		Conditions:  make([]*proto.SplitTunnelCondition, 0, len(rule.Conditions)),
	}
	for i := range rule.Conditions {
		out.Conditions = append(out.Conditions, conditionToProto(&rule.Conditions[i]))
	}
	return out
}

func conditionToProto(condition *config.Condition) *proto.SplitTunnelCondition {
	out := &proto.SplitTunnelCondition{Type: string(condition.Type)}
	switch condition.Type {
	case config.ConditionAll, config.ConditionAny:
		out.Children = make([]*proto.SplitTunnelCondition, 0, len(condition.Children))
		for i := range condition.Children {
			out.Children = append(out.Children, conditionToProto(&condition.Children[i]))
		}
	case config.ConditionDesktopID:
		out.Value = string(condition.DesktopID)
	case config.ConditionExecutable:
		out.Value = string(condition.Executable)
	case config.ConditionFlatpakID:
		out.Value = string(condition.FlatpakID)
	case config.ConditionSnapID:
		out.Value = string(condition.SnapID)
	case config.ConditionDomain:
		out.Value = string(condition.Domain)
	case config.ConditionWildcardDomain:
		out.Value = "*." + string(condition.Wildcard)
	case config.ConditionCIDR:
		if condition.Prefix.IsValid() {
			out.Value = condition.Prefix.String()
		}
	case config.ConditionProtocolPort:
		out.Value = string(condition.Protocol) + "/" + strconv.FormatUint(uint64(condition.Port), 10)
	case config.ConditionUID:
		if condition.UID != nil {
			out.Value = strconv.FormatUint(uint64(*condition.UID), 10)
		}
	}
	return out
}

func applicationToProto(app application.Application) *proto.SplitTunnelApplication {
	return &proto.SplitTunnelApplication{
		DesktopId:   app.DesktopID,
		Name:        app.Name,
		IconName:    app.Icon.Name,
		IconPath:    app.Icon.Path,
		Executable:  app.Executable,
		InstallType: string(app.InstallType),
		SourcePath:  app.SourcePath,
		NoDisplay:   app.NoDisplay,
		Unknown:     app.Unknown,
	}
}

func matchesApplication(app application.Application, query string) bool {
	if query == "" {
		return true
	}
	query = strings.ToLower(query)
	return strings.Contains(strings.ToLower(app.DesktopID), query) ||
		strings.Contains(strings.ToLower(app.Name), query)
}
