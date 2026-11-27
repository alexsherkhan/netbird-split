// Package config defines the versioned split tunnel configuration model and
// its validation rules.
//
// The model is deliberately independent of the client, kernel, IPC and UI
// layers so that configuration can be imported, exported and validated in
// isolation. Parsing rejects unknown fields, enforces the schema version and
// applies the limits in Limits. Conditions store parsed values: IP prefixes
// use netip.Prefix, ports use uint16 and user IDs use UID.
package config

import "net/netip"

// CurrentSchemaVersion is the schema version written by this package.
const CurrentSchemaVersion uint32 = 1

// Mode selects how split tunnel rules are interpreted.
type Mode string

const (
	// ModeStandard disables split tunneling and defers routing to upstream.
	ModeStandard Mode = "standard"
	// ModeInclude sends matched rules through the VPN and everything else
	// directly to the Internet.
	ModeInclude Mode = "include"
	// ModeExclude sends matched rules directly to the Internet and everything
	// else through the VPN.
	ModeExclude Mode = "exclude"
	// ModeCustom allows all supported actions in rules and chooses the default
	// action explicitly.
	ModeCustom Mode = "custom"
)

// Action is the routing decision produced by a rule or the global default.
type Action string

const (
	// ActionVPN routes traffic through the NetBird overlay.
	ActionVPN Action = "vpn"
	// ActionDirect routes traffic through the physical interface.
	ActionDirect Action = "direct"
	// ActionBlock drops traffic.
	ActionBlock Action = "block"
	// ActionExitNode routes traffic through the configured exit node.
	ActionExitNode Action = "exit_node"
	// ActionDefault defers to the global default action.
	ActionDefault Action = "default"
)

// KillSwitchMode selects the protection level applied when the tunnel fails.
type KillSwitchMode string

const (
	// KillSwitchDisabled does not install failure protection.
	KillSwitchDisabled KillSwitchMode = "disabled"
	// KillSwitchSelective protects only traffic selected for the VPN.
	KillSwitchSelective KillSwitchMode = "selective"
	// KillSwitchGlobal protects all Internet traffic.
	KillSwitchGlobal KillSwitchMode = "global"
	// KillSwitchStrict protects all traffic except explicitly allowed direct
	// traffic.
	KillSwitchStrict KillSwitchMode = "strict"
)

// MatchMode selects how a rule combines its conditions.
type MatchMode string

const (
	// MatchAll requires every condition to match.
	MatchAll MatchMode = "all"
	// MatchAny requires at least one condition to match.
	MatchAny MatchMode = "any"
)

// ConditionType identifies the kind of value a Condition carries.
type ConditionType string

const (
	// ConditionDesktopID matches an XDG desktop entry ID.
	ConditionDesktopID ConditionType = "desktop_id"
	// ConditionExecutable matches an executable path.
	ConditionExecutable ConditionType = "executable"
	// ConditionFlatpakID matches a Flatpak application ID.
	ConditionFlatpakID ConditionType = "flatpak_id"
	// ConditionSnapID matches a Snap package name.
	ConditionSnapID ConditionType = "snap_id"
	// ConditionDomain matches an exact DNS name.
	ConditionDomain ConditionType = "domain"
	// ConditionWildcardDomain matches subdomains of a DNS name.
	ConditionWildcardDomain ConditionType = "wildcard_domain"
	// ConditionCIDR matches an IP address or CIDR prefix.
	ConditionCIDR ConditionType = "cidr"
	// ConditionProtocolPort matches an IP protocol and destination port.
	ConditionProtocolPort ConditionType = "protocol_port"
	// ConditionUID matches a Linux user ID.
	ConditionUID ConditionType = "uid"
	// ConditionAll combines child conditions with logical AND.
	ConditionAll ConditionType = "all"
	// ConditionAny combines child conditions with logical OR.
	ConditionAny ConditionType = "any"
)

// Protocol is an IP transport protocol supported by protocol/port conditions.
type Protocol string

const (
	// ProtocolTCP is the Transmission Control Protocol.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP is the User Datagram Protocol.
	ProtocolUDP Protocol = "udp"
)

// ConflictPolicy selects how a domain resolving to a shared IP is handled.
type ConflictPolicy string

const (
	// ConflictVPN prefers VPN routing for shared addresses.
	ConflictVPN ConflictPolicy = "vpn"
	// ConflictDirect prefers direct routing for shared addresses.
	ConflictDirect ConflictPolicy = "direct"
	// ConflictBlock blocks shared addresses.
	ConflictBlock ConflictPolicy = "block"
)

// RuleID identifies a rule within one configuration.
type RuleID string

// ExitNodeID identifies an exit node selected by an exit_node rule.
type ExitNodeID string

// DesktopID is an XDG desktop entry ID such as "firefox.desktop".
type DesktopID string

// Executable is an absolute executable path.
type Executable string

// FlatpakID is a Flatpak application ID such as "org.mozilla.firefox".
type FlatpakID string

// SnapID is a Snap package name such as "firefox".
type SnapID string

// UID is a Linux user ID.
type UID uint32

// Domain is a canonical exact DNS name: lower case, without a trailing dot.
type Domain string

// WildcardDomain is the canonical base of a wildcard DNS name. It matches
// subdomains of the base but not the base itself.
type WildcardDomain string

// Config is the root of the versioned split tunnel configuration document.
type Config struct {
	SchemaVersion uint32      `json:"schemaVersion"`
	SplitTunnel   SplitTunnel `json:"splitTunnel"`
}

// SplitTunnel holds the split tunnel engine settings and user rules.
type SplitTunnel struct {
	Enabled       bool           `json:"enabled"`
	Mode          Mode           `json:"mode"`
	DefaultAction Action         `json:"defaultAction,omitempty"`
	KillSwitch    KillSwitchMode `json:"killSwitch,omitempty"`
	IPv6          bool           `json:"ipv6"`
	DNS           DNSSettings    `json:"dns"`
	Rules         []Rule         `json:"rules,omitempty"`
}

// DNSSettings controls domain tracking and shared-address conflict handling.
type DNSSettings struct {
	TrackingEnabled bool           `json:"trackingEnabled"`
	RespectTTL      bool           `json:"respectTTL"`
	ConflictPolicy  ConflictPolicy `json:"conflictPolicy,omitempty"`
	StrictMode      bool           `json:"strictMode"`
}

// Rule is one ordered policy rule. Lower Priority values take precedence; RuleID
// breaks ties.
type Rule struct {
	ID          RuleID      `json:"id"`
	Name        string      `json:"name"`
	Enabled     bool        `json:"enabled"`
	Priority    int         `json:"priority"`
	MatchMode   MatchMode   `json:"matchMode,omitempty"`
	Conditions  []Condition `json:"conditions"`
	Action      Action      `json:"action"`
	ExitNodeID  ExitNodeID  `json:"exitNodeId,omitempty"`
	Description string      `json:"description,omitempty"`
}

// Condition is a typed match condition. Exactly one value field is populated
// according to Type; composite conditions populate Children instead.
type Condition struct {
	Type       ConditionType
	DesktopID  DesktopID
	Executable Executable
	FlatpakID  FlatpakID
	SnapID     SnapID
	Domain     Domain
	Wildcard   WildcardDomain
	Prefix     netip.Prefix
	Protocol   Protocol
	Port       uint16
	UID        *UID
	Children   []Condition
}

// Limits bounds a configuration document before it is accepted. Zero values
// are replaced by DefaultLimits.
type Limits struct {
	MaxRules             int
	MaxConditionsPerRule int
	MaxTotalConditions   int
	MaxCompositeDepth    int
	MaxIDLength          int
	MaxNameLength        int
	MaxDescriptionLength int
	MaxValueLength       int
	MaxConfigBytes       int64
}

// DefaultLimits returns the production limits for imported configurations.
func DefaultLimits() Limits {
	return Limits{
		// Spec section 19 requires at least 10,000 supported rules.
		MaxRules:             10_000,
		MaxConditionsPerRule: 64,
		MaxTotalConditions:   100_000,
		MaxCompositeDepth:    4,
		MaxIDLength:          128,
		MaxNameLength:        256,
		MaxDescriptionLength: 1024,
		MaxValueLength:       512,
		MaxConfigBytes:       16 << 20,
	}
}

// withDefaults replaces non-positive limit fields with their defaults.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxRules <= 0 {
		l.MaxRules = d.MaxRules
	}
	if l.MaxConditionsPerRule <= 0 {
		l.MaxConditionsPerRule = d.MaxConditionsPerRule
	}
	if l.MaxTotalConditions <= 0 {
		l.MaxTotalConditions = d.MaxTotalConditions
	}
	if l.MaxCompositeDepth <= 0 {
		l.MaxCompositeDepth = d.MaxCompositeDepth
	}
	if l.MaxIDLength <= 0 {
		l.MaxIDLength = d.MaxIDLength
	}
	if l.MaxNameLength <= 0 {
		l.MaxNameLength = d.MaxNameLength
	}
	if l.MaxDescriptionLength <= 0 {
		l.MaxDescriptionLength = d.MaxDescriptionLength
	}
	if l.MaxValueLength <= 0 {
		l.MaxValueLength = d.MaxValueLength
	}
	if l.MaxConfigBytes <= 0 {
		l.MaxConfigBytes = d.MaxConfigBytes
	}
	return l
}
