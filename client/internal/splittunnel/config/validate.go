package config

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// FieldError identifies a configuration field that failed validation.
type FieldError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *FieldError) Error() string {
	return e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying validation error.
func (e *FieldError) Unwrap() error {
	return e.Err
}

// Validate checks the configuration with DefaultLimits.
func (c *Config) Validate() error {
	return c.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks the schema version, modes, actions, rules,
// conditions and size limits of the configuration.
func (c *Config) ValidateWithLimits(limits Limits) error {
	if c == nil {
		return &FieldError{Path: "config", Err: errors.New("is nil")}
	}
	if c.SchemaVersion != CurrentSchemaVersion {
		return fail("schemaVersion", "must be %d", CurrentSchemaVersion)
	}
	return c.SplitTunnel.validate(limits.withDefaults())
}

func (s *SplitTunnel) validate(limits Limits) error {
	if !s.Mode.valid() {
		return fail("splitTunnel.mode", "unsupported mode %q", s.Mode)
	}
	if s.Mode == ModeStandard && s.Enabled {
		return fail("splitTunnel.enabled", "must be false in standard mode")
	}
	if err := s.validateDefaultAction(); err != nil {
		return err
	}
	if s.KillSwitch != "" && !s.KillSwitch.valid() {
		return fail("splitTunnel.killSwitch", "unsupported kill switch mode %q", s.KillSwitch)
	}
	if s.DNS.ConflictPolicy != "" && !s.DNS.ConflictPolicy.valid() {
		return fail("splitTunnel.dns.conflictPolicy", "unsupported conflict policy %q",
			s.DNS.ConflictPolicy)
	}

	if len(s.Rules) > limits.MaxRules {
		return fail("splitTunnel.rules", "has %d rules, limit is %d", len(s.Rules), limits.MaxRules)
	}

	seen := make(map[RuleID]struct{}, len(s.Rules))
	total := 0
	for i := range s.Rules {
		rule := &s.Rules[i]
		path := fmt.Sprintf("splitTunnel.rules[%d]", i)
		if _, ok := seen[rule.ID]; ok {
			return fail(path+".id", "duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}

		count, err := rule.validate(s.Mode, path, limits)
		if err != nil {
			return err
		}
		total += count
		if total > limits.MaxTotalConditions {
			return fail("splitTunnel.rules", "has %d conditions, limit is %d",
				total, limits.MaxTotalConditions)
		}
	}
	return nil
}

func (s *SplitTunnel) validateDefaultAction() error {
	switch s.Mode {
	case ModeStandard:
		if s.DefaultAction != "" && s.DefaultAction != ActionDefault {
			return fail("splitTunnel.defaultAction", "must be omitted or %q in standard mode",
				ActionDefault)
		}
	case ModeInclude:
		if s.DefaultAction != ActionDirect {
			return fail("splitTunnel.defaultAction", "must be %q in include mode", ActionDirect)
		}
	case ModeExclude:
		if s.DefaultAction != ActionVPN {
			return fail("splitTunnel.defaultAction", "must be %q in exclude mode", ActionVPN)
		}
	case ModeCustom:
		switch s.DefaultAction {
		case ActionVPN, ActionDirect, ActionBlock:
		default:
			return fail("splitTunnel.defaultAction",
				"must be vpn, direct or block in custom mode, got %q", s.DefaultAction)
		}
	}
	return nil
}

func (r *Rule) validate(mode Mode, path string, limits Limits) (int, error) {
	if err := validateRuleID(r.ID, limits.MaxIDLength); err != nil {
		return 0, &FieldError{Path: path + ".id", Err: err}
	}
	if err := validateText(r.Name, limits.MaxNameLength, true); err != nil {
		return 0, &FieldError{Path: path + ".name", Err: err}
	}
	if err := validateText(r.Description, limits.MaxDescriptionLength, false); err != nil {
		return 0, &FieldError{Path: path + ".description", Err: err}
	}
	if r.Priority < 0 || r.Priority > maxPriority {
		return 0, fail(path+".priority", "must be between 0 and %d", maxPriority)
	}
	if r.MatchMode != "" && r.MatchMode != MatchAll && r.MatchMode != MatchAny {
		return 0, fail(path+".matchMode", "unsupported match mode %q", r.MatchMode)
	}
	if !r.Action.valid() {
		return 0, fail(path+".action", "unsupported action %q", r.Action)
	}
	if err := r.validateAction(mode, path); err != nil {
		return 0, err
	}
	if err := r.validateExitNode(path, limits); err != nil {
		return 0, err
	}
	if len(r.Conditions) == 0 {
		return 0, fail(path+".conditions", "must have at least one condition")
	}

	total := 0
	for i := range r.Conditions {
		count, err := validateCondition(&r.Conditions[i],
			fmt.Sprintf("%s.conditions[%d]", path, i), 0, limits)
		if err != nil {
			return 0, err
		}
		total += count
		if total > limits.MaxConditionsPerRule {
			return 0, fail(path+".conditions", "has %d conditions, limit is %d",
				total, limits.MaxConditionsPerRule)
		}
	}
	return total, nil
}

func (r *Rule) validateAction(mode Mode, path string) error {
	if mode == ModeStandard {
		if r.Enabled {
			return fail(path+".enabled", "rules are not evaluated in standard mode")
		}
		return nil
	}

	switch mode {
	case ModeInclude, ModeExclude:
		if r.Action == ActionDefault {
			return fail(path+".action",
				"action %q duplicates the global default in %s mode", r.Action, mode)
		}
		return nil
	case ModeCustom:
		return nil
	default:
		return fail("splitTunnel.mode", "unsupported mode %q", mode)
	}
}

func (r *Rule) validateExitNode(path string, limits Limits) error {
	if r.Action == ActionExitNode {
		if err := validateRuleID(RuleID(r.ExitNodeID), limits.MaxIDLength); err != nil {
			return &FieldError{Path: path + ".exitNodeId", Err: err}
		}
		return nil
	}
	if r.ExitNodeID != "" {
		return fail(path+".exitNodeId", "is only valid with the exit_node action")
	}
	return nil
}

func validateCondition(c *Condition, path string, depth int, limits Limits) (int, error) {
	if !c.Type.valid() {
		return 0, fail(path+".type", "unsupported condition type %q", c.Type)
	}
	if groups := c.fieldGroups(); groups != 1 {
		return 0, fail(path, "must set exactly one condition value, got %d", groups)
	}

	switch c.Type {
	case ConditionAll, ConditionAny:
		if depth >= limits.MaxCompositeDepth {
			return 0, fail(path, "composite nesting exceeds depth %d",
				limits.MaxCompositeDepth)
		}
		if len(c.Children) == 0 {
			return 0, fail(path+".conditions", "must have at least one child")
		}
		total := 1
		for i := range c.Children {
			count, err := validateCondition(&c.Children[i],
				fmt.Sprintf("%s.conditions[%d]", path, i), depth+1, limits)
			if err != nil {
				return 0, err
			}
			total += count
		}
		return total, nil
	default:
		if len(c.Children) != 0 {
			return 0, fail(path+".conditions", "is only valid for all or any conditions")
		}
		if err := c.validateValue(path, limits); err != nil {
			return 0, err
		}
		return 1, nil
	}
}

func (c *Condition) validateValue(path string, limits Limits) error {
	switch c.Type {
	case ConditionDesktopID:
		return fieldErr(path+".value", validateDesktopID(c.DesktopID, limits.MaxValueLength))
	case ConditionExecutable:
		return fieldErr(path+".value", validateExecutable(c.Executable, limits.MaxValueLength))
	case ConditionFlatpakID:
		return fieldErr(path+".value", validateFlatpakID(c.FlatpakID, limits.MaxValueLength))
	case ConditionSnapID:
		return fieldErr(path+".value", validateSnapID(c.SnapID, limits.MaxValueLength))
	case ConditionDomain:
		normalized, err := NormalizeDomain(string(c.Domain))
		if err != nil {
			return fieldErr(path+".value", err)
		}
		if normalized != c.Domain {
			return fail(path+".value", "must be normalized to %q", normalized)
		}
		return nil
	case ConditionWildcardDomain:
		normalized, err := NormalizeWildcardDomain("*." + string(c.Wildcard))
		if err != nil {
			return fieldErr(path+".value", err)
		}
		if normalized != c.Wildcard {
			return fail(path+".value", "must be normalized to %q", normalized)
		}
		return nil
	case ConditionCIDR:
		if !c.Prefix.IsValid() {
			return fail(path+".value", "cidr prefix is invalid")
		}
		if c.Prefix.Addr().Zone() != "" {
			return fail(path+".value", "cidr must not contain a zone")
		}
		if c.Prefix.Addr().Is4In6() {
			return fail(path+".value", "cidr must use a plain IPv4 address")
		}
		if c.Prefix.Masked() != c.Prefix {
			return fail(path+".value", "cidr has host bits set; use the network address")
		}
		return nil
	case ConditionProtocolPort:
		if c.Protocol != ProtocolTCP && c.Protocol != ProtocolUDP {
			return fail(path+".value", "unsupported protocol %q", c.Protocol)
		}
		if c.Port == 0 {
			return fail(path+".value", "port must be between 1 and 65535")
		}
		return nil
	case ConditionUID:
		if c.UID == nil {
			return fail(path+".value", "uid is required")
		}
		return nil
	case ConditionAll, ConditionAny:
		return fail(path, "composite conditions do not have a value")
	default:
		return fail(path+".type", "unsupported condition type %q", c.Type)
	}
}

func (c *Condition) fieldGroups() int {
	groups := 0
	if c.DesktopID != "" {
		groups++
	}
	if c.Executable != "" {
		groups++
	}
	if c.FlatpakID != "" {
		groups++
	}
	if c.SnapID != "" {
		groups++
	}
	if c.Domain != "" {
		groups++
	}
	if c.Wildcard != "" {
		groups++
	}
	if c.Prefix.IsValid() {
		groups++
	}
	if c.Protocol != "" || c.Port != 0 {
		groups++
	}
	if c.UID != nil {
		groups++
	}
	if len(c.Children) != 0 {
		groups++
	}
	return groups
}

func (m Mode) valid() bool {
	switch m {
	case ModeStandard, ModeInclude, ModeExclude, ModeCustom:
		return true
	default:
		return false
	}
}

func (a Action) valid() bool {
	switch a {
	case ActionVPN, ActionDirect, ActionBlock, ActionExitNode, ActionDefault:
		return true
	default:
		return false
	}
}

func (k KillSwitchMode) valid() bool {
	switch k {
	case KillSwitchDisabled, KillSwitchSelective, KillSwitchGlobal, KillSwitchStrict:
		return true
	default:
		return false
	}
}

func (p ConflictPolicy) valid() bool {
	switch p {
	case ConflictVPN, ConflictDirect, ConflictBlock:
		return true
	default:
		return false
	}
}

func (t ConditionType) valid() bool {
	switch t {
	case ConditionDesktopID, ConditionExecutable, ConditionFlatpakID, ConditionSnapID,
		ConditionDomain, ConditionWildcardDomain, ConditionCIDR, ConditionProtocolPort,
		ConditionUID, ConditionAll, ConditionAny:
		return true
	default:
		return false
	}
}

func validateText(value string, maxLen int, required bool) error {
	if value == "" {
		if required {
			return errors.New("is required")
		}
		return nil
	}
	if len(value) > maxLen {
		return fmt.Errorf("is longer than %d characters", maxLen)
	}
	if !utf8.ValidString(value) {
		return errors.New("is not valid UTF-8")
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

func fail(path, format string, args ...any) error {
	return &FieldError{Path: path, Err: fmt.Errorf(format, args...)}
}

func fieldErr(path string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldError{Path: path, Err: err}
}
