package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Parse decodes and validates a configuration document using DefaultLimits.
func Parse(data []byte) (*Config, error) {
	return ParseWithLimits(data, DefaultLimits())
}

// ParseWithLimits decodes and validates a configuration document with explicit
// limits. Unknown fields, unsupported schema versions and invalid values are
// rejected.
func ParseWithLimits(data []byte, limits Limits) (*Config, error) {
	limits = limits.withDefaults()
	if int64(len(data)) > limits.MaxConfigBytes {
		return nil, fmt.Errorf("parse config: document is %d bytes, limit is %d",
			len(data), limits.MaxConfigBytes)
	}

	version, err := schemaVersion(data)
	if err != nil {
		return nil, err
	}
	if version != CurrentSchemaVersion {
		data, err = migrate(data, version)
		if err != nil {
			return nil, err
		}
	}

	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Encode validates the configuration and returns its canonical JSON form.
func (c *Config) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return append(out, '\n'), nil
}

// schemaVersion extracts and checks the document schema version without
// applying the current schema's strict field rules.
func schemaVersion(data []byte) (uint32, error) {
	var header struct {
		SchemaVersion *uint32 `json:"schemaVersion"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&header); err != nil {
		return 0, fmt.Errorf("parse config: %w", err)
	}
	if header.SchemaVersion == nil {
		return 0, errors.New("parse config: schemaVersion is required")
	}
	version := *header.SchemaVersion
	if version == 0 {
		return 0, errors.New("parse config: schemaVersion must be positive")
	}
	if version > CurrentSchemaVersion {
		return 0, fmt.Errorf("parse config: schema version %d is newer than supported version %d",
			version, CurrentSchemaVersion)
	}
	return version, nil
}

// migrate upgrades an older document to the current schema. No older schema
// exists yet; future versions chain their migrations here.
func migrate(_ []byte, from uint32) ([]byte, error) {
	return nil, fmt.Errorf("parse config: schema version %d requires a migration that is not implemented",
		from)
}

// decodeConfig decodes the current schema with unknown fields rejected.
func decodeConfig(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// requireEOF rejects trailing data after the first JSON document.
func requireEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return errors.New("parse config: unexpected trailing JSON value")
}

// conditionWire is the on-disk representation of a condition. Pointers
// distinguish omitted fields from empty values.
type conditionWire struct {
	Type       ConditionType      `json:"type"`
	Value      *string            `json:"value,omitempty"`
	Conditions *[]json.RawMessage `json:"conditions,omitempty"`
}

// UnmarshalJSON decodes a condition strictly, including nested composites.
func (c *Condition) UnmarshalJSON(data []byte) error {
	parsed, err := decodeCondition(data)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MarshalJSON writes the canonical on-disk representation of a condition.
func (c Condition) MarshalJSON() ([]byte, error) {
	wire, err := c.toWire()
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

func decodeCondition(data []byte) (Condition, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var wire conditionWire
	if err := dec.Decode(&wire); err != nil {
		return Condition{}, err
	}
	if err := requireEOF(dec); err != nil {
		return Condition{}, err
	}
	return wire.toCondition()
}

func (w conditionWire) toCondition() (Condition, error) {
	if w.Type == "" {
		return Condition{}, errors.New("condition type is required")
	}

	switch w.Type {
	case ConditionAll, ConditionAny:
		return w.toComposite()
	default:
		return w.toSimple()
	}
}

func (w conditionWire) toComposite() (Condition, error) {
	if w.Value != nil {
		return Condition{}, fmt.Errorf("%s condition must not have a value", w.Type)
	}
	if w.Conditions == nil {
		return Condition{}, fmt.Errorf("%s condition requires conditions", w.Type)
	}
	raw := *w.Conditions
	if len(raw) == 0 {
		return Condition{}, fmt.Errorf("%s condition must have at least one child", w.Type)
	}

	children := make([]Condition, 0, len(raw))
	for i, item := range raw {
		child, err := decodeCondition(item)
		if err != nil {
			return Condition{}, fmt.Errorf("child %d: %w", i, err)
		}
		children = append(children, child)
	}
	return Condition{Type: w.Type, Children: children}, nil
}

func (w conditionWire) toSimple() (Condition, error) {
	if w.Conditions != nil {
		return Condition{}, fmt.Errorf("%s condition must not have children", w.Type)
	}
	if w.Value == nil {
		return Condition{}, fmt.Errorf("%s condition requires a value", w.Type)
	}

	value := *w.Value
	condition := Condition{Type: w.Type}
	switch w.Type {
	case ConditionDesktopID:
		condition.DesktopID = DesktopID(value)
	case ConditionExecutable:
		condition.Executable = Executable(value)
	case ConditionFlatpakID:
		condition.FlatpakID = FlatpakID(value)
	case ConditionSnapID:
		condition.SnapID = SnapID(value)
	case ConditionDomain:
		if strings.HasPrefix(value, "*.") {
			wildcard, err := NormalizeWildcardDomain(value)
			if err != nil {
				return Condition{}, err
			}
			condition.Type = ConditionWildcardDomain
			condition.Wildcard = wildcard
			return condition, nil
		}
		domain, err := NormalizeDomain(value)
		if err != nil {
			return Condition{}, err
		}
		condition.Domain = domain
	case ConditionWildcardDomain:
		wildcard, err := NormalizeWildcardDomain(value)
		if err != nil {
			return Condition{}, err
		}
		condition.Wildcard = wildcard
	case ConditionCIDR:
		prefix, err := parsePrefix(value)
		if err != nil {
			return Condition{}, err
		}
		condition.Prefix = prefix
	case ConditionProtocolPort:
		protocol, port, err := parseProtocolPort(value)
		if err != nil {
			return Condition{}, err
		}
		condition.Protocol = protocol
		condition.Port = port
	case ConditionUID:
		uid, err := parseUID(value)
		if err != nil {
			return Condition{}, err
		}
		condition.UID = &uid
	default:
		return Condition{}, fmt.Errorf("unknown condition type %q", w.Type)
	}
	return condition, nil
}

func (c Condition) toWire() (conditionWire, error) {
	wire := conditionWire{Type: c.Type}
	value, err := c.valueString()
	if err != nil {
		return conditionWire{}, err
	}

	switch c.Type {
	case ConditionAll, ConditionAny:
		raw := make([]json.RawMessage, 0, len(c.Children))
		for i := range c.Children {
			encoded, err := c.Children[i].MarshalJSON()
			if err != nil {
				return conditionWire{}, err
			}
			raw = append(raw, encoded)
		}
		wire.Conditions = &raw
	default:
		wire.Value = &value
	}
	return wire, nil
}

func (c Condition) valueString() (string, error) {
	switch c.Type {
	case ConditionDesktopID:
		return string(c.DesktopID), nil
	case ConditionExecutable:
		return string(c.Executable), nil
	case ConditionFlatpakID:
		return string(c.FlatpakID), nil
	case ConditionSnapID:
		return string(c.SnapID), nil
	case ConditionDomain:
		return string(c.Domain), nil
	case ConditionWildcardDomain:
		return "*." + string(c.Wildcard), nil
	case ConditionCIDR:
		if !c.Prefix.IsValid() {
			return "", errors.New("cidr condition has no valid prefix")
		}
		return c.Prefix.String(), nil
	case ConditionProtocolPort:
		return string(c.Protocol) + "/" + strconv.FormatUint(uint64(c.Port), 10), nil
	case ConditionUID:
		if c.UID == nil {
			return "", errors.New("uid condition has no user ID")
		}
		return strconv.FormatUint(uint64(*c.UID), 10), nil
	case ConditionAll, ConditionAny:
		return "", nil
	default:
		return "", fmt.Errorf("unknown condition type %q", c.Type)
	}
}
