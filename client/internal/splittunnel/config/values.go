package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxDomainLength   = 253
	maxDomainLabel    = 63
	maxSnapNameLength = 40
	maxPriority       = 1_000_000
)

// NormalizeDomain validates a DNS name and returns its canonical form: lower
// case, without a trailing dot. Wildcards and IP literals are rejected.
func NormalizeDomain(name string) (Domain, error) {
	normalized, err := normalizeDomain(name)
	if err != nil {
		return "", err
	}
	return Domain(normalized), nil
}

// NormalizeWildcardDomain validates a wildcard DNS pattern such as
// "*.example.com" and returns its canonical base name.
func NormalizeWildcardDomain(pattern string) (WildcardDomain, error) {
	if pattern == "" {
		return "", errors.New("wildcard domain is empty")
	}
	if !strings.HasPrefix(pattern, "*.") {
		return "", errors.New("wildcard domain must start with \"*.\"")
	}
	if strings.Count(pattern, "*") != 1 {
		return "", errors.New("wildcard domain must contain exactly one wildcard")
	}
	base, err := normalizeDomain(strings.TrimPrefix(pattern, "*."))
	if err != nil {
		return "", fmt.Errorf("wildcard base: %w", err)
	}
	return WildcardDomain(base), nil
}

func normalizeDomain(name string) (string, error) {
	if name == "" {
		return "", errors.New("domain is empty")
	}
	if name != strings.TrimSpace(name) {
		return "", errors.New("domain must not have surrounding whitespace")
	}
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)
	if name == "" {
		return "", errors.New("domain is empty")
	}
	if len(name) > maxDomainLength {
		return "", fmt.Errorf("domain is longer than %d characters", maxDomainLength)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("domain must not be an IP literal; use a cidr condition")
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return "", errors.New("domain has an empty label")
		}
		if len(label) > maxDomainLabel {
			return "", fmt.Errorf("domain label is longer than %d characters", maxDomainLabel)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain label %q starts or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if !isLowerAlphaNumeric(ch) && ch != '-' {
				return "", fmt.Errorf("domain label %q contains invalid character %q", label, ch)
			}
		}
	}
	return name, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	if value == "" {
		return netip.Prefix{}, errors.New("cidr is empty")
	}

	var prefix netip.Prefix
	if strings.Contains(value, "/") {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: %w", value, err)
		}
		prefix = parsed
	} else {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid ip %q: %w", value, err)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid cidr %q", value)
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("cidr must not contain a zone")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("cidr must use a plain IPv4 address")
	}
	if prefix.Masked() != prefix {
		return netip.Prefix{}, fmt.Errorf("cidr %q has host bits set; use the network address", value)
	}
	return prefix, nil
}

func parseProtocolPort(value string) (Protocol, uint16, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("protocol_port %q must use \"<protocol>/<port>\"", value)
	}

	protocol := Protocol(strings.ToLower(parts[0]))
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return "", 0, fmt.Errorf("unsupported protocol %q; use tcp or udp", parts[0])
	}

	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid port %q; use 1-65535", parts[1])
	}
	return protocol, uint16(port), nil
}

func parseUID(value string) (UID, error) {
	uid, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid uid %q", value)
	}
	return UID(uid), nil
}

func validateRuleID(id RuleID, maxLen int) error {
	s := string(id)
	if s == "" {
		return errors.New("is required")
	}
	if len(s) > maxLen {
		return fmt.Errorf("is longer than %d characters", maxLen)
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !isAlphaNumeric(ch) && ch != '.' && ch != '_' && ch != ':' && ch != '-' {
			return fmt.Errorf("contains invalid character %q", ch)
		}
	}
	return nil
}

func validateDesktopID(id DesktopID, maxLen int) error {
	s := string(id)
	if s == "" {
		return errors.New("desktop ID is empty")
	}
	if len(s) > maxLen {
		return fmt.Errorf("desktop ID is longer than %d characters", maxLen)
	}
	if !strings.HasSuffix(s, ".desktop") || len(s) == len(".desktop") {
		return errors.New("desktop ID must end with .desktop and have a name")
	}
	if strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
		return errors.New("desktop ID must not contain a path separator or \"..\"")
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !isAlphaNumeric(ch) && ch != '.' && ch != '_' && ch != '-' {
			return fmt.Errorf("desktop ID contains invalid character %q", ch)
		}
	}
	return nil
}

func validateExecutable(executable Executable, maxLen int) error {
	s := string(executable)
	if s == "" {
		return errors.New("executable path is empty")
	}
	if len(s) > maxLen {
		return fmt.Errorf("executable path is longer than %d characters", maxLen)
	}
	if !utf8.ValidString(s) {
		return errors.New("executable path is not valid UTF-8")
	}
	for _, ch := range s {
		if unicode.IsControl(ch) {
			return errors.New("executable path must not contain control characters")
		}
	}
	if !path.IsAbs(s) {
		return errors.New("executable path must be absolute")
	}
	if s == "/" {
		return errors.New("executable path must not be the root directory")
	}
	if path.Clean(s) != s {
		return errors.New("executable path must be canonical")
	}
	return nil
}

func validateFlatpakID(id FlatpakID, maxLen int) error {
	s := string(id)
	if s == "" {
		return errors.New("flatpak ID is empty")
	}
	if len(s) > maxLen {
		return fmt.Errorf("flatpak ID is longer than %d characters", maxLen)
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return errors.New("flatpak ID must have at least two components")
	}
	for _, part := range parts {
		if part == "" {
			return errors.New("flatpak ID has an empty component")
		}
		if len(part) > maxDomainLabel {
			return fmt.Errorf("flatpak ID component is longer than %d characters", maxDomainLabel)
		}
		first := part[0]
		if !isAlphaNumeric(first) && first != '_' {
			return fmt.Errorf("flatpak ID component %q must start with a letter", part)
		}
		for i := 0; i < len(part); i++ {
			ch := part[i]
			if !isAlphaNumeric(ch) && ch != '_' && ch != '-' {
				return fmt.Errorf("flatpak ID component %q contains invalid character %q", part, ch)
			}
		}
	}
	return nil
}

func validateSnapID(id SnapID, maxLen int) error {
	s := string(id)
	if s == "" {
		return errors.New("snap name is empty")
	}
	if len(s) > maxSnapNameLength {
		return fmt.Errorf("snap name is longer than %d characters", maxSnapNameLength)
	}
	if len(s) > maxLen {
		return fmt.Errorf("snap name is longer than %d characters", maxLen)
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return errors.New("snap name must not start or end with a hyphen")
	}
	if strings.Contains(s, "--") {
		return errors.New("snap name must not contain consecutive hyphens")
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !isLowerAlphaNumeric(ch) && ch != '-' {
			return fmt.Errorf("snap name contains invalid character %q", ch)
		}
	}
	return nil
}

func isAlphaNumeric(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func isLowerAlphaNumeric(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
}
