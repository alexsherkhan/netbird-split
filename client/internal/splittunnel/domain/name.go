// Package domain tracks DNS names for split tunnel domain and wildcard rules.
//
// The tracker observes A, AAAA and CNAME answers returned by the NetBird DNS
// handler chain and materialises the resolved addresses into backend-owned
// timeout sets. It keeps per-answer expiry and reference counts so an address
// shared by several names is removed only after the last reference expires.
//
// # Limitations
//
// The tracker can only observe answers that pass through the NetBird resolver.
// Encrypted DNS (DoH and DoT), Encrypted Client Hello (ECH), and answers cached
// by an application, the operating system, or another resolver are not
// observed. A missed answer cannot update a kernel set, so an application can
// keep using an address after the client stopped tracking it. The tracker does
// not inspect TLS or DNS payloads and does not intercept encrypted queries.
//
// A wildcard pattern covers subdomains only; it never covers the apex name.
// Incomplete CNAME chains, where the answer contains a CNAME without the
// canonical address records, are not resolved by this package.
//
// Kernel elements carry their own timeout, and the tracker prunes expired
// references when it observes a response. Callers should also invoke Sweep
// periodically so a shared address is removed and conflicting actions are
// recomputed even when no new DNS query arrives.
package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxDomainLength = 253
	maxDomainLabel  = 63
)

// Name is a canonical exact DNS name: lower case, Punycode, no trailing dot.
type Name string

// Wildcard is the canonical base of a wildcard DNS name. The pattern
// "*.example.com" is stored as "example.com" and never matches the apex.
type Wildcard string

// Pattern is one exact or wildcard domain selector.
type Pattern struct {
	Name     Name
	Wildcard bool
}

// String returns the canonical selector, including the wildcard prefix.
func (p Pattern) String() string {
	if p.Wildcard {
		return "*." + string(p.Name)
	}
	return string(p.Name)
}

// Normalize validates an exact DNS name and returns its canonical form. The
// name is mapped to lower case and to Punycode so IDN input and its A-label
// form compare equal.
func Normalize(raw string) (Name, error) {
	normalized, err := normalize(raw)
	if err != nil {
		return "", err
	}
	return Name(normalized), nil
}

// NormalizeWildcard validates a wildcard pattern such as "*.example.com" and
// returns its canonical base name.
func NormalizeWildcard(pattern string) (Wildcard, error) {
	if pattern == "" {
		return "", errors.New("wildcard domain is empty")
	}
	if !strings.HasPrefix(pattern, "*.") {
		return "", errors.New("wildcard domain must start with \"*.\"")
	}
	if strings.Count(pattern, "*") != 1 {
		return "", errors.New("wildcard domain must contain exactly one wildcard")
	}
	base, err := normalize(strings.TrimPrefix(pattern, "*."))
	if err != nil {
		return "", fmt.Errorf("wildcard base: %w", err)
	}
	return Wildcard(base), nil
}

func normalize(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("domain is empty")
	}
	if raw != strings.TrimSpace(raw) {
		return "", errors.New("domain must not have surrounding whitespace")
	}
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" {
		return "", errors.New("domain is empty")
	}
	if strings.Contains(raw, "*") {
		return "", errors.New("wildcards are not valid in an exact domain")
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return "", errors.New("domain must not be an IP literal")
	}

	ascii, err := idna.Lookup.ToASCII(strings.ToLower(raw))
	if err != nil {
		return "", fmt.Errorf("normalize domain %q: %w", raw, err)
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" {
		return "", errors.New("domain is empty")
	}
	if len(ascii) > maxDomainLength {
		return "", fmt.Errorf("domain is longer than %d characters", maxDomainLength)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", errors.New("domain has an empty label")
		}
		if len(label) > maxDomainLabel {
			return "", fmt.Errorf("domain label is longer than %d characters", maxDomainLabel)
		}
	}
	return ascii, nil
}
