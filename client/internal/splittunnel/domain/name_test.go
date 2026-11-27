package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

func TestNormalizeExactName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Name
		wantErr bool
	}{
		{name: "lower case and trailing dot", input: "Example.COM.", want: "example.com"},
		{name: "punycode unchanged", input: "xn--mnchen-3ya.example", want: "xn--mnchen-3ya.example"},
		{name: "unicode to punycode", input: "münchen.example", want: "xn--mnchen-3ya.example"},
		{name: "uppercase unicode", input: "MÜNCHEN.example", want: "xn--mnchen-3ya.example"},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace", input: " example.com", wantErr: true},
		{name: "ipv4 literal", input: "192.0.2.1", wantErr: true},
		{name: "ipv6 literal", input: "2001:db8::1", wantErr: true},
		{name: "empty label", input: "example..com", wantErr: true},
		{name: "wildcard in exact", input: "*.example.com", wantErr: true},
		{name: "underscore label", input: "_dmarc.example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeWildcard(t *testing.T) {
	base, err := NormalizeWildcard("*.Example.COM.")
	require.NoError(t, err)
	assert.Equal(t, Wildcard("example.com"), base)

	base, err = NormalizeWildcard("*.münchen.example")
	require.NoError(t, err)
	assert.Equal(t, Wildcard("xn--mnchen-3ya.example"), base)

	for _, pattern := range []string{"", "example.com", "*.*.example.com", "*example.com"} {
		_, err := NormalizeWildcard(pattern)
		require.Error(t, err, "pattern %q must be rejected", pattern)
	}
}

func TestWildcardDoesNotMatchApex(t *testing.T) {
	rules := NewRules()
	rules.add(Rule{
		Pattern: Pattern{Name: "example.com", Wildcard: true},
		Action:  config.ActionVPN,
		RuleID:  "wild",
	}, 0)

	if _, ok := rules.Match("example.com"); ok {
		t.Fatal("a wildcard rule must not match the apex")
	}
	for _, name := range []Name{"a.example.com", "deep.a.example.com"} {
		_, ok := rules.Match(name)
		assert.True(t, ok, "wildcard must match %s", name)
	}
}

func TestExactAndWildcardPrecedence(t *testing.T) {
	rules := NewRules()
	rules.add(Rule{
		Pattern: Pattern{Name: "example.com", Wildcard: true},
		Action:  config.ActionDirect,
		RuleID:  "wild",
	}, 0)
	rules.add(Rule{
		Pattern: Pattern{Name: "api.example.com"},
		Action:  config.ActionVPN,
		RuleID:  "exact",
	}, 1)

	rule, ok := rules.Match("api.example.com")
	require.True(t, ok)
	assert.Equal(t, config.ActionDirect, rule.Action,
		"the earliest matching rule in evaluation order wins")

	rule, ok = rules.Match("other.example.com")
	require.True(t, ok)
	assert.Equal(t, config.ActionDirect, rule.Action)
}
