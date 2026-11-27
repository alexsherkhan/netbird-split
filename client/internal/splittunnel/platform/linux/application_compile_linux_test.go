//go:build linux && !android

package linux

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
)

type fakeCgroupResolver map[string]uint64

func (f fakeCgroupResolver) ID(path string) (uint64, error) {
	id, ok := f[path]
	if !ok {
		return 0, fmt.Errorf("cgroup %q not found", path)
	}
	return id, nil
}

func appCondition(conditionType config.ConditionType, value string) config.Condition {
	condition := config.Condition{Type: conditionType}
	switch conditionType {
	case config.ConditionDesktopID:
		condition.DesktopID = config.DesktopID(value)
	case config.ConditionExecutable:
		condition.Executable = config.Executable(value)
	case config.ConditionFlatpakID:
		condition.FlatpakID = config.FlatpakID(value)
	case config.ConditionSnapID:
		condition.SnapID = config.SnapID(value)
	}
	return condition
}

func TestResolveCgroupMatchUsesPathLevelAndInode(t *testing.T) {
	resolver := fakeCgroupResolver{
		"user.slice/user-1000.slice/app.slice/firefox.scope": 0x1234,
	}

	match, err := resolveCgroupMatch(
		"user.slice/user-1000.slice/app.slice/firefox.scope", resolver)
	require.NoError(t, err)
	assert.Equal(t, uint32(4), match.Level,
		"/a/b/c/d is nft level 4, matching the M01 probe")
	assert.Equal(t, uint64(0x1234), match.ID)
	assert.Equal(t, "user.slice/user-1000.slice/app.slice/firefox.scope", match.Path)

	for _, invalid := range []string{
		"",
		"/absolute/path",
		"a//b",
		"a/./b",
		"a/../b",
		`a\b`,
	} {
		t.Run(fmt.Sprintf("invalid_%q", invalid), func(t *testing.T) {
			_, err := resolveCgroupMatch(invalid, resolver)
			require.Error(t, err)
		})
	}

	_, err = resolveCgroupMatch("missing", resolver)
	require.Error(t, err)
}

func TestNftRuleExprsEncodesSocketCgroupV2(t *testing.T) {
	cgroup := &nftCgroupMatch{Path: "apps/firefox.scope", Level: 2, ID: 0x0102030405060708}
	exprs, err := nftRuleExprs(nftRule{cgroup: cgroup, mark: 0x1BD01}, nil)
	require.NoError(t, err)

	var socket *expr.Socket
	var cgroupID []byte
	for i := range exprs {
		value, ok := exprs[i].(*expr.Socket)
		if !ok {
			continue
		}
		socket = value
		if i+1 < len(exprs) {
			if cmp, ok := exprs[i+1].(*expr.Cmp); ok {
				cgroupID = cmp.Data
			}
		}
	}
	require.NotNil(t, socket, "the encoding must include a socket expression")
	assert.Equal(t, expr.SocketKeyCgroupv2, socket.Key)
	assert.Equal(t, uint32(2), socket.Level)
	assert.Equal(t, binaryutil.NativeEndian.PutUint64(0x0102030405060708), cgroupID,
		"the kernel compares the socket cgroup id in native byte order")
}

func TestCompilePolicyMapsApplicationsToOwnedCgroups(t *testing.T) {
	cfg := includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
		testRule("chrome", config.ActionDirect,
			appCondition(config.ConditionExecutable, "/usr/bin/chrome")),
		testRule("flatpak", config.ActionVPN,
			appCondition(config.ConditionFlatpakID, "org.mozilla.firefox")),
	)
	cfg.SplitTunnel.Mode = config.ModeCustom
	cfg.SplitTunnel.DefaultAction = config.ActionBlock
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)
	resolver := fakeCgroupResolver{
		"apps/firefox.scope": 0x11,
		"apps/chrome.scope":  0x22,
		"apps/flatpak.scope": 0x33,
	}
	options := testOptions()
	options.Applications = []backend.ApplicationScope{
		{
			Identity: backend.ApplicationIdentity{
				DesktopID:  "firefox.desktop",
				Executable: "/usr/bin/firefox",
			},
			UID:        1000,
			CgroupPath: "apps/firefox.scope",
		},
		{
			Identity:   backend.ApplicationIdentity{Executable: "/usr/bin/chrome"},
			UID:        1000,
			CgroupPath: "apps/chrome.scope",
		},
		{
			Identity:   backend.ApplicationIdentity{FlatpakID: "org.mozilla.firefox"},
			UID:        1000,
			CgroupPath: "apps/flatpak.scope",
		},
		{
			Identity:   backend.ApplicationIdentity{DesktopID: "unused.desktop"},
			UID:        1000,
			CgroupPath: "apps/unused.scope",
		},
	}

	plan, err := compilePolicyForWithResolver(
		compiled, options, allocations, false, resolver)
	require.NoError(t, err)

	vpn := allocations.byClass[classVPN].mark.Value
	direct := allocations.byClass[classDirect].mark.Value
	block := allocations.byClass[classBlock].mark.Value

	cgroupIDs := map[uint64]uint32{}
	for _, rule := range plan.nft.rules {
		if rule.cgroup == nil {
			continue
		}
		cgroupIDs[rule.cgroup.ID] = rule.mark
		assert.Equal(t, family4, rule.family)
	}
	assert.Equal(t, map[uint64]uint32{
		0x11: vpn,
		0x22: direct,
		0x33: vpn,
	}, cgroupIDs, "each matching application must map to its own cgroup and rule class")

	var defaultMark uint32
	for _, rule := range plan.nft.rules {
		if rule.cgroup == nil && rule.uid == nil && !rule.bypass &&
			len(rule.matches) == 0 && rule.family == family4 {
			defaultMark = rule.mark
		}
	}
	assert.Equal(t, block, defaultMark, "unknown applications must follow the configured default")
}

func TestCompilePolicyFiltersScopesByUIDAndCIDR(t *testing.T) {
	uid1000 := config.UID(1000)
	cfg := includeConfig(
		testRule("firefox-user", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop"),
			config.Condition{Type: config.ConditionUID, UID: &uid1000},
			cidrCondition("10.9.3.0/24")),
	)
	cfg.SplitTunnel.DefaultAction = config.ActionDirect
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)
	resolver := fakeCgroupResolver{
		"apps/firefox-1000.scope": 0x1000,
		"apps/firefox-2000.scope": 0x2000,
	}
	options := testOptions()
	options.Applications = []backend.ApplicationScope{
		{
			Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
			UID:        1000,
			CgroupPath: "apps/firefox-1000.scope",
		},
		{
			Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
			UID:        2000,
			CgroupPath: "apps/firefox-2000.scope",
		},
	}

	plan, err := compilePolicyForWithResolver(
		compiled, options, allocations, false, resolver)
	require.NoError(t, err)

	var cgroups []*nftCgroupMatch
	for _, rule := range plan.nft.rules {
		if rule.cgroup != nil {
			cgroups = append(cgroups, rule.cgroup)
			require.Len(t, rule.matches, 1)
			assert.Equal(t, netip.MustParsePrefix("10.9.3.0/24"), rule.matches[0].prefix)
		}
	}
	require.Len(t, cgroups, 1)
	assert.Equal(t, uint64(0x1000), cgroups[0].ID,
		"the UID condition must select only the matching user's scope")
}

func TestCompilePolicyUIDOnlyRuleUsesSocketUID(t *testing.T) {
	uid := config.UID(1000)
	cfg := includeConfig(
		testRule("uid", config.ActionVPN,
			config.Condition{Type: config.ConditionUID, UID: &uid},
			cidrCondition("10.9.3.0/24")),
	)
	cfg.SplitTunnel.DefaultAction = config.ActionDirect
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)

	plan, err := compilePolicyForWithResolver(
		compiled, testOptions(), allocations, false, fakeCgroupResolver{})
	require.NoError(t, err)

	var uidRules int
	for _, rule := range plan.nft.rules {
		if rule.uid == nil {
			continue
		}
		uidRules++
		require.NotNil(t, rule.uid)
		assert.Equal(t, uint32(1000), *rule.uid)
		assert.Nil(t, rule.cgroup)
	}
	assert.Equal(t, 1, uidRules)
}

func TestCompilePolicyUnknownApplicationDoesNotCreateCgroupRule(t *testing.T) {
	cfg := includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
	)
	cfg.SplitTunnel.Mode = config.ModeCustom
	cfg.SplitTunnel.DefaultAction = config.ActionBlock
	compiled := mustCompile(t, cfg)
	allocations := testAllocations(t)

	plan, err := compilePolicyForWithResolver(
		compiled, testOptions(), allocations, false, fakeCgroupResolver{})
	require.NoError(t, err)

	for _, rule := range plan.nft.rules {
		assert.Nil(t, rule.cgroup,
			"an application that is not classified must not get a cgroup rule")
	}

	block := allocations.byClass[classBlock].mark.Value
	foundDefault := false
	for _, rule := range plan.nft.rules {
		if rule.cgroup == nil && rule.uid == nil && !rule.bypass &&
			len(rule.matches) == 0 && rule.family == family4 {
			foundDefault = true
			assert.Equal(t, block, rule.mark)
		}
	}
	assert.True(t, foundDefault,
		"unknown traffic must still follow the configured block default")
}

func TestCompilePolicyRejectsInvalidApplicationScope(t *testing.T) {
	cfg := includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
	)
	compiled := mustCompile(t, cfg)
	options := testOptions()
	options.Applications = []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
		CgroupPath: "../escape",
	}}

	_, err := compilePolicyForWithResolver(
		compiled, options, testAllocations(t), false, fakeCgroupResolver{})
	require.Error(t, err)
}

func TestCompilePolicyApplicationRuleCoversBothFamilies(t *testing.T) {
	cfg := includeConfig(
		testRule("firefox", config.ActionVPN,
			appCondition(config.ConditionDesktopID, "firefox.desktop")),
	)
	cfg.SplitTunnel.IPv6 = true
	compiled := mustCompile(t, cfg)
	options := testOptions6()
	options.Applications = []backend.ApplicationScope{{
		Identity:   backend.ApplicationIdentity{DesktopID: "firefox.desktop"},
		UID:        1000,
		CgroupPath: "apps/firefox.scope",
	}}

	plan, err := compilePolicyForWithResolver(
		compiled, options, testAllocations(t), true,
		fakeCgroupResolver{"apps/firefox.scope": 0x77})
	require.NoError(t, err)

	families := map[nftFamily]bool{}
	for _, rule := range plan.nft.rules {
		if rule.cgroup != nil {
			families[rule.family] = true
		}
	}
	assert.True(t, families[family4], "an application rule must cover IPv4")
	assert.True(t, families[family6], "an application rule must cover IPv6 when enabled")
}
