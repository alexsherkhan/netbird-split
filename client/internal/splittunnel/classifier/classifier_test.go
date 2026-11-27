package classifier

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func testManager(t *testing.T, registry *application.Registry) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	manager, err := newManager(registry, Options{
		Root: root,
		Base: "netbird",
	}, false)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, manager.Close())
	})
	return manager, filepath.Join(root, "netbird")
}

func testProcess(pid int32, start uint64, uid uint32, executable, cgroup string) application.Process {
	return application.Process{
		PID:        pid,
		StartTime:  start,
		UID:        uid,
		Executable: executable,
		Cgroup:     cgroup,
	}
}

func executableRequirement(path string) Requirement {
	return Requirement{Executable: config.Executable(path)}
}

func TestEnsureScopeAllocatesAndReuses(t *testing.T) {
	manager, base := testManager(t, nil)
	ctx := context.Background()
	identity := Identity{DesktopID: "firefox.desktop", Executable: "/usr/bin/firefox"}

	first, err := manager.EnsureScope(ctx, identity, 1000)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(base), "base must be absolute")
	assert.NotEmpty(t, first.Path)
	assert.Equal(t, uint64(0), first.Generation)
	assert.DirExists(t, filepath.Join(base, filepath.Base(first.Path)))

	second, err := manager.EnsureScope(ctx, identity, 1000)
	require.NoError(t, err)
	assert.Equal(t, first.Path, second.Path, "the same identity and user must reuse a scope")

	otherUser, err := manager.EnsureScope(ctx, identity, 1001)
	require.NoError(t, err)
	assert.NotEqual(t, first.Path, otherUser.Path, "concurrent users need separate scopes")

	otherApp, err := manager.EnsureScope(ctx, Identity{DesktopID: "chrome.desktop"}, 1000)
	require.NoError(t, err)
	assert.NotEqual(t, first.Path, otherApp.Path, "different applications need separate scopes")
}

func TestReconcileClassifiesAndRemovesStaleScopes(t *testing.T) {
	manager, base := testManager(t, nil)
	ctx := context.Background()
	requirement := executableRequirement("/usr/bin/firefox")

	scopes, err := manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/firefox", "/user.slice/session.scope"),
	}, []Requirement{requirement})
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, uint64(1), scopes[0].Generation)
	assert.Equal(t, []int32{100}, scopes[0].PIDs)
	scopeDir := filepath.Join(base, filepath.Base(scopes[0].Path))
	assert.FileExists(t, filepath.Join(scopeDir, "cgroup.procs"))

	scopes, err = manager.ReconcileProcesses(ctx, nil, []Requirement{requirement})
	require.NoError(t, err)
	assert.Empty(t, scopes)
	assert.NoDirExists(t, scopeDir)
}

func TestReconcileChildInheritanceAndRestart(t *testing.T) {
	manager, _ := testManager(t, nil)
	ctx := context.Background()
	requirement := executableRequirement("/usr/bin/browser")

	scopes, err := manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/browser", ""),
	}, []Requirement{requirement})
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	scopePath := scopes[0].Path
	assert.Equal(t, uint64(1), scopes[0].Generation)

	// A child process with a different executable inherits the parent's cgroup
	// and must keep the scope live and classified.
	scopes, err = manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/browser", "/"+scopePath),
		testProcess(101, 11, 1000, "/usr/bin/renderer", "/"+scopePath),
	}, []Requirement{requirement})
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, []int32{100, 101}, scopes[0].PIDs)
	assert.Equal(t, uint64(1), scopes[0].Generation, "adding a child must not count as a restart")

	// A new process generation with no overlap is a restart.
	scopes, err = manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(102, 99, 1000, "/usr/bin/browser", ""),
	}, []Requirement{requirement})
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, scopePath, scopes[0].Path, "a restart reuses the deterministic scope path")
	assert.Equal(t, uint64(2), scopes[0].Generation)
	assert.Equal(t, []int32{102}, scopes[0].PIDs)
}

func TestReconcileSeparatesConcurrentUsers(t *testing.T) {
	manager, _ := testManager(t, nil)
	ctx := context.Background()
	requirement := executableRequirement("/usr/bin/firefox")

	scopes, err := manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/firefox", ""),
		testProcess(200, 20, 1001, "/usr/bin/firefox", ""),
	}, []Requirement{requirement})
	require.NoError(t, err)
	require.Len(t, scopes, 2)

	paths := map[string]bool{}
	for _, scope := range scopes {
		paths[scope.Path] = true
	}
	assert.Len(t, paths, 2, "the same application under two users needs two cgroup scopes")
}

func TestReconcileUnknownApplicationIsNotClassified(t *testing.T) {
	manager, _ := testManager(t, nil)
	ctx := context.Background()
	requirement := executableRequirement("/usr/bin/firefox")

	scopes, err := manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/unknown", "/user.slice/session.scope"),
	}, []Requirement{requirement})
	require.NoError(t, err)
	assert.Empty(t, scopes, "unknown traffic must be left to the configured policy default")
}

func TestRequirementsExtractsApplicationConditions(t *testing.T) {
	compiled := mustCompilePolicy(t, &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionBlock,
			Rules: []config.Rule{{
				ID:        "apps",
				Name:      "apps",
				Enabled:   true,
				Priority:  10,
				MatchMode: config.MatchAny,
				Action:    config.ActionVPN,
				Conditions: []config.Condition{
					{Type: config.ConditionDesktopID, DesktopID: "firefox.desktop"},
					{Type: config.ConditionExecutable, Executable: "/usr/bin/chrome"},
					{Type: config.ConditionFlatpakID, FlatpakID: "org.mozilla.firefox"},
					{Type: config.ConditionSnapID, SnapID: "firefox"},
					{Type: config.ConditionDomain, Domain: "example.com"},
				},
			}},
		},
	})

	requirements := Requirements(compiled)
	require.Len(t, requirements, 4)
	assert.True(t, requirements[0].Matches(Identity{DesktopID: "firefox.desktop"}))
	assert.True(t, requirements[1].Matches(Identity{Executable: "/usr/bin/chrome"}))
	assert.True(t, requirements[2].Matches(Identity{FlatpakID: "org.mozilla.firefox"}))
	assert.True(t, requirements[3].Matches(Identity{SnapID: "firefox"}))

	for _, requirement := range requirements {
		assert.False(t, requirement.Matches(Identity{DesktopID: "unknown.desktop"}),
			"domain conditions must not create a cgroup requirement")
	}
}

func TestRequirementsEmptyForDomainOnlyPolicy(t *testing.T) {
	compiled := mustCompilePolicy(t, &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeInclude,
			DefaultAction: config.ActionDirect,
			Rules: []config.Rule{{
				ID:         "domain",
				Name:       "domain",
				Enabled:    true,
				Priority:   10,
				MatchMode:  config.MatchAll,
				Action:     config.ActionVPN,
				Conditions: []config.Condition{{Type: config.ConditionDomain, Domain: "example.com"}},
			}},
		},
	})
	assert.Empty(t, Requirements(compiled))
}

func TestCloseRemovesOnlyOwnedScopes(t *testing.T) {
	manager, base := testManager(t, nil)
	ctx := context.Background()

	scopes, err := manager.ReconcileProcesses(ctx, []application.Process{
		testProcess(100, 10, 1000, "/usr/bin/firefox", ""),
	}, []Requirement{executableRequirement("/usr/bin/firefox")})
	require.NoError(t, err)
	require.Len(t, scopes, 1)

	foreign := filepath.Join(base, "foreign")
	require.NoError(t, os.Mkdir(foreign, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(foreign, "keep"), []byte("x"), 0o644))

	require.NoError(t, manager.Close())
	assert.NoDirExists(t, filepath.Join(base, filepath.Base(scopes[0].Path)))
	assert.DirExists(t, foreign, "cleanup must leave foreign directories alone")
	require.NoError(t, manager.Close(), "Close must be idempotent")
}

func TestIdentityFromCgroup(t *testing.T) {
	flatpak := IdentityFromCgroup(
		"/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-1234.scope")
	assert.Equal(t, config.FlatpakID("org.mozilla.firefox"), flatpak.FlatpakID)
	assert.Equal(t, config.DesktopID("org.mozilla.firefox.desktop"), flatpak.DesktopID)

	snap := IdentityFromCgroup(
		"/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-abc.scope")
	assert.Equal(t, config.SnapID("firefox"), snap.SnapID)
	assert.Equal(t, config.DesktopID("firefox_firefox.desktop"), snap.DesktopID)
}

func mustCompilePolicy(t *testing.T, cfg *config.Config) *policy.CompiledPolicy {
	t.Helper()
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)
	return compiled
}
