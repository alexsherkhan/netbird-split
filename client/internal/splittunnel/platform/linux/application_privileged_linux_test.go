//go:build linux && !android && privileged

package linux

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/classifier"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

func TestApplicationClassificationEgressInNetworkNamespace(t *testing.T) {
	requirePrivilegedNetwork(t)

	names := createTestInterfaces(t)
	manager, base := startApplicationClassifier(t)
	scopeA, err := manager.EnsureScope(context.Background(),
		classifier.Identity{DesktopID: "app-a.desktop"}, 0)
	require.NoError(t, err)
	scopeB, err := manager.EnsureScope(context.Background(),
		classifier.Identity{Executable: "/usr/bin/app-b"}, 0)
	require.NoError(t, err)

	compiled, options := applicationPolicy(t, names, scopeA, scopeB)
	b := startM07Backend(t)
	require.NoError(t, b.ApplyPolicy(context.Background(), compiled, options))
	t.Cleanup(func() {
		assert.NoError(t, manager.Close())
		assert.NoError(t, os.Remove(base))
	})

	t.Run("classified application follows the exit path", func(t *testing.T) {
		before := counters(t, names)
		runHelper(t, manager, scopeA.Identity, "10.9.1.1", 9999)
		after := counters(t, names)

		assert.Equal(t, before.exit+1, after.exit)
		assert.Equal(t, before.direct, after.direct)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("second classified application follows direct", func(t *testing.T) {
		before := counters(t, names)
		runHelper(t, manager, scopeB.Identity, "10.9.5.1", 9999)
		after := counters(t, names)

		assert.Equal(t, before.direct+1, after.direct)
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("unknown application follows the configured block default", func(t *testing.T) {
		before := counters(t, names)
		requireUnreachable(t, sendUDP("10.9.1.1", 9999))
		after := counters(t, names)

		assert.Equal(t, before.direct, after.direct,
			"unknown traffic must not fall through to the physical path")
		assert.Equal(t, before.exit, after.exit)
		assert.Equal(t, before.vpn, after.vpn)
	})

	t.Run("restart still classifies", func(t *testing.T) {
		before := counters(t, names)
		runHelper(t, manager, scopeA.Identity, "10.9.1.1", 9999)
		after := counters(t, names)

		assert.Equal(t, before.exit+1, after.exit)
	})

	t.Run("child process inherits the classification", func(t *testing.T) {
		before := counters(t, names)
		runHelperMode(t, manager, scopeA.Identity, "spawn-child", "10.9.1.1", 9999)
		after := counters(t, names)

		assert.Equal(t, before.exit+1, after.exit,
			"a child that inherited the application cgroup must stay classified")
	})

	t.Run("rollback removes only the split policy and owned scopes", func(t *testing.T) {
		require.NoError(t, b.Rollback(context.Background()))
		require.NoError(t, manager.Close())

		assert.NotNil(t, findInetTable(t, fmt.Sprintf("netbird_split_m07_%d", os.Getpid())),
			"rollback must keep the baseline table")
		assert.NoDirExists(t, filepath.Join(base, filepath.Base(scopeA.Path)))
		assert.NoDirExists(t, filepath.Join(base, filepath.Base(scopeB.Path)))
	})
}

func startApplicationClassifier(t *testing.T) (*classifier.Manager, string) {
	t.Helper()

	base := fmt.Sprintf("nbtest-m07-%d", os.Getpid())
	manager, err := classifier.New(nil, classifier.Options{
		Root: classifier.DefaultRoot,
		Base: base,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = manager.Close()
		_ = os.Remove(filepath.Join(classifier.DefaultRoot, base))
	})
	return manager, filepath.Join(classifier.DefaultRoot, base)
}

func startM07Backend(t *testing.T) *Backend {
	t.Helper()

	table := fmt.Sprintf("netbird_split_m07_%d", os.Getpid())
	b := newBackend(
		systemProber{},
		func(table string) (nftManager, error) {
			return newNFTablesManager(table)
		},
		table,
	)
	require.NoError(t, b.Initialize(context.Background()))
	t.Cleanup(func() {
		assert.NoError(t, b.Close(context.Background()))
	})
	return b
}

func applicationPolicy(
	t *testing.T,
	names testInterfaces,
	scopeA, scopeB classifier.Scope,
) (*policy.CompiledPolicy, backend.PolicyOptions) {
	t.Helper()

	cfg := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionBlock,
			Rules: []config.Rule{
				{
					ID:         "app-a",
					Name:       "app-a",
					Enabled:    true,
					Priority:   10,
					MatchMode:  config.MatchAll,
					Action:     config.ActionExitNode,
					ExitNodeID: "exit-1",
					Conditions: []config.Condition{{
						Type:      config.ConditionDesktopID,
						DesktopID: "app-a.desktop",
					}},
				},
				{
					ID:        "app-b",
					Name:      "app-b",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAll,
					Action:    config.ActionDirect,
					Conditions: []config.Condition{{
						Type:       config.ConditionExecutable,
						Executable: "/usr/bin/app-b",
					}},
				},
			},
		},
	}
	compiled, err := policy.Compile(cfg)
	require.NoError(t, err)

	options := backend.PolicyOptions{
		Direct: backend.RouteTarget{
			Interface: names.direct,
		},
		ExitNode: &backend.ExitNode{
			ID: "exit-1",
			Target: backend.RouteTarget{
				Interface: names.exit,
			},
		},
		Applications: []backend.ApplicationScope{
			scopeA.BackendScope(),
			scopeB.BackendScope(),
		},
	}
	return compiled, options
}

func runHelper(
	t *testing.T,
	manager *classifier.Manager,
	identity classifier.Identity,
	destination string,
	port int,
) {
	t.Helper()
	runHelperMode(t, manager, identity, "send", destination, port)
}

func runHelperMode(
	t *testing.T,
	manager *classifier.Manager,
	identity classifier.Identity,
	mode, destination string,
	port int,
) {
	t.Helper()

	executable, err := os.Executable()
	require.NoError(t, err)
	cmd, err := manager.Launch(context.Background(), classifier.LaunchSpec{
		Identity: identity,
		UID:      0,
		Path:     executable,
		Args:     []string{"-test.run=^TestSplitTunnelClassifierHelperProcess$"},
		Env: helperEnvironment(
			"NB_SPLIT_HELPER="+mode,
			fmt.Sprintf("NB_SPLIT_HELPER_DEST=%s:%d", destination, port),
		),
	})
	if err != nil {
		t.Skipf("managed launcher is unavailable in this environment: %v", err)
	}
	require.NoError(t, cmd.Wait())
}

func helperEnvironment(values ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "NB_SPLIT_HELPER") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, values...)
}

// TestSplitTunnelClassifierHelperProcess is the managed helper body. It only
// runs when the launcher sets NB_SPLIT_HELPER; the normal suite skips it.
func TestSplitTunnelClassifierHelperProcess(t *testing.T) {
	mode := os.Getenv("NB_SPLIT_HELPER")
	if mode == "" {
		t.Skip("not a classifier helper process")
	}

	destination := os.Getenv("NB_SPLIT_HELPER_DEST")
	host, portValue, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portValue)
	require.NoError(t, err)

	switch mode {
	case "spawn-child":
		executable, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.Command(executable, "-test.run=^TestSplitTunnelClassifierHelperProcess$")
		cmd.Env = helperEnvironment("NB_SPLIT_HELPER=send", "NB_SPLIT_HELPER_DEST="+destination)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "child output: %s", output)
	case "send":
		require.NoError(t, sendUDP(host, port))
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
