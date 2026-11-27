package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

func runSplit(t *testing.T, dial DialFunc, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(Options{Dial: dial})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return output.String(), err
}

func testConfig(mode config.Mode, enabled bool) *proto.SplitTunnelConfig {
	return &proto.SplitTunnelConfig{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: &proto.SplitTunnelSettings{
			Enabled:       enabled,
			Mode:          string(mode),
			DefaultAction: string(defaultActionFor(mode)),
		},
	}
}

func defaultActionFor(mode config.Mode) config.Action {
	switch mode {
	case config.ModeInclude:
		return config.ActionDirect
	case config.ModeExclude:
		return config.ActionVPN
	}
	return ""
}

func TestExitCodeMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", err: nil, want: ExitSuccess},
		{name: "usage", err: Usagef("bad arguments"), want: ExitUsage},
		{name: "denied", err: Deniedf("not allowed"), want: ExitDenied},
		{name: "unavailable", err: Unavailablef("daemon down"), want: ExitUnavailable},
		{name: "conflict", err: Conflictf("stale revision"), want: ExitRevisionConflict},
		{name: "internal", err: Internalf("boom"), want: ExitInternal},
		{name: "untyped", err: errors.New("boom"), want: ExitInternal},
		{name: "unauthenticated", err: Classify(status.Error(codes.Unauthenticated, "identity unknown")), want: ExitDenied},
		{name: "permission denied", err: Classify(status.Error(codes.PermissionDenied, "not allowed")), want: ExitDenied},
		{name: "grpc unavailable", err: Classify(status.Error(codes.Unavailable, "down")), want: ExitUnavailable},
		{name: "unimplemented", err: Classify(status.Error(codes.Unimplemented, "not implemented")), want: ExitUnavailable},
		{name: "invalid argument", err: Classify(status.Error(codes.InvalidArgument, "bad")), want: ExitUsage},
		{name: "failed precondition", err: Classify(status.Error(codes.FailedPrecondition, "bad")), want: ExitUsage},
		{name: "aborted conflict", err: Classify(revisionConflictStatus()), want: ExitRevisionConflict},
		{name: "aborted other", err: Classify(status.Error(codes.Aborted, "other")), want: ExitInternal},
		{name: "grpc internal", err: Classify(status.Error(codes.Internal, "boom")), want: ExitInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExitCode(tt.err))
		})
	}
}

func TestClassifyCommandUsesUsageForCobraErrors(t *testing.T) {
	err := ClassifyCommand(errors.New(`unknown flag: --bogus`))
	assert.Equal(t, ExitUsage, ExitCode(err))
}

func TestStatusJSONShape(t *testing.T) {
	server := &fakeSplitServer{status: &proto.GetSplitTunnelStatusResponse{
		ApiVersion: api.APIVersion,
		Revision:   7,
		Enabled:    true,
		Running:    true,
		Mode:       "include",
		Backend:    "nftables",
	}}
	output, err := runSplit(t, startFake(t, server), "", "status", "--json")
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &document))
	for _, key := range []string{"apiVersion", "revision", "enabled", "running", "mode", "backend", "processes", "diagnostics", "redactedFields"} {
		require.Contains(t, document, key)
	}
	assert.Equal(t, []any{}, document["processes"])
	assert.Equal(t, map[string]any{}, document["diagnostics"])
	assert.Equal(t, []any{}, document["redactedFields"])
}

func TestCapabilitiesJSONShape(t *testing.T) {
	server := &fakeSplitServer{status: &proto.GetSplitTunnelStatusResponse{ApiVersion: api.APIVersion}}
	output, err := runSplit(t, startFake(t, server), "", "capabilities", "--json")
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &document))
	for _, key := range []string{"clientApiVersion", "serverApiVersion", "modes", "actions", "conditionTypes", "features"} {
		require.Contains(t, document, key)
	}
	assert.Equal(t, float64(api.APIVersion), document["clientApiVersion"])
}

func TestListJSONShapes(t *testing.T) {
	server := &fakeSplitServer{
		apps: []*proto.SplitTunnelApplication{{
			DesktopId:  "firefox.desktop",
			Name:       "Firefox",
			Executable: "/usr/bin/firefox",
		}},
		rules: &proto.ListSplitTunnelRulesResponse{
			ApiVersion: api.APIVersion,
			Revision:   3,
			Rules: []*proto.SplitTunnelRule{{
				Id:         "rule-1",
				Name:       "Example",
				Enabled:    true,
				Action:     "vpn",
				Priority:   10,
				Conditions: []*proto.SplitTunnelCondition{{Type: "domain", Value: "example.com"}},
			}, {
				Id:         "rule-2",
				Name:       "Wildcard",
				Enabled:    true,
				Action:     "direct",
				Priority:   20,
				Conditions: []*proto.SplitTunnelCondition{{Type: "wildcard_domain", Value: "*.example.org"}},
			}},
		},
	}
	dial := startFake(t, server)

	appOutput, err := runSplit(t, dial, "", "app", "list", "--json")
	require.NoError(t, err)
	var apps map[string]any
	require.NoError(t, json.Unmarshal([]byte(appOutput), &apps))
	require.Contains(t, apps, "applications")
	require.Contains(t, apps, "redactedFields")

	domainOutput, err := runSplit(t, dial, "", "domain", "list", "--json")
	require.NoError(t, err)
	var domains map[string]any
	require.NoError(t, json.Unmarshal([]byte(domainOutput), &domains))
	require.Contains(t, domains, "domains")
	require.Contains(t, domains, "revision")
	require.Len(t, domains["domains"], 2)
	patterns := []string{}
	for _, item := range domains["domains"].([]any) {
		patterns = append(patterns, item.(map[string]any)["pattern"].(string))
	}
	assert.ElementsMatch(t, []string{"example.com", "*.example.org"}, patterns)
}

func TestDomainAddAndRemove(t *testing.T) {
	server := &fakeSplitServer{
		config:    testConfig(config.ModeInclude, true),
		revision:  2,
		hasConfig: true,
	}
	dial := startFake(t, server)

	output, err := runSplit(t, dial, "", "domain", "add", "Example.COM", "--via", "vpn")
	require.NoError(t, err, output)
	assert.Contains(t, output, "Added rule")

	server.mu.Lock()
	require.Len(t, server.config.GetSplitTunnel().GetRules(), 1)
	rule := server.config.GetSplitTunnel().GetRules()[0]
	server.mu.Unlock()
	assert.Equal(t, "domain", rule.GetConditions()[0].GetType())
	assert.Equal(t, "example.com", rule.GetConditions()[0].GetValue())
	assert.Equal(t, "vpn", rule.GetAction())

	output, err = runSplit(t, dial, "", "domain", "remove", "example.com")
	require.NoError(t, err, output)
	assert.Contains(t, output, "Removed rule")

	server.mu.Lock()
	assert.Empty(t, server.config.GetSplitTunnel().GetRules())
	server.mu.Unlock()
}

func TestDuplicateDomainAddIsUsageError(t *testing.T) {
	server := &fakeSplitServer{
		config:    testConfig(config.ModeInclude, true),
		revision:  1,
		hasConfig: true,
	}
	dial := startFake(t, server)

	_, err := runSplit(t, dial, "", "domain", "add", "example.com", "--via", "vpn")
	require.NoError(t, err)

	_, err = runSplit(t, dial, "", "domain", "add", "example.com", "--via", "direct")
	require.Error(t, err)
	assert.Equal(t, ExitUsage, ExitCode(err))
}

func TestArgumentValidation(t *testing.T) {
	dial := startFake(t, &fakeSplitServer{})

	tests := []struct {
		name string
		args []string
	}{
		{name: "invalid mode", args: []string{"mode", "bogus"}},
		{name: "invalid domain", args: []string{"domain", "add", "bad_domain", "--via", "vpn"}},
		{name: "invalid ip", args: []string{"ip", "add", "999.1.1.1", "--via", "vpn"}},
		{name: "cidr host bits", args: []string{"cidr", "add", "10.0.0.1/24", "--via", "direct"}},
		{name: "missing via", args: []string{"app", "add", "firefox"}},
		{name: "invalid via", args: []string{"domain", "add", "example.com", "--via", "sideways"}},
		{name: "trace destination", args: []string{"trace"}},
		{name: "trace app unsupported", args: []string{"trace", "--app", "firefox"}},
		{name: "rollback revision", args: []string{"rollback", "zero"}},
		{name: "extra args", args: []string{"enable", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runSplit(t, dial, "", tt.args...)
			require.Error(t, err)
			assert.Equal(t, ExitUsage, ExitCode(err), "error: %v", err)
		})
	}
}

func TestRevisionConflict(t *testing.T) {
	server := &fakeSplitServer{
		config:    testConfig(config.ModeInclude, true),
		revision:  1,
		hasConfig: true,
		setErr:    revisionConflictStatus(),
	}
	_, err := runSplit(t, startFake(t, server), "", "mode", "include")
	require.Error(t, err)
	assert.Equal(t, ExitRevisionConflict, ExitCode(err))
}

func TestDisableConfirmation(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  1,
			hasConfig: true,
		}
		_, err := runSplit(t, startFake(t, server), "n\n", "disable")
		require.Error(t, err)
		assert.Equal(t, ExitInternal, ExitCode(err))
		assert.Equal(t, 0, server.setCalls)
	})

	t.Run("accepted with yes", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  1,
			hasConfig: true,
		}
		output, err := runSplit(t, startFake(t, server), "", "disable", "--yes")
		require.NoError(t, err, output)
		assert.Equal(t, 1, server.setCalls)
		server.mu.Lock()
		assert.False(t, server.config.GetSplitTunnel().GetEnabled())
		server.mu.Unlock()
	})
}

func TestResetConfirmation(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  1,
			hasConfig: true,
		}
		_, err := runSplit(t, startFake(t, server), "no\n", "reset")
		require.Error(t, err)
		assert.Equal(t, ExitInternal, ExitCode(err))
		assert.Equal(t, 0, server.setCalls)
	})

	t.Run("accepted", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  1,
			hasConfig: true,
		}
		output, err := runSplit(t, startFake(t, server), "yes\n", "reset")
		require.NoError(t, err, output)
		server.mu.Lock()
		defer server.mu.Unlock()
		assert.Equal(t, 1, server.setCalls)
		assert.False(t, server.config.GetSplitTunnel().GetEnabled())
		assert.Equal(t, string(config.ModeStandard), server.config.GetSplitTunnel().GetMode())
		assert.Empty(t, server.config.GetSplitTunnel().GetRules())
	})
}

func TestRollbackConfirmation(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  3,
			hasConfig: true,
		}
		_, err := runSplit(t, startFake(t, server), "n\n", "rollback", "2")
		require.Error(t, err)
		assert.Equal(t, ExitInternal, ExitCode(err))
		assert.Equal(t, 0, server.rollbackCalls)
	})

	t.Run("accepted", func(t *testing.T) {
		server := &fakeSplitServer{
			config:    testConfig(config.ModeInclude, true),
			revision:  3,
			hasConfig: true,
		}
		output, err := runSplit(t, startFake(t, server), "", "rollback", "2", "--yes")
		require.NoError(t, err, output)
		assert.Equal(t, 1, server.rollbackCalls)
		assert.EqualValues(t, 3, server.lastExpected)
	})
}

func TestProfileImportExportRoundTrip(t *testing.T) {
	original := testConfig(config.ModeInclude, true)
	original.SplitTunnel.Rules = []*proto.SplitTunnelRule{{
		Id:         "rule-1",
		Name:       "Example",
		Enabled:    true,
		Priority:   10,
		MatchMode:  "all",
		Action:     "vpn",
		Conditions: []*proto.SplitTunnelCondition{{Type: "domain", Value: "example.com"}},
	}}
	exportServer := &fakeSplitServer{config: original, revision: 4, hasConfig: true}
	exported, err := runSplit(t, startFake(t, exportServer), "", "export")
	require.NoError(t, err)

	parsed, err := config.Parse([]byte(exported))
	require.NoError(t, err)
	require.Equal(t, "example.com", string(parsed.SplitTunnel.Rules[0].Conditions[0].Domain))

	importServer := &fakeSplitServer{}
	output, err := runSplit(t, startFake(t, importServer), exported, "import", "-")
	require.NoError(t, err, output)
	assert.Contains(t, output, "Configuration imported")

	importServer.mu.Lock()
	defer importServer.mu.Unlock()
	require.NotNil(t, importServer.config)
	imported, err := configFromProto(importServer.config)
	require.NoError(t, err)
	assert.Equal(t, parsed, imported)
}

func TestValidateFile(t *testing.T) {
	dial := startFake(t, &fakeSplitServer{})

	output, err := runSplit(t, dial, `{"schemaVersion":1,"splitTunnel":{"mode":"standard"}}`, "validate", "-")
	require.NoError(t, err, output)
	assert.Contains(t, output, "valid")

	output, err = runSplit(t, dial, `{"schemaVersion":1}`, "validate", "-")
	require.Error(t, err)
	assert.Equal(t, ExitUsage, ExitCode(err))
	assert.Contains(t, output, "Invalid")
}

func TestProfileCreateIsUnavailable(t *testing.T) {
	_, err := runSplit(t, startFake(t, &fakeSplitServer{}), "", "profile", "create", "work")
	require.Error(t, err)
	assert.Equal(t, ExitUnavailable, ExitCode(err))
}

func TestUnimplementedServiceMapsToUnavailable(t *testing.T) {
	server := &fakeSplitServer{statusEr: status.Error(codes.Unimplemented, "split tunnel status is not implemented")}
	_, err := runSplit(t, startFake(t, server), "", "status")
	require.Error(t, err)
	assert.Equal(t, ExitUnavailable, ExitCode(err))
}

func TestDoctorHealthy(t *testing.T) {
	server := &fakeSplitServer{
		status: &proto.GetSplitTunnelStatusResponse{
			ApiVersion: api.APIVersion,
			Revision:   1,
			Enabled:    true,
			Mode:       "include",
		},
		config:    testConfig(config.ModeInclude, true),
		revision:  1,
		hasConfig: true,
	}
	output, err := runSplit(t, startFake(t, server), "", "doctor", "--json")
	require.NoError(t, err, output)

	var document doctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &document))
	assert.True(t, document.Healthy)
	assert.Len(t, document.Checks, 4)
}

func TestStatsJSONShape(t *testing.T) {
	server := &fakeSplitServer{
		status: &proto.GetSplitTunnelStatusResponse{
			ApiVersion: api.APIVersion,
			Revision:   2,
			Enabled:    true,
			Running:    true,
			Mode:       "include",
			Processes:  []*proto.SplitTunnelProcess{{Pid: 1}},
		},
		rules: &proto.ListSplitTunnelRulesResponse{ApiVersion: api.APIVersion, Revision: 2},
	}
	output, err := runSplit(t, startFake(t, server), "", "stats", "--json")
	require.NoError(t, err)

	var document statsOutput
	require.NoError(t, json.Unmarshal([]byte(output), &document))
	assert.True(t, document.Available)
	assert.EqualValues(t, 1, document.Processes)
	assert.False(t, document.CountersAvailable)
}

func TestEnableRequiresConfiguration(t *testing.T) {
	server := &fakeSplitServer{}
	_, err := runSplit(t, startFake(t, server), "", "enable")
	require.Error(t, err)
	assert.Equal(t, ExitUsage, ExitCode(err))
	assert.Equal(t, 0, server.setCalls)
}

func TestEnableAlreadyEnabledDoesNotMutate(t *testing.T) {
	server := &fakeSplitServer{
		config:    testConfig(config.ModeInclude, true),
		revision:  4,
		hasConfig: true,
	}
	output, err := runSplit(t, startFake(t, server), "", "enable")
	require.NoError(t, err, output)
	assert.Contains(t, output, "already enabled")
	assert.Equal(t, 0, server.setCalls)
}

func TestModeReadJSONShape(t *testing.T) {
	server := &fakeSplitServer{
		config:    testConfig(config.ModeExclude, true),
		revision:  9,
		hasConfig: true,
	}
	output, err := runSplit(t, startFake(t, server), "", "mode", "--json")
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &document))
	for _, key := range []string{"mode", "defaultAction", "enabled", "revision"} {
		require.Contains(t, document, key)
	}
	assert.Equal(t, "exclude", document["mode"])
	assert.Equal(t, "vpn", document["defaultAction"])
}
