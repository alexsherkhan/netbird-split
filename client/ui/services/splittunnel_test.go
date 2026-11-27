//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/proto"
)

type stubSplitTunnel struct {
	proto.SplitTunnelServiceClient

	statusResp *proto.GetSplitTunnelStatusResponse
	statusErr  error
	configResp *proto.GetSplitTunnelConfigResponse
	configErr  error
	setResp    *proto.SetSplitTunnelConfigResponse
	setErr     error
	appsResp   *proto.ListSplitTunnelApplicationsResponse
	appsErr    error
	rulesResp  *proto.ListSplitTunnelRulesResponse
	rulesErr   error
	eventsResp *proto.ListSplitTunnelEventsResponse
	eventsErr  error
	traceResp  *proto.TraceSplitTunnelPacketResponse
	traceErr   error
	rollResp   *proto.RollbackSplitTunnelConfigResponse
	rollErr    error

	setCalls      int
	lastSet       *proto.SetSplitTunnelConfigRequest
	lastAppsQuery string
	lastEvents    *proto.ListSplitTunnelEventsRequest
	lastTrace     *proto.TraceSplitTunnelPacketRequest
	rollCalls     int
	lastRollback  *proto.RollbackSplitTunnelConfigRequest
}

func (d *stubSplitTunnel) GetStatus(_ context.Context, _ *proto.GetSplitTunnelStatusRequest, _ ...grpc.CallOption) (*proto.GetSplitTunnelStatusResponse, error) {
	return d.statusResp, d.statusErr
}

func (d *stubSplitTunnel) GetConfig(_ context.Context, _ *proto.GetSplitTunnelConfigRequest, _ ...grpc.CallOption) (*proto.GetSplitTunnelConfigResponse, error) {
	return d.configResp, d.configErr
}

func (d *stubSplitTunnel) SetConfig(_ context.Context, req *proto.SetSplitTunnelConfigRequest, _ ...grpc.CallOption) (*proto.SetSplitTunnelConfigResponse, error) {
	d.setCalls++
	d.lastSet = req
	if d.setErr != nil {
		return nil, d.setErr
	}
	return d.setResp, nil
}

func (d *stubSplitTunnel) ListApplications(_ context.Context, req *proto.ListSplitTunnelApplicationsRequest, _ ...grpc.CallOption) (*proto.ListSplitTunnelApplicationsResponse, error) {
	d.lastAppsQuery = req.GetQuery()
	return d.appsResp, d.appsErr
}

func (d *stubSplitTunnel) ListRules(_ context.Context, _ *proto.ListSplitTunnelRulesRequest, _ ...grpc.CallOption) (*proto.ListSplitTunnelRulesResponse, error) {
	return d.rulesResp, d.rulesErr
}

func (d *stubSplitTunnel) ListEvents(_ context.Context, req *proto.ListSplitTunnelEventsRequest, _ ...grpc.CallOption) (*proto.ListSplitTunnelEventsResponse, error) {
	d.lastEvents = req
	return d.eventsResp, d.eventsErr
}

func (d *stubSplitTunnel) TracePacket(_ context.Context, req *proto.TraceSplitTunnelPacketRequest, _ ...grpc.CallOption) (*proto.TraceSplitTunnelPacketResponse, error) {
	d.lastTrace = req
	return d.traceResp, d.traceErr
}

func (d *stubSplitTunnel) RollbackConfig(_ context.Context, req *proto.RollbackSplitTunnelConfigRequest, _ ...grpc.CallOption) (*proto.RollbackSplitTunnelConfigResponse, error) {
	d.rollCalls++
	d.lastRollback = req
	if d.rollErr != nil {
		return nil, d.rollErr
	}
	return d.rollResp, nil
}

type stubSplitTunnelConn struct {
	client proto.SplitTunnelServiceClient
	err    error
}

func (c stubSplitTunnelConn) SplitTunnelClient() (proto.SplitTunnelServiceClient, error) {
	return c.client, c.err
}

func splitTunnelWith(daemon *stubSplitTunnel) *SplitTunnel {
	return NewSplitTunnel(stubSplitTunnelConn{client: daemon}, nil, nil)
}

func reasonError(t *testing.T, code codes.Code, reason, message string, metadata map[string]string) error {
	t.Helper()

	st := gstatus.New(code, message)
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   api.ErrorDomain,
		Metadata: metadata,
	})
	require.NoError(t, err, "attach split tunnel error detail")
	return withDetails.Err()
}

func sampleConfig() *proto.SplitTunnelConfig {
	return &proto.SplitTunnelConfig{
		SchemaVersion: 1,
		SplitTunnel: &proto.SplitTunnelSettings{
			Enabled:       true,
			Mode:          "include",
			DefaultAction: "direct",
			KillSwitch:    "disabled",
			Rules: []*proto.SplitTunnelRule{
				{
					Id:         "work",
					Name:       "Work",
					Enabled:    true,
					Action:     "exit_node",
					ExitNodeId: "peer-a",
					Conditions: []*proto.SplitTunnelCondition{{Type: "domain", Value: "work.example.com"}},
				},
				{
					Id:         "direct",
					Name:       "Direct",
					Enabled:    true,
					Action:     "direct",
					Conditions: []*proto.SplitTunnelCondition{{Type: "domain", Value: "local.example.com"}},
				},
			},
		},
	}
}

func TestSplitTunnelGetStatusMapsRedactedDiagnostics(t *testing.T) {
	daemon := &stubSplitTunnel{
		statusResp: &proto.GetSplitTunnelStatusResponse{
			ApiVersion:     1,
			Revision:       9,
			Enabled:        true,
			Running:        false,
			Mode:           "include",
			Backend:        "nftables",
			RedactedFields: []string{"diagnostics"},
			Processes: []*proto.SplitTunnelProcess{{
				Pid:        0,
				DesktopId:  "firefox.desktop",
				Name:       "Firefox",
				Executable: "",
			}},
		},
	}

	status, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.NoError(t, err)

	assert.Equal(t, uint64(9), status.Revision)
	assert.True(t, status.Enabled)
	assert.False(t, status.Running)
	assert.True(t, status.DiagnosticsRedacted, "redaction must be explicit")
	assert.Nil(t, status.Diagnostics, "an unprivileged caller must not receive diagnostics")
	assert.Len(t, status.Processes, 1)
	assert.Equal(t, "Firefox", status.Processes[0].Name)
	assert.True(t, status.Degraded)
	assert.Contains(t, degradedCodes(status), "not_running")
	assert.NotContains(t, degradedCodes(status), "config_invalid",
		"missing diagnostics must not be guessed as an invalid configuration")
}

func TestSplitTunnelGetStatusReportsDegradedBackend(t *testing.T) {
	daemon := &stubSplitTunnel{
		statusResp: &proto.GetSplitTunnelStatusResponse{
			ApiVersion: 1,
			Revision:   4,
			Enabled:    false,
			Running:    false,
			Mode:       "standard",
			Backend:    "nftables",
			Diagnostics: map[string]string{
				"backend.state": "degraded",
				"config":        "invalid",
				"config.error":  "splitTunnel.mode: unsupported mode",
			},
		},
	}

	status, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.NoError(t, err)

	assert.False(t, status.DiagnosticsRedacted)
	assert.Equal(t, "degraded", status.Diagnostics["backend.state"])
	assert.True(t, status.Degraded)
	codes := degradedCodes(status)
	assert.Contains(t, codes, "backend_degraded")
	assert.Contains(t, codes, "config_invalid")
	assert.NotContains(t, codes, "not_running",
		"a disabled engine is not a running failure")
}

func TestSplitTunnelGetStatusMapsUnimplemented(t *testing.T) {
	daemon := &stubSplitTunnel{statusErr: gstatus.Error(codes.Unimplemented, "split tunnel status is not implemented")}

	_, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok, "service errors must be ClientError values")
	assert.Equal(t, "split_tunnel_unavailable", clientErr.Code)
	assert.Equal(t, "error.split_tunnel_unavailable", clientErr.Short)
}

func TestSplitTunnelGetConfigMapsRulesAndExitNodes(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{
			ApiVersion: 1,
			Revision:   3,
			Config:     sampleConfig(),
		},
	}

	config, err := splitTunnelWith(daemon).GetConfig(context.Background())
	require.NoError(t, err)

	assert.True(t, config.Exists)
	assert.Equal(t, uint64(3), config.Revision)
	assert.Equal(t, "include", config.Mode)
	assert.Equal(t, "direct", config.DefaultAction)
	assert.Equal(t, 2, config.RuleCount)
	require.Len(t, config.Rules, 2)
	assert.Equal(t, 1, config.Rules[0].ConditionCount)
	require.Len(t, config.ExitNodeRules, 1)
	assert.Equal(t, "work", config.ExitNodeRules[0].RuleID)
	assert.Equal(t, "peer-a", config.ExitNodeRules[0].ExitNodeID)
}

func TestSplitTunnelGetConfigHandlesNoConfiguration(t *testing.T) {
	daemon := &stubSplitTunnel{configResp: &proto.GetSplitTunnelConfigResponse{}}

	config, err := splitTunnelWith(daemon).GetConfig(context.Background())
	require.NoError(t, err)

	assert.False(t, config.Exists)
	assert.Equal(t, uint64(0), config.Revision)
	assert.Empty(t, config.Rules)
	assert.Empty(t, config.ExitNodeRules)
}

func TestSplitTunnelGetConfigRejectsRevisionWithoutConfig(t *testing.T) {
	daemon := &stubSplitTunnel{configResp: &proto.GetSplitTunnelConfigResponse{Revision: 5}}

	_, err := splitTunnelWith(daemon).GetConfig(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_response", clientErr.Code)
}

func TestSplitTunnelApplyRefusesStaleRevisionBeforeWriting(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 3,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_revision_conflict", clientErr.Code)
	assert.Equal(t, 0, daemon.setCalls, "a stale revision must not be written")
}

func TestSplitTunnelApplyRequiresModeBeforeEnabling(t *testing.T) {
	cfg := sampleConfig()
	cfg.SplitTunnel.Mode = "standard"
	cfg.SplitTunnel.DefaultAction = ""
	cfg.SplitTunnel.Enabled = false
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: cfg},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "standard",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_mode_required", clientErr.Code)
	assert.Equal(t, 0, daemon.setCalls)
}

func TestSplitTunnelApplySendsOneCompleteRevision(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	result, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "custom",
		DefaultAction:    "block",
		KillSwitch:       "global",
		ExitNodes: []SplitTunnelExitNodeSelection{{
			RuleID:     "work",
			ExitNodeID: "peer-b",
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(5), result.Revision)

	require.Equal(t, 1, daemon.setCalls)
	require.NotNil(t, daemon.lastSet)
	assert.Equal(t, uint64(4), daemon.lastSet.GetExpectedRevision())
	settings := daemon.lastSet.GetConfig().GetSplitTunnel()
	require.NotNil(t, settings)
	assert.True(t, settings.GetEnabled())
	assert.Equal(t, "custom", settings.GetMode())
	assert.Equal(t, "block", settings.GetDefaultAction())
	assert.Equal(t, "global", settings.GetKillSwitch())
	require.Len(t, settings.GetRules(), 2)
	assert.Equal(t, "peer-b", settings.GetRules()[0].GetExitNodeId())
	assert.Equal(t, "direct", settings.GetRules()[1].GetAction(),
		"rules the overview does not edit must survive the write")
	assert.Equal(t, "local.example.com", settings.GetRules()[1].GetConditions()[0].GetValue())
}

func TestSplitTunnelApplyStandardModeDisablesRules(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          false,
		Mode:             "standard",
		KillSwitch:       "disabled",
	})
	require.NoError(t, err)

	require.Equal(t, 1, daemon.setCalls)
	settings := daemon.lastSet.GetConfig().GetSplitTunnel()
	assert.False(t, settings.GetEnabled())
	assert.Empty(t, settings.GetDefaultAction())
	for _, rule := range settings.GetRules() {
		assert.False(t, rule.GetEnabled(), "standard mode requires every rule to be disabled")
	}
}

func TestSplitTunnelApplyCreatesFirstConfiguration(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 0},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 1},
	}

	result, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 0,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "selective",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), result.Revision)

	require.Equal(t, 1, daemon.setCalls)
	cfg := daemon.lastSet.GetConfig()
	assert.Equal(t, uint32(1), cfg.GetSchemaVersion())
	settings := cfg.GetSplitTunnel()
	require.NotNil(t, settings)
	assert.True(t, settings.GetEnabled())
	assert.Equal(t, "include", settings.GetMode())
	assert.Equal(t, "direct", settings.GetDefaultAction())
	assert.Equal(t, "selective", settings.GetKillSwitch())
}

func TestSplitTunnelApplyRejectsMalformedDaemonConfiguration(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{
			Revision: 4,
			Config:   &proto.SplitTunnelConfig{SchemaVersion: 1},
		},
		setResp: &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          false,
		Mode:             "standard",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_response", clientErr.Code)
	assert.Equal(t, 0, daemon.setCalls)
}

func TestSplitTunnelApplyRejectsEmptyRevisionAdvance(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 4},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_revision_conflict", clientErr.Code)
}

func TestSplitTunnelApplyMapsValidationError(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setErr: reasonError(t, codes.InvalidArgument, api.ReasonInvalidConfig,
			"unsupported mode \"broken\"", map[string]string{"field": "splitTunnel.mode"}),
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_config", clientErr.Code)
	assert.Equal(t, "error.split_tunnel_invalid_config", clientErr.Short)
	assert.Contains(t, clientErr.Long, "splitTunnel.mode")
	assert.Contains(t, clientErr.Long, "unsupported mode")
}

func TestSplitTunnelApplyMapsDeniedMutation(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setErr: reasonError(t, codes.PermissionDenied, api.ReasonMutationDenied,
			"split tunnel mutations require a privileged caller", nil),
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_mutation_denied", clientErr.Code)
	assert.Equal(t, "error.split_tunnel_mutation_denied", clientErr.Short)
	assert.Contains(t, clientErr.Long, "privileged caller")
}

func TestSplitTunnelApplyRejectsUnknownExitNodeRule(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		ExitNodes: []SplitTunnelExitNodeSelection{{
			RuleID:     "missing",
			ExitNodeID: "peer-b",
		}},
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_rule_not_found", clientErr.Code)
	assert.Equal(t, 0, daemon.setCalls)
}

func TestSplitTunnelApplyMapsDaemonRevisionConflict(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setErr: reasonError(t, codes.Aborted, api.ReasonRevisionConflict,
			"split tunnel configuration revision is stale", nil),
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_revision_conflict", clientErr.Code)
	assert.Equal(t, "error.split_tunnel_revision_conflict", clientErr.Short)
	assert.Contains(t, clientErr.Long, "stale")
}

func TestSplitTunnelGetStatusMapsStructuredNotImplemented(t *testing.T) {
	daemon := &stubSplitTunnel{
		statusErr: reasonError(t, codes.Unimplemented, api.ReasonNotImplemented,
			"split tunnel status is not implemented", nil),
	}

	_, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_unavailable", clientErr.Code)
}

func TestSplitTunnelGetStatusMapsUnidentifiedCaller(t *testing.T) {
	daemon := &stubSplitTunnel{
		statusErr: reasonError(t, codes.Unauthenticated, api.ReasonUnauthenticated,
			"caller identity could not be verified", nil),
	}

	_, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_authentication_required", clientErr.Code)
}

func TestSplitTunnelConnErrorIsClassified(t *testing.T) {
	svc := NewSplitTunnel(stubSplitTunnelConn{err: gstatus.Error(codes.Unavailable, "dial daemon: no such file")}, nil, nil)

	_, err := svc.GetStatus(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "daemon_unreachable", clientErr.Code)
}

func degradedCodes(status SplitTunnelStatus) []string {
	codes := make([]string, 0, len(status.DegradedChecks))
	for _, check := range status.DegradedChecks {
		codes = append(codes, check.Code)
	}
	return codes
}

func TestSplitTunnelGetStatusReportsRestartRequired(t *testing.T) {
	daemon := &stubSplitTunnel{
		statusResp: &proto.GetSplitTunnelStatusResponse{
			ApiVersion:  1,
			Enabled:     true,
			Running:     false,
			Backend:     "nftables",
			Diagnostics: map[string]string{"backend.state": "ready"},
		},
	}

	status, err := splitTunnelWith(daemon).GetStatus(context.Background())
	require.NoError(t, err)

	assert.True(t, status.RestartRequired,
		"an enabled configuration that is not running needs a restart or a reapply")
}

func TestSplitTunnelListApplicationsMapsRedaction(t *testing.T) {
	daemon := &stubSplitTunnel{
		appsResp: &proto.ListSplitTunnelApplicationsResponse{
			ApiVersion: 1,
			Applications: []*proto.SplitTunnelApplication{{
				DesktopId:   "firefox.desktop",
				Name:        "Firefox",
				InstallType: "system",
			}},
			RedactedFields: []string{"applications.executable", "applications.source_path"},
		},
	}

	apps, err := splitTunnelWith(daemon).ListApplications(context.Background(), "fire")
	require.NoError(t, err)

	assert.Equal(t, "fire", daemon.lastAppsQuery)
	require.Len(t, apps.Applications, 1)
	assert.Equal(t, "firefox.desktop", apps.Applications[0].DesktopID)
	assert.Equal(t, "Firefox", apps.Applications[0].Name)
	assert.True(t, apps.ExecutableRedacted)
	assert.True(t, apps.SourceRedacted)
	assert.Contains(t, apps.RedactedFields, "applications.executable")
}

func TestSplitTunnelListRulesMapsNestedConditionsAndConflicts(t *testing.T) {
	daemon := &stubSplitTunnel{
		rulesResp: &proto.ListSplitTunnelRulesResponse{
			ApiVersion: 1,
			Revision:   7,
			Conflicts:  []string{"rules \"a\" and \"b\" have identical conditions"},
			Rules: []*proto.SplitTunnelRule{{
				Id:        "a",
				Name:      "Browser",
				Enabled:   true,
				Priority:  5,
				MatchMode: "any",
				Action:    "vpn",
				Conditions: []*proto.SplitTunnelCondition{
					{Type: "desktop_id", Value: "firefox.desktop"},
					{
						Type: "all",
						Children: []*proto.SplitTunnelCondition{
							{Type: "domain", Value: "work.example.com"},
							{Type: "cidr", Value: "10.0.0.0/8"},
						},
					},
				},
			}},
		},
	}

	rules, err := splitTunnelWith(daemon).ListRules(context.Background())
	require.NoError(t, err)

	assert.Equal(t, uint64(7), rules.Revision)
	require.Len(t, rules.Rules, 1)
	rule := rules.Rules[0]
	assert.True(t, rule.Supported)
	assert.Equal(t, "any", rule.MatchMode)
	require.Len(t, rule.Conditions, 2)
	assert.Equal(t, "desktop_id", rule.Conditions[0].Type)
	require.Len(t, rule.Conditions[1].Children, 2)
	assert.Equal(t, "10.0.0.0/8", rule.Conditions[1].Children[1].Value)
	assert.Len(t, rules.Conflicts, 1)
}

func TestSplitTunnelListRulesMarksUnknownConditionUnsupported(t *testing.T) {
	daemon := &stubSplitTunnel{
		rulesResp: &proto.ListSplitTunnelRulesResponse{
			ApiVersion: 1,
			Rules: []*proto.SplitTunnelRule{{
				Id:         "future",
				Name:       "Future rule",
				Enabled:    true,
				Action:     "vpn",
				Conditions: []*proto.SplitTunnelCondition{{Type: "future_condition", Value: "x"}},
			}},
		},
	}

	rules, err := splitTunnelWith(daemon).ListRules(context.Background())
	require.NoError(t, err)

	require.Len(t, rules.Rules, 1)
	assert.False(t, rules.Rules[0].Supported)
	assert.Contains(t, rules.Rules[0].UnsupportedReason, "future_condition")
}

func TestSplitTunnelListEventsMapsTimestampAndRedaction(t *testing.T) {
	when := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	daemon := &stubSplitTunnel{
		eventsResp: &proto.ListSplitTunnelEventsResponse{
			ApiVersion:   1,
			NextSequence: 12,
			Events: []*proto.SplitTunnelEvent{{
				Sequence:      12,
				Type:          "apply",
				Severity:      "info",
				Message:       "policy applied",
				Timestamp:     timestamppb.New(when),
				Redacted:      true,
				DroppedEvents: 3,
			}},
		},
	}

	events, err := splitTunnelWith(daemon).ListEvents(context.Background(), SplitTunnelEventParams{
		AfterSequence: 4,
		Limit:         50,
	})
	require.NoError(t, err)

	require.NotNil(t, daemon.lastEvents)
	assert.Equal(t, uint64(4), daemon.lastEvents.GetAfterSequence())
	assert.Equal(t, uint32(50), daemon.lastEvents.GetLimit())
	assert.Equal(t, uint64(12), events.NextSequence)
	require.Len(t, events.Events, 1)
	assert.Equal(t, when.Format(time.RFC3339Nano), events.Events[0].Timestamp)
	assert.True(t, events.Events[0].Redacted)
	assert.Equal(t, uint64(3), events.Events[0].DroppedEvents)
}

func TestSplitTunnelTracePacketMapsStages(t *testing.T) {
	daemon := &stubSplitTunnel{
		traceResp: &proto.TraceSplitTunnelPacketResponse{
			ApiVersion:  1,
			FinalAction: "direct",
			Redacted:    true,
			Stages: []*proto.SplitTunnelTraceStage{{
				Name:    "policy",
				Message: "matched rule direct",
				Allowed: true,
			}},
		},
	}

	trace, err := splitTunnelWith(daemon).TracePacket(context.Background(), SplitTunnelTraceParams{
		SourceIP:        " 10.0.0.1 ",
		DestinationIP:   "10.1.0.1",
		Protocol:        "TCP",
		SourcePort:      443,
		DestinationPort: 8443,
		Direction:       "outbound",
		UID:             1000,
		HasUID:          true,
	})
	require.NoError(t, err)

	require.NotNil(t, daemon.lastTrace)
	assert.Equal(t, "10.0.0.1", daemon.lastTrace.GetSourceIp())
	assert.Equal(t, "tcp", daemon.lastTrace.GetProtocol())
	assert.True(t, daemon.lastTrace.GetHasUid())
	assert.Equal(t, uint32(1000), daemon.lastTrace.GetUid())
	assert.Equal(t, "direct", trace.FinalAction)
	assert.True(t, trace.Redacted)
	require.Len(t, trace.Stages, 1)
	assert.True(t, trace.Stages[0].Allowed)
}

func TestSplitTunnelRollbackAdvancesRevision(t *testing.T) {
	daemon := &stubSplitTunnel{rollResp: &proto.RollbackSplitTunnelConfigResponse{Revision: 9}}

	result, err := splitTunnelWith(daemon).Rollback(context.Background(), SplitTunnelRollbackParams{
		ExpectedRevision: 8,
		Revision:         5,
	})
	require.NoError(t, err)

	assert.Equal(t, uint64(9), result.Revision)
	require.Equal(t, 1, daemon.rollCalls)
	assert.Equal(t, uint64(8), daemon.lastRollback.GetExpectedRevision())
	assert.Equal(t, uint64(5), daemon.lastRollback.GetRevision())
}

func TestSplitTunnelRollbackRejectsCurrentRevision(t *testing.T) {
	daemon := &stubSplitTunnel{}

	_, err := splitTunnelWith(daemon).Rollback(context.Background(), SplitTunnelRollbackParams{
		ExpectedRevision: 8,
		Revision:         8,
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_request", clientErr.Code)
	assert.Equal(t, 0, daemon.rollCalls)
}

func TestSplitTunnelRollbackMapsMissingRevision(t *testing.T) {
	daemon := &stubSplitTunnel{
		rollErr: gstatus.Error(codes.Internal, "split tunnel configuration revision not found: 3"),
	}

	_, err := splitTunnelWith(daemon).Rollback(context.Background(), SplitTunnelRollbackParams{
		ExpectedRevision: 8,
		Revision:         3,
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_revision_not_found", clientErr.Code)
}

func TestSplitTunnelApplyRulesReplacesSupportedAndPreservesUnsupported(t *testing.T) {
	cfg := sampleConfig()
	cfg.SplitTunnel.Rules = append(cfg.SplitTunnel.Rules, &proto.SplitTunnelRule{
		Id:         "future",
		Name:       "Future",
		Enabled:    true,
		Action:     "vpn",
		Conditions: []*proto.SplitTunnelCondition{{Type: "future_condition", Value: "x"}},
	})
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: cfg},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		RulesChanged:     true,
		Rules: []SplitTunnelRuleInput{{
			ID:         "work",
			Name:       "Work edited",
			Enabled:    true,
			Priority:   3,
			Action:     "exit_node",
			ExitNodeID: "peer-a",
			Conditions: []SplitTunnelCondition{
				{Type: "domain", Value: "Work.Example.com."},
				{
					Type: "any",
					Children: []SplitTunnelCondition{
						{Type: "wildcard_domain", Value: "*.internal.example.com"},
						{Type: "cidr", Value: "192.168.10.0/24"},
					},
				},
			},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, 1, daemon.setCalls)
	rules := daemon.lastSet.GetConfig().GetSplitTunnel().GetRules()
	require.Len(t, rules, 2, "the unsupported rule must survive the write")
	assert.Equal(t, "work", rules[0].GetId())
	assert.Equal(t, "Work edited", rules[0].GetName())
	assert.Equal(t, "work.example.com", rules[0].GetConditions()[0].GetValue())
	assert.Equal(t, "*.internal.example.com", rules[0].GetConditions()[1].GetChildren()[0].GetValue())
	assert.Equal(t, "192.168.10.0/24", rules[0].GetConditions()[1].GetChildren()[1].GetValue())
	assert.Equal(t, "future", rules[1].GetId())
}

func TestSplitTunnelApplyRulesDeletesOmittedSupportedRule(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		RulesChanged:     true,
		Rules: []SplitTunnelRuleInput{{
			ID:         "direct",
			Name:       "Direct",
			Enabled:    true,
			Action:     "direct",
			Conditions: []SplitTunnelCondition{{Type: "domain", Value: "local.example.com"}},
		}},
	})
	require.NoError(t, err)

	rules := daemon.lastSet.GetConfig().GetSplitTunnel().GetRules()
	require.Len(t, rules, 1, "a supported rule omitted from the editor is deleted")
	assert.Equal(t, "direct", rules[0].GetId())
}

func TestSplitTunnelApplyRulesGeneratesIDsForNewRules(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		RulesChanged:     true,
		Rules: []SplitTunnelRuleInput{
			{
				ID:         "work",
				Name:       "Work",
				Enabled:    true,
				Action:     "exit_node",
				ExitNodeID: "peer-a",
				Conditions: []SplitTunnelCondition{{Type: "domain", Value: "work.example.com"}},
			},
			{
				ID:         "direct",
				Name:       "Direct",
				Enabled:    true,
				Action:     "direct",
				Conditions: []SplitTunnelCondition{{Type: "domain", Value: "local.example.com"}},
			},
			{
				Name:       "New",
				Enabled:    true,
				Action:     "vpn",
				Conditions: []SplitTunnelCondition{{Type: "cidr", Value: "172.16.0.0/12"}},
			},
		},
	})
	require.NoError(t, err)

	rules := daemon.lastSet.GetConfig().GetSplitTunnel().GetRules()
	require.Len(t, rules, 3)
	assert.Equal(t, "gui-rule-1", rules[2].GetId())
}

func TestSplitTunnelApplyRulesValidatesNestedCondition(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		RulesChanged:     true,
		Rules: []SplitTunnelRuleInput{{
			Name:    "Broken",
			Enabled: true,
			Action:  "vpn",
			Conditions: []SplitTunnelCondition{{
				Type: "all",
				Children: []SplitTunnelCondition{
					{Type: "cidr", Value: "10.0.0.1/8"},
				},
			}},
		}},
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_config", clientErr.Code)
	assert.Equal(t, "splitTunnel.rules[0].conditions[0].children[0].value", clientErr.Field)
	assert.Contains(t, clientErr.Long, "host bits")
	assert.Equal(t, 0, daemon.setCalls, "an invalid rule must not be written")
}

func TestSplitTunnelApplyRulesRejectsEditingUnsupportedRule(t *testing.T) {
	cfg := sampleConfig()
	cfg.SplitTunnel.Rules[0].Conditions = []*proto.SplitTunnelCondition{{Type: "future_condition", Value: "x"}}
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: cfg},
		setResp:    &proto.SetSplitTunnelConfigResponse{Revision: 5},
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
		RulesChanged:     true,
		Rules: []SplitTunnelRuleInput{{
			ID:         "work",
			Name:       "Work",
			Enabled:    true,
			Action:     "vpn",
			Conditions: []SplitTunnelCondition{{Type: "domain", Value: "work.example.com"}},
		}},
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_invalid_config", clientErr.Code)
	assert.Contains(t, clientErr.Long, "not editable")
	assert.Equal(t, 0, daemon.setCalls)
}

func TestSplitTunnelApplyMapsValidationField(t *testing.T) {
	daemon := &stubSplitTunnel{
		configResp: &proto.GetSplitTunnelConfigResponse{Revision: 4, Config: sampleConfig()},
		setErr: reasonError(t, codes.InvalidArgument, api.ReasonInvalidConfig,
			"unsupported mode \"broken\"", map[string]string{"field": "splitTunnel.mode"}),
	}

	_, err := splitTunnelWith(daemon).Apply(context.Background(), SplitTunnelApplyParams{
		ExpectedRevision: 4,
		Enabled:          true,
		Mode:             "include",
		KillSwitch:       "disabled",
	})
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "splitTunnel.mode", clientErr.Field)
}

func TestSplitTunnelListRulesMapsUnavailable(t *testing.T) {
	daemon := &stubSplitTunnel{
		rulesErr: reasonError(t, codes.Unimplemented, api.ReasonNotImplemented,
			"split tunnel rule listing is not implemented", nil),
	}

	_, err := splitTunnelWith(daemon).ListRules(context.Background())
	require.Error(t, err)

	clientErr, ok := err.(*ClientError)
	require.True(t, ok)
	assert.Equal(t, "split_tunnel_unavailable", clientErr.Code)
}
