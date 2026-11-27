//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

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

	setCalls int
	lastSet  *proto.SetSplitTunnelConfigRequest
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
