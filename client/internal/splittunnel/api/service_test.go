package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	nbproto "github.com/netbirdio/netbird/client/proto"
)

func requireErrorReason(t *testing.T, err error, code codes.Code, reason string) *errdetails.ErrorInfo {
	t.Helper()
	require.Error(t, err)
	converted, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status error, got %v", err)
	assert.Equal(t, code, converted.Code(), "unexpected status code: %v", err)
	for _, detail := range converted.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		assert.Equal(t, ErrorDomain, info.Domain)
		assert.Equal(t, reason, info.Reason)
		return info
	}
	t.Fatalf("error %v carries no ErrorInfo detail", err)
	return nil
}

func TestGetStatusRedactsUnprivilegedCaller(t *testing.T) {
	backend := &fakeBackend{
		status: Status{
			Enabled:  true,
			Running:  true,
			Mode:     config.ModeCustom,
			Backend:  "nftables",
			Revision: 7,
			Processes: []ProcessStatus{{
				PID:        42,
				DesktopID:  "firefox.desktop",
				Name:       "Firefox",
				Executable: "/usr/lib/firefox/firefox",
				UID:        1000,
				Cgroup:     "/user.slice/firefox.scope",
			}},
			Diagnostics: map[string]string{"nftables": "ok"},
		},
	}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	response, err := client.GetStatus(testContext(t), &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	assert.True(t, response.Enabled)
	assert.Equal(t, uint64(7), response.Revision)
	require.Len(t, response.Processes, 1)
	process := response.Processes[0]
	assert.Equal(t, "firefox.desktop", process.DesktopId)
	assert.Zero(t, process.Pid)
	assert.Empty(t, process.Executable)
	assert.Zero(t, process.Uid)
	assert.Empty(t, process.Cgroup)
	assert.Empty(t, response.Diagnostics)
	assert.ElementsMatch(t, []string{
		redactedDiagnostics,
		redactedProcessPID,
		redactedProcessExecutable,
		redactedProcessUID,
		redactedProcessCgroup,
	}, response.RedactedFields)
}

func TestMutationIdentityAllowsProfileOwnerLevel(t *testing.T) {
	id := unprivilegedIdentity()
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: ipcauth.AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       id,
		},
	})
	ctx = ipcauth.WithAuthzLevel(ctx, ipcauth.AuthzLevelProfileOwner)

	svc := New(nil)
	caller, err := svc.mutationIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, id, caller)
}

func TestMutationIdentityDeniesIdentifiedLevel(t *testing.T) {
	id := unprivilegedIdentity()
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: ipcauth.AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       id,
		},
	})
	ctx = ipcauth.WithAuthzLevel(ctx, ipcauth.AuthzLevelIdentified)

	svc := New(nil)
	_, err := svc.mutationIdentity(ctx)
	requireErrorReason(t, err, codes.PermissionDenied, ReasonMutationDenied)
}

func TestGetStatusPrivilegedCallerSeesDiagnostics(t *testing.T) {
	backend := &fakeBackend{
		status: Status{
			Processes:   []ProcessStatus{{PID: 42, Executable: "/usr/lib/firefox/firefox", UID: 1000, Cgroup: "/user.slice/firefox.scope"}},
			Diagnostics: map[string]string{"nftables": "ok"},
		},
	}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	response, err := client.GetStatus(testContext(t), &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	require.Len(t, response.Processes, 1)
	assert.Equal(t, int32(42), response.Processes[0].Pid)
	assert.Equal(t, "/usr/lib/firefox/firefox", response.Processes[0].Executable)
	assert.Equal(t, map[string]string{"nftables": "ok"}, response.Diagnostics)
	assert.Empty(t, response.RedactedFields)
}

func TestMutationRequiresPrivilege(t *testing.T) {
	backend := &fakeBackend{}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion: APIVersion,
		Config:     configToProto(testConfig()),
	})
	requireErrorReason(t, err, codes.PermissionDenied, ReasonMutationDenied)

	_, apply, rollback := backend.calls()
	assert.Zero(t, apply, "denied mutation must not reach the backend")
	assert.Zero(t, rollback)
}

func TestUnidentifiedCallerDenied(t *testing.T) {
	backend := &fakeBackend{}
	client := startTestServer(t, New(backend), ipcauth.Identity{}, false)
	ctx := testContext(t)

	_, err := client.GetStatus(ctx, &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	requireErrorReason(t, err, codes.Unauthenticated, ReasonUnauthenticated)

	_, err = client.SetConfig(ctx, &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion: APIVersion,
		Config:     configToProto(testConfig()),
	})
	requireErrorReason(t, err, codes.Unauthenticated, ReasonUnauthenticated)

	statusCalls, applyCalls, _ := backend.calls()
	assert.Zero(t, statusCalls)
	assert.Zero(t, applyCalls)
}

func TestSetConfigAdvancesRevision(t *testing.T) {
	backend := &fakeBackend{}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	response, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion:       APIVersion,
		ExpectedRevision: 0,
		Config:           configToProto(testConfig()),
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), response.Revision)
	require.NotNil(t, backend.cfg)
	assert.Equal(t, config.RuleID("rule-desktop"), backend.cfg.SplitTunnel.Rules[0].ID)
	assert.Equal(t, uint64(0), backend.lastExpect)
}

func TestSetConfigRevisionConflict(t *testing.T) {
	backend := &fakeBackend{revision: 4}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion:       APIVersion,
		ExpectedRevision: 3,
		Config:           configToProto(testConfig()),
	})
	requireErrorReason(t, err, codes.Aborted, ReasonRevisionConflict)
	assert.Equal(t, uint64(4), backend.revision, "a conflicted mutation must not change the revision")
}

func TestSetConfigRejectsNoOpSuccess(t *testing.T) {
	backend := &fakeBackend{revision: 2, applyRev: 2}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion:       APIVersion,
		ExpectedRevision: 2,
		Config:           configToProto(testConfig()),
	})
	requireErrorReason(t, err, codes.Internal, ReasonInternal)
}

func TestSetConfigRejectsInvalidConfig(t *testing.T) {
	backend := &fakeBackend{}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	invalid := configToProto(testConfig())
	invalid.SplitTunnel.Mode = "unsupported"
	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion: APIVersion,
		Config:     invalid,
	})
	info := requireErrorReason(t, err, codes.InvalidArgument, ReasonInvalidConfig)
	assert.Contains(t, info.Metadata["field"], "mode")

	_, apply, _ := backend.calls()
	assert.Zero(t, apply)
}

func TestRollbackConfig(t *testing.T) {
	backend := &fakeBackend{revision: 5, rollbackRev: 6}
	client := startTestServer(t, New(backend), privilegedIdentity(), true)

	response, err := client.RollbackConfig(testContext(t), &nbproto.RollbackSplitTunnelConfigRequest{
		ApiVersion:       APIVersion,
		ExpectedRevision: 5,
		Revision:         2,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(6), response.Revision)

	_, err = client.RollbackConfig(testContext(t), &nbproto.RollbackSplitTunnelConfigRequest{
		ApiVersion:       APIVersion,
		ExpectedRevision: 6,
		Revision:         0,
	})
	requireErrorReason(t, err, codes.InvalidArgument, ReasonInvalidRequest)
}

func TestUnsupportedAPIVersion(t *testing.T) {
	backend := &fakeBackend{}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	_, err := client.GetStatus(testContext(t), &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion + 1})
	requireErrorReason(t, err, codes.FailedPrecondition, ReasonUnsupportedVersion)
	statusCalls, _, _ := backend.calls()
	assert.Zero(t, statusCalls)
}

func TestGetConfigRoundTrip(t *testing.T) {
	backend := &fakeBackend{cfg: testConfig(), revision: 9}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	response, err := client.GetConfig(testContext(t), &nbproto.GetSplitTunnelConfigRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	assert.Equal(t, uint64(9), response.Revision)
	assert.True(t, proto.Equal(configToProto(testConfig()), response.Config))
}

func TestListApplicationsRedactsPaths(t *testing.T) {
	backend := &fakeBackend{apps: []application.Application{{
		DesktopID:   "firefox.desktop",
		Name:        "Firefox",
		Icon:        application.Icon{Name: "firefox", Path: "/usr/share/icons/firefox.png"},
		Executable:  "/usr/lib/firefox/firefox",
		InstallType: application.InstallSystem,
		SourcePath:  "/usr/share/applications/firefox.desktop",
	}}}

	unprivileged := startTestServer(t, New(backend), unprivilegedIdentity(), true)
	response, err := unprivileged.ListApplications(testContext(t), &nbproto.ListSplitTunnelApplicationsRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	require.Len(t, response.Applications, 1)
	assert.Equal(t, "firefox.desktop", response.Applications[0].DesktopId)
	assert.Empty(t, response.Applications[0].Executable)
	assert.Empty(t, response.Applications[0].IconPath)
	assert.Empty(t, response.Applications[0].SourcePath)
	assert.ElementsMatch(t, []string{
		redactedApplicationExec,
		redactedApplicationIcon,
		redactedApplicationSource,
	}, response.RedactedFields)

	privileged := startTestServer(t, New(backend), privilegedIdentity(), true)
	response, err = privileged.ListApplications(testContext(t), &nbproto.ListSplitTunnelApplicationsRequest{ApiVersion: APIVersion, Query: "fire"})
	require.NoError(t, err)
	require.Len(t, response.Applications, 1)
	assert.Equal(t, "/usr/lib/firefox/firefox", response.Applications[0].Executable)
	assert.Empty(t, response.RedactedFields)

	response, err = privileged.ListApplications(testContext(t), &nbproto.ListSplitTunnelApplicationsRequest{ApiVersion: APIVersion, Query: "chrome"})
	require.NoError(t, err)
	assert.Empty(t, response.Applications)
}

func TestListRules(t *testing.T) {
	backend := &fakeBackend{rules: Rules{
		Revision:  3,
		Rules:     testConfig().SplitTunnel.Rules,
		Conflicts: []string{"rule-desktop overlaps rule-network"},
	}}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	response, err := client.ListRules(testContext(t), &nbproto.ListSplitTunnelRulesRequest{ApiVersion: APIVersion})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), response.Revision)
	require.Len(t, response.Rules, 2)
	assert.Equal(t, "rule-desktop", response.Rules[0].Id)
	assert.Equal(t, []string{"rule-desktop overlaps rule-network"}, response.Conflicts)
}

func TestTracePacketRedactsDiagnostics(t *testing.T) {
	backend := &fakeBackend{trace: TraceResult{
		FinalAction: config.ActionVPN,
		Stages: []TraceStage{{
			Name:              "rule-desktop",
			Message:           "matched",
			Allowed:           true,
			ForwardingDetails: "uid=1000 cgroup=/user.slice/firefox.scope",
		}},
	}}
	request := &nbproto.TraceSplitTunnelPacketRequest{
		ApiVersion:      APIVersion,
		SourceIp:        "10.1.2.3",
		DestinationIp:   "192.168.1.10",
		Protocol:        "TCP",
		SourcePort:      1234,
		DestinationPort: 443,
		Direction:       "outbound",
		Uid:             1000,
		HasUid:          true,
	}

	unprivileged := startTestServer(t, New(backend), unprivilegedIdentity(), true)
	response, err := unprivileged.TracePacket(testContext(t), request)
	require.NoError(t, err)
	require.Len(t, response.Stages, 1)
	assert.Empty(t, response.Stages[0].ForwardingDetails)
	assert.True(t, response.Redacted)
	assert.Equal(t, []string{redactedTraceDetails}, response.RedactedFields)
	assert.Equal(t, "tcp", backend.traceQuery.Protocol)
	require.NotNil(t, backend.traceQuery.UID)
	assert.Equal(t, config.UID(1000), *backend.traceQuery.UID)

	privileged := startTestServer(t, New(backend), privilegedIdentity(), true)
	response, err = privileged.TracePacket(testContext(t), request)
	require.NoError(t, err)
	assert.Equal(t, "uid=1000 cgroup=/user.slice/firefox.scope", response.Stages[0].ForwardingDetails)
	assert.False(t, response.Redacted)
}

func TestTracePacketValidation(t *testing.T) {
	client := startTestServer(t, New(&fakeBackend{}), unprivilegedIdentity(), true)

	_, err := client.TracePacket(testContext(t), &nbproto.TraceSplitTunnelPacketRequest{
		ApiVersion:    APIVersion,
		SourceIp:      "not-an-ip",
		DestinationIp: "192.168.1.10",
	})
	requireErrorReason(t, err, codes.InvalidArgument, ReasonInvalidRequest)
}

func TestRateLimit(t *testing.T) {
	client := startTestServer(t, New(&fakeBackend{}, WithRateLimit(1, 1)), unprivilegedIdentity(), true)
	ctx := testContext(t)

	_, err := client.GetStatus(ctx, &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	require.NoError(t, err)

	_, err = client.GetStatus(ctx, &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	requireErrorReason(t, err, codes.ResourceExhausted, ReasonRateLimited)
}

func TestRequestSizeLimit(t *testing.T) {
	service := New(&fakeBackend{}, WithMaxMessageBytes(1024, 1024), WithRateLimit(0, 0))
	client := startTestServer(t, service, unprivilegedIdentity(), true)

	_, err := client.ListApplications(testContext(t), &nbproto.ListSplitTunnelApplicationsRequest{
		ApiVersion: APIVersion,
		Query:      strings.Repeat("a", 4096),
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestCancellationReachesBackend(t *testing.T) {
	ready := make(chan struct{}, 1)
	backend := &fakeBackend{statusBlock: true, statusReady: ready}
	client := startTestServer(t, New(backend, WithRateLimit(0, 0)), unprivilegedIdentity(), true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.GetStatus(ctx, &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("backend Status was never called")
	}
}

func TestBackendNotImplemented(t *testing.T) {
	backend := &fakeBackend{configErr: ErrNotImplemented}
	client := startTestServer(t, New(backend), unprivilegedIdentity(), true)

	_, err := client.GetConfig(testContext(t), &nbproto.GetSplitTunnelConfigRequest{ApiVersion: APIVersion})
	requireErrorReason(t, err, codes.Unimplemented, ReasonNotImplemented)
}

func TestNilBackendReturnsUnimplemented(t *testing.T) {
	client := startTestServer(t, New(nil), unprivilegedIdentity(), true)

	_, err := client.GetStatus(testContext(t), &nbproto.GetSplitTunnelStatusRequest{ApiVersion: APIVersion})
	requireErrorReason(t, err, codes.Unimplemented, ReasonNotImplemented)
}

func TestMutationAuthorizerCanAllowUnprivilegedCaller(t *testing.T) {
	backend := &fakeBackend{}
	authorizer := func(context.Context, ipcauth.Identity) error { return nil }
	client := startTestServer(t, New(backend, WithMutationAuthorizer(authorizer)), unprivilegedIdentity(), true)

	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion: APIVersion,
		Config:     configToProto(testConfig()),
	})
	require.NoError(t, err)
}

func TestMutationAuthorizerDenialIsStructured(t *testing.T) {
	backend := &fakeBackend{}
	authorizer := func(context.Context, ipcauth.Identity) error {
		return errors.New("not the owner")
	}
	client := startTestServer(t, New(backend, WithMutationAuthorizer(authorizer)), unprivilegedIdentity(), true)

	_, err := client.SetConfig(testContext(t), &nbproto.SetSplitTunnelConfigRequest{
		ApiVersion: APIVersion,
		Config:     configToProto(testConfig()),
	})
	requireErrorReason(t, err, codes.PermissionDenied, ReasonMutationDenied)
	_, apply, _ := backend.calls()
	assert.Zero(t, apply)
}
