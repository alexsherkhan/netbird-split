package ipcauth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	nbproto "github.com/netbirdio/netbird/client/proto"
)

func TestSplitMethodPoliciesCoverService(t *testing.T) {
	sd := nbproto.File_split_tunnel_proto.Services().ByName("SplitTunnelService")
	require.NotNil(t, sd, "SplitTunnelService is missing from the proto descriptor")

	for i := 0; i < sd.Methods().Len(); i++ {
		name := string(sd.Methods().Get(i).Name())
		assert.Contains(t, splitMethodPolicies, splitServicePath+name,
			"%s has no explicit split tunnel policy", name)
	}

	registered := make(map[string]struct{}, len(splitMethodPolicies))
	for method := range splitMethodPolicies {
		registered[strings.TrimPrefix(method, splitServicePath)] = struct{}{}
	}
	for i := 0; i < sd.Methods().Len(); i++ {
		delete(registered, string(sd.Methods().Get(i).Name()))
	}
	for stale := range registered {
		assert.Fail(t, "stale split tunnel policy entry",
			"splitMethodPolicies has %s, which SplitTunnelService does not define", stale)
	}
}

func TestSplitMethodPolicyKeysAreFullMethodNames(t *testing.T) {
	for method := range splitMethodPolicies {
		assert.True(t, strings.HasPrefix(method, splitServicePath),
			"%q is not a full gRPC method name and can never match a request", method)
	}
}

func TestSplitReadsAllowIdentifiedCallers(t *testing.T) {
	g := gateFor(t, stubState{})
	reads := []string{
		"GetStatus",
		"GetConfig",
		"ListApplications",
		"ListRules",
		"TracePacket",
		"ListEvents",
		"SubscribeEvents",
	}
	for _, method := range reads {
		t.Run(method, func(t *testing.T) {
			_, err := g.authorize(transportCtx(unprivUser, nil), splitServicePath+method, nil)
			assert.NoError(t, err)
		})
	}
}

func TestSplitMutationsRequirePrivilege(t *testing.T) {
	g := gateFor(t, stubState{})
	for _, method := range []string{"SetConfig", "RollbackConfig"} {
		t.Run(method, func(t *testing.T) {
			_, err := g.authorize(transportCtx(unprivUser, nil), splitServicePath+method, nil)
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
			assert.NotContains(t, err.Error(), "profile claim",
				"a split tunnel refusal must not suggest a profile remedy")
		})
	}
}

func TestSplitPrivilegedMutationsAllowed(t *testing.T) {
	g := gateFor(t, stubState{})
	for _, method := range []string{"SetConfig", "RollbackConfig"} {
		t.Run(method, func(t *testing.T) {
			_, err := g.authorize(transportCtx(root, nil), splitServicePath+method, nil)
			assert.NoError(t, err)
		})
	}
}

func TestSplitUnknownMethodDeniedForUnprivilegedCaller(t *testing.T) {
	g := gateFor(t, stubState{})
	_, err := g.authorize(transportCtx(unprivUser, nil), splitServicePath+"NotARealMethod", nil)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
}

func TestSplitUnidentifiedCallerDenied(t *testing.T) {
	g := gateFor(t, stubState{})
	_, err := g.authorize(transportCtx(Identity{}, nil), splitServicePath+"GetStatus", nil)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
}
