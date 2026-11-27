//go:build linux && !android

package linux

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		release   string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{release: "7.0.0-43-generic", wantMajor: 7, wantMinor: 0, wantOK: true},
		{release: "4.10", wantMajor: 4, wantMinor: 10, wantOK: true},
		{release: "6.8.0+", wantMajor: 6, wantMinor: 8, wantOK: true},
		{release: "garbage", wantOK: false},
		{release: "5", wantOK: false},
		{release: "5.x", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			major, minor, ok := parseKernelVersion(tt.release)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantMajor, major)
			assert.Equal(t, tt.wantMinor, minor)
		})
	}
}

func TestCapabilityFromError(t *testing.T) {
	permission := capabilityFromError(
		backend.CapabilityNFTables,
		"list nftables tables",
		os.ErrPermission,
	)
	assert.Equal(t, backend.CapabilityUnavailable, permission.State)
	assert.Contains(t, permission.Detail, "CAP_NET_ADMIN")

	unsupported := capabilityFromError(
		backend.CapabilityNFTables,
		"list nftables tables",
		unix.EOPNOTSUPP,
	)
	assert.Equal(t, backend.CapabilityUnavailable, unsupported.State)
	assert.Contains(t, unsupported.Detail, "not supported")

	other := capabilityFromError(
		backend.CapabilityNetlink,
		"list links",
		errors.New("boom"),
	)
	assert.Equal(t, backend.CapabilityUnavailable, other.State)
	assert.Contains(t, other.Detail, "boom")
}

func TestSystemProberReturnsEveryCapability(t *testing.T) {
	capabilities, err := systemProber{}.Probe(context.Background())
	require.NoError(t, err)

	for _, id := range []backend.CapabilityID{
		backend.CapabilityNFTables,
		backend.CapabilityNetlink,
		backend.CapabilityPolicyRouting,
		backend.CapabilityRouteOutputHook,
		backend.CapabilityCgroupV2,
		backend.CapabilityIPv6,
	} {
		item, ok := capabilities.Get(id)
		require.True(t, ok, "capability %q must be probed", id)
		assert.NotEmpty(t, item.Detail, "capability %q must explain its state", id)
		switch item.State {
		case backend.CapabilityAvailable, backend.CapabilityUnavailable,
			backend.CapabilityDegraded, backend.CapabilityUnknown:
		default:
			t.Fatalf("capability %q has invalid state %q", id, item.State)
		}
	}
}

func TestSystemProberHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := systemProber{}.Probe(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestProbeRouteOutputHookReportsKernel(t *testing.T) {
	item := probeRouteOutputHook()
	assert.Equal(t, backend.CapabilityRouteOutputHook, item.ID)
	assert.NotEmpty(t, item.Detail)
	assert.NotEqual(t, backend.CapabilityDegraded, item.State)
}
