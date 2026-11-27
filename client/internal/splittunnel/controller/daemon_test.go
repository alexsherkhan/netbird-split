package controller

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/internal/splittunnel/cli"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

type testTransportCreds struct {
	identity ipcauth.Identity
}

type testClientAuthInfo struct{}

func (testClientAuthInfo) AuthType() string { return "split-controller-test" }

func (c testTransportCreds) ClientHandshake(
	_ context.Context,
	_ string,
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	return conn, testClientAuthInfo{}, nil
}

func (c testTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, ipcauth.AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       c.identity,
	}, nil
}

func (c testTransportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "split-controller-test"}
}

func (c testTransportCreds) Clone() credentials.TransportCredentials { return c }

func (c testTransportCreds) OverrideServerName(string) error { return nil }

type testDaemonState struct{}

func (testDaemonState) SessionHolder() (ipcauth.Principal, bool) {
	return ipcauth.Principal{}, false
}

func (testDaemonState) ResolveTarget(ipcauth.Identity, string) (ipcauth.Target, error) {
	return ipcauth.Target{}, nil
}

func unprivilegedTestIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: "S-1-5-21-1-2-3-1001"})
	}
	uid := uint32(os.Geteuid()) + 1
	if uid == 0 {
		uid = 1000
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: uid, GID: uid})
}

func privilegedTestIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: "S-1-5-18"})
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
}

func startDaemonSplitServer(
	t *testing.T,
	ctrl *Controller,
	identity ipcauth.Identity,
) proto.SplitTunnelServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	creds := testTransportCreds{identity: identity}
	gate := ipcauth.NewAuthzGate()
	gate.SetState(testDaemonState{})

	server := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(gate.UnaryPolicyInterceptor()),
		grpc.ChainStreamInterceptor(gate.StreamPolicyInterceptor()),
	)
	api.New(ctrl).Register(server)
	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("serve split tunnel daemon: %v", err)
		}
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(creds),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return proto.NewSplitTunnelServiceClient(conn)
}

func runSplitCLI(t *testing.T, client proto.SplitTunnelServiceClient, args ...string) (string, error) {
	t.Helper()

	cmd := cli.NewCommand(cli.Options{
		Dial: func(context.Context) (proto.SplitTunnelServiceClient, io.Closer, error) {
			return client, io.NopCloser(bytes.NewReader(nil)), nil
		},
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(testContext(t))
	return out.String(), err
}

func TestDaemonSplitCLIStatusAndPrivilegedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	ctrl := newTestController(t, path, &fakeBackend{})
	require.NoError(t, ctrl.Start(testContext(t)))

	client := startDaemonSplitServer(t, ctrl, privilegedTestIdentity())

	output, err := runSplitCLI(t, client, "status")
	require.NoError(t, err)
	assert.Contains(t, output, "Enabled: false")

	_, err = runSplitCLI(t, client, "mode", "include")
	require.NoError(t, err)

	_, err = runSplitCLI(t, client, "enable")
	require.NoError(t, err)

	output, err = runSplitCLI(t, client, "status")
	require.NoError(t, err)
	assert.Contains(t, output, "Mode: include")
	assert.Contains(t, output, "Enabled: true")

	output, err = runSplitCLI(t, client, "config", "get")
	require.NoError(t, err)
	assert.Contains(t, output, `"mode": "include"`)

	cfgFile := filepath.Join(t.TempDir(), "split.json")
	encoded, err := testConfig().Encode()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgFile, encoded, 0o600))
	_, err = runSplitCLI(t, client, "config", "set", cfgFile)
	require.NoError(t, err)

	cfg, revision, err := ctrl.Config(testContext(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), revision)
	require.NotNil(t, cfg)
	assert.Equal(t, config.ModeCustom, cfg.SplitTunnel.Mode)
	assert.True(t, cfg.SplitTunnel.Enabled)
}

func TestDaemonSplitCLIDeniesUnprivilegedMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigFileName)
	backend := &fakeBackend{}
	ctrl := newTestController(t, path, backend)
	require.NoError(t, ctrl.Start(testContext(t)))

	client := startDaemonSplitServer(t, ctrl, unprivilegedTestIdentity())

	_, err := runSplitCLI(t, client, "status")
	require.NoError(t, err, "reads stay available to an identified caller")

	_, err = runSplitCLI(t, client, "mode", "include")
	require.Error(t, err)
	assert.Equal(t, cli.ExitDenied, cli.ExitCode(err))

	_, _, apply := backend.calls()
	assert.Zero(t, apply, "the denied mutation must not reach the backend")
	_, revision, configErr := ctrl.Config(testContext(t))
	require.NoError(t, configErr)
	assert.Zero(t, revision)
}
