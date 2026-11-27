package api

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

type fakeBackend struct {
	mu sync.Mutex

	status      Status
	statusErr   error
	statusBlock bool
	statusReady chan struct{}
	statusCalls int

	cfg        *config.Config
	revision   uint64
	configErr  error
	applyErr   error
	applyRev   uint64
	applyCalls int
	lastExpect uint64

	rollbackErr   error
	rollbackRev   uint64
	rollbackCalls int

	apps    []application.Application
	appsErr error

	rules    Rules
	rulesErr error

	trace      TraceResult
	traceErr   error
	traceQuery TraceQuery
}

func (b *fakeBackend) Status(ctx context.Context) (Status, error) {
	b.mu.Lock()
	b.statusCalls++
	block := b.statusBlock
	ready := b.statusReady
	b.mu.Unlock()

	if block {
		if ready != nil {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
		<-ctx.Done()
		return Status{}, ctx.Err()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status, b.statusErr
}

func (b *fakeBackend) Config(context.Context) (*config.Config, uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg, b.revision, b.configErr
}

func (b *fakeBackend) ApplyConfig(_ context.Context, cfg *config.Config, expected uint64) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.applyCalls++
	b.lastExpect = expected
	if b.applyErr != nil {
		return 0, b.applyErr
	}
	if expected != b.revision {
		return 0, ErrRevisionConflict
	}
	b.cfg = cfg
	if b.applyRev != 0 {
		b.revision = b.applyRev
	} else {
		b.revision++
	}
	return b.revision, nil
}

func (b *fakeBackend) RollbackConfig(_ context.Context, revision, expected uint64) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollbackCalls++
	b.lastExpect = expected
	if b.rollbackErr != nil {
		return 0, b.rollbackErr
	}
	if expected != b.revision {
		return 0, ErrRevisionConflict
	}
	if b.rollbackRev != 0 {
		b.revision = b.rollbackRev
	} else {
		b.revision++
	}
	return b.revision, nil
}

func (b *fakeBackend) Applications(context.Context) ([]application.Application, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.apps, b.appsErr
}

func (b *fakeBackend) Rules(context.Context) (Rules, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rules, b.rulesErr
}

func (b *fakeBackend) Trace(_ context.Context, query TraceQuery) (TraceResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.traceQuery = query
	return b.trace, b.traceErr
}

func (b *fakeBackend) calls() (status, apply, rollback int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.statusCalls, b.applyCalls, b.rollbackCalls
}

func testConfig() *config.Config {
	return &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		SplitTunnel: config.SplitTunnel{
			Enabled:       true,
			Mode:          config.ModeCustom,
			DefaultAction: config.ActionDirect,
			KillSwitch:    config.KillSwitchSelective,
			IPv6:          true,
			DNS: config.DNSSettings{
				TrackingEnabled: true,
				RespectTTL:      true,
				ConflictPolicy:  config.ConflictVPN,
			},
			Rules: []config.Rule{
				{
					ID:        "rule-desktop",
					Name:      "Firefox",
					Enabled:   true,
					Priority:  10,
					MatchMode: config.MatchAll,
					Conditions: []config.Condition{
						{Type: config.ConditionDesktopID, DesktopID: "firefox.desktop"},
					},
					Action: config.ActionVPN,
				},
				{
					ID:        "rule-network",
					Name:      "Private network",
					Enabled:   true,
					Priority:  20,
					MatchMode: config.MatchAny,
					Conditions: []config.Condition{
						{Type: config.ConditionCIDR, Prefix: mustPrefix("10.0.0.0/8")},
						{Type: config.ConditionProtocolPort, Protocol: config.ProtocolTCP, Port: 443},
					},
					Action: config.ActionDirect,
				},
			},
		},
	}
}

func mustPrefix(value string) netip.Prefix {
	prefix, err := parsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix
}

func privilegedIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: "S-1-5-18"})
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: 0})
}

func unprivilegedIdentity() ipcauth.Identity {
	if runtime.GOOS == "windows" {
		return ipcauth.KnownForTest(ipcauth.Identity{SID: "S-1-5-21-1-2-3-1001"})
	}
	return ipcauth.KnownForTest(ipcauth.Identity{UID: uint32(os.Geteuid()) + 1, GID: uint32(os.Geteuid()) + 1})
}

func testCreds(id ipcauth.Identity, known bool) testTransportCreds {
	return testTransportCreds{identity: id, known: known}
}

type testTransportCreds struct {
	identity ipcauth.Identity
	known    bool
}

type clientAuthInfo struct{}
type opaqueAuthInfo struct{}

func (clientAuthInfo) AuthType() string { return "splittunnel-test" }
func (opaqueAuthInfo) AuthType() string { return "splittunnel-test" }

func (c testTransportCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, clientAuthInfo{}, nil
}

func (c testTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.known {
		return conn, opaqueAuthInfo{}, nil
	}
	return conn, ipcauth.AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       c.identity,
	}, nil
}

func (c testTransportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "splittunnel-test"}
}

func (c testTransportCreds) Clone() credentials.TransportCredentials { return c }

func (c testTransportCreds) OverrideServerName(string) error { return nil }

func startTestServer(t *testing.T, svc *Service, id ipcauth.Identity, known bool) proto.SplitTunnelServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	serverCalls := testCreds(id, known)
	opts := append(svc.ServerOptions(), grpc.Creds(serverCalls))
	server := grpc.NewServer(opts...)
	svc.Register(server)
	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("serve split tunnel API: %v", err)
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
		grpc.WithTransportCredentials(serverCalls),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return proto.NewSplitTunnelServiceClient(conn)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
