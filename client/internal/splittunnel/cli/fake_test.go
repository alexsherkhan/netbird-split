package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/client/internal/splittunnel/api"
	"github.com/netbirdio/netbird/client/proto"
)

type fakeSplitServer struct {
	proto.UnimplementedSplitTunnelServiceServer

	mu          sync.Mutex
	status      *proto.GetSplitTunnelStatusResponse
	statusEr    error
	config      *proto.SplitTunnelConfig
	revision    uint64
	hasConfig   bool
	configErr   error
	setErr      error
	rollbackErr error
	apps        []*proto.SplitTunnelApplication
	appsErr     error
	rules       *proto.ListSplitTunnelRulesResponse
	rulesErr    error
	trace       *proto.TraceSplitTunnelPacketResponse
	traceErr    error

	setCalls      int
	rollbackCalls int
	lastExpected  uint64
}

func (s *fakeSplitServer) GetStatus(context.Context, *proto.GetSplitTunnelStatusRequest) (*proto.GetSplitTunnelStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statusEr != nil {
		return nil, s.statusEr
	}
	if s.status == nil {
		return &proto.GetSplitTunnelStatusResponse{ApiVersion: api.APIVersion}, nil
	}
	return s.status, nil
}

func (s *fakeSplitServer) GetConfig(context.Context, *proto.GetSplitTunnelConfigRequest) (*proto.GetSplitTunnelConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configErr != nil {
		return nil, s.configErr
	}
	var cfg *proto.SplitTunnelConfig
	if s.hasConfig {
		cfg = s.config
	}
	return &proto.GetSplitTunnelConfigResponse{
		ApiVersion: api.APIVersion,
		Revision:   s.revision,
		Config:     cfg,
	}, nil
}

func (s *fakeSplitServer) SetConfig(_ context.Context, req *proto.SetSplitTunnelConfigRequest) (*proto.SetSplitTunnelConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setCalls++
	s.lastExpected = req.GetExpectedRevision()
	if s.setErr != nil {
		return nil, s.setErr
	}
	if req.GetExpectedRevision() != s.revision {
		return nil, revisionConflictStatus()
	}
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}
	s.config = req.GetConfig()
	s.hasConfig = true
	s.revision++
	return &proto.SetSplitTunnelConfigResponse{ApiVersion: api.APIVersion, Revision: s.revision}, nil
}

func (s *fakeSplitServer) RollbackConfig(_ context.Context, req *proto.RollbackSplitTunnelConfigRequest) (*proto.RollbackSplitTunnelConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollbackCalls++
	s.lastExpected = req.GetExpectedRevision()
	if s.rollbackErr != nil {
		return nil, s.rollbackErr
	}
	if req.GetExpectedRevision() != s.revision {
		return nil, revisionConflictStatus()
	}
	if req.GetRevision() == 0 {
		return nil, status.Error(codes.InvalidArgument, "revision must be positive")
	}
	s.revision++
	return &proto.RollbackSplitTunnelConfigResponse{ApiVersion: api.APIVersion, Revision: s.revision}, nil
}

func (s *fakeSplitServer) ListApplications(context.Context, *proto.ListSplitTunnelApplicationsRequest) (*proto.ListSplitTunnelApplicationsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.appsErr != nil {
		return nil, s.appsErr
	}
	return &proto.ListSplitTunnelApplicationsResponse{ApiVersion: api.APIVersion, Applications: s.apps}, nil
}

func (s *fakeSplitServer) ListRules(context.Context, *proto.ListSplitTunnelRulesRequest) (*proto.ListSplitTunnelRulesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rulesErr != nil {
		return nil, s.rulesErr
	}
	if s.rules == nil {
		return &proto.ListSplitTunnelRulesResponse{ApiVersion: api.APIVersion}, nil
	}
	return s.rules, nil
}

func (s *fakeSplitServer) TracePacket(context.Context, *proto.TraceSplitTunnelPacketRequest) (*proto.TraceSplitTunnelPacketResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.traceErr != nil {
		return nil, s.traceErr
	}
	if s.trace == nil {
		return &proto.TraceSplitTunnelPacketResponse{ApiVersion: api.APIVersion}, nil
	}
	return s.trace, nil
}

func revisionConflictStatus() error {
	st := status.New(codes.Aborted, "split tunnel configuration revision is stale")
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: api.ReasonRevisionConflict,
		Domain: api.ErrorDomain,
	})
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}

func startFake(t *testing.T, server *fakeSplitServer) DialFunc {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	proto.RegisterSplitTunnelServiceServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve fake split tunnel service: %v", err)
		}
	}()
	t.Cleanup(grpcServer.Stop)

	return func(ctx context.Context) (proto.SplitTunnelServiceClient, io.Closer, error) {
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		return proto.NewSplitTunnelServiceClient(conn), conn, nil
	}
}
