// Package api implements the local gRPC split tunnel control plane.
//
// The service is a typed boundary between the daemon's IPC socket and a split
// tunnel engine. It authenticates callers with kernel-backed identity, separates
// reads from mutations, and owns the API-level concerns: contract versioning,
// configuration revisions, event fan-out, rate limits, request size limits and
// redaction of diagnostics.
package api

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/config"
	"github.com/netbirdio/netbird/client/proto"
)

// APIVersion is the split tunnel API contract version implemented here.
const APIVersion uint32 = 1

// Defaults for the local API service.
const (
	DefaultEventHistory     = 256
	DefaultSubscriberBuffer = 32
	DefaultEventLimit       = 100
	MaxEventLimit           = 1000
	DefaultRateLimit        = 100
	DefaultRateBurst        = 200
	DefaultRequestTimeout   = 30 * time.Second
	DefaultMaxRequestBytes  = 20 << 20
	DefaultMaxResponseBytes = 32 << 20
)

// Errors the backend may return to request a specific API error mapping.
var (
	// ErrNotImplemented reports that the engine cannot satisfy an operation yet.
	ErrNotImplemented = errors.New("split tunnel operation is not implemented")
	// ErrRevisionConflict reports that the caller's expected configuration
	// revision is stale.
	ErrRevisionConflict = errors.New("split tunnel configuration revision conflict")
)

// ConfigStore is the persistent configuration surface of the split tunnel
// engine.
type ConfigStore interface {
	// Config returns the current configuration and revision. A missing
	// configuration is reported with a nil config and revision zero.
	Config(ctx context.Context) (*config.Config, uint64, error)
	// ApplyConfig replaces the configuration when expectedRevision is current.
	ApplyConfig(ctx context.Context, cfg *config.Config, expectedRevision uint64) (uint64, error)
	// RollbackConfig restores revision as a new current revision when
	// expectedRevision is current.
	RollbackConfig(ctx context.Context, revision, expectedRevision uint64) (uint64, error)
}

// Engine is the runtime surface of the split tunnel engine.
type Engine interface {
	// Status returns the current engine status.
	Status(ctx context.Context) (Status, error)
	// Applications returns discovered application metadata.
	Applications(ctx context.Context) ([]application.Application, error)
	// Rules returns the evaluated rules and structural conflicts.
	Rules(ctx context.Context) (Rules, error)
	// Trace evaluates a packet against the current policy.
	Trace(ctx context.Context, query TraceQuery) (TraceResult, error)
}

// Backend is the full engine boundary. The daemon wires a concrete
// implementation after the split tunnel engine exists.
type Backend interface {
	ConfigStore
	Engine
}

// Status is the engine state exposed over the local API.
type Status struct {
	Enabled     bool
	Running     bool
	Mode        config.Mode
	Backend     string
	Revision    uint64
	Processes   []ProcessStatus
	Diagnostics map[string]string
}

// ProcessStatus describes one process attributed to the split tunnel.
type ProcessStatus struct {
	PID        int32
	DesktopID  string
	Name       string
	Executable string
	UID        config.UID
	Cgroup     string
}

// Rules is the evaluated rule set and any structural conflicts.
type Rules struct {
	Revision  uint64
	Rules     []config.Rule
	Conflicts []string
}

// TraceQuery is one packet to evaluate against the policy.
type TraceQuery struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	Protocol        string
	SourcePort      uint16
	DestinationPort uint16
	Direction       string
	UID             *config.UID
}

// TraceResult is the policy evaluation of a traced packet.
type TraceResult struct {
	Stages      []TraceStage
	FinalAction config.Action
}

// TraceStage is one decision step in a trace.
type TraceStage struct {
	Name              string
	Message           string
	Allowed           bool
	ForwardingDetails string
}

// Event is a split tunnel control event published to API subscribers.
type Event struct {
	Sequence  uint64
	Type      string
	Severity  string
	Message   string
	Timestamp time.Time
	Details   map[string]string
}

// MutationAuthorizer decides whether an identified caller may mutate split
// tunnel state. It can relax the default privileged-only rule to the daemon's
// profile ownership model once the service is wired.
type MutationAuthorizer func(ctx context.Context, caller ipcauth.Identity) error

// Service implements the SplitTunnelService gRPC contract.
type Service struct {
	proto.UnimplementedSplitTunnelServiceServer

	backend            Backend
	events             *eventHub
	mutationAuthorizer MutationAuthorizer
	limiter            *rateLimiter
	timeout            time.Duration
	maxRequestBytes    int
	maxResponseBytes   int
	eventHistory       int
	eventBuffer        int
}

// Option configures a Service.
type Option func(*Service)

// New creates a split tunnel API service. A nil backend makes every operation
// return Unimplemented until the daemon wires an engine.
func New(backend Backend, opts ...Option) *Service {
	s := &Service{
		backend:          backend,
		timeout:          DefaultRequestTimeout,
		maxRequestBytes:  DefaultMaxRequestBytes,
		maxResponseBytes: DefaultMaxResponseBytes,
		eventHistory:     DefaultEventHistory,
		eventBuffer:      DefaultSubscriberBuffer,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.events = newEventHub(s.eventHistory, s.eventBuffer)
	return s
}

// WithEventHistory bounds the number of retained events.
func WithEventHistory(size int) Option {
	return func(s *Service) {
		if size >= 0 {
			s.eventHistory = size
		}
	}
}

// WithSubscriberBuffer bounds the number of queued events per subscriber.
func WithSubscriberBuffer(size int) Option {
	return func(s *Service) {
		if size > 0 {
			s.eventBuffer = size
		}
	}
}

// WithRateLimit sets the per-caller request rate and burst. A non-positive
// rate disables rate limiting.
func WithRateLimit(rate float64, burst int) Option {
	return func(s *Service) {
		s.limiter = newRateLimiter(rate, burst)
	}
}

// WithRequestTimeout bounds unary requests that do not already carry a
// deadline. A non-positive timeout disables the default.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(s *Service) {
		s.timeout = timeout
	}
}

// WithMaxMessageBytes overrides the gRPC receive and send message limits.
func WithMaxMessageBytes(request, response int) Option {
	return func(s *Service) {
		if request > 0 {
			s.maxRequestBytes = request
		}
		if response > 0 {
			s.maxResponseBytes = response
		}
	}
}

// WithMutationAuthorizer overrides the default privileged-only mutation rule.
func WithMutationAuthorizer(authorizer MutationAuthorizer) Option {
	return func(s *Service) {
		s.mutationAuthorizer = authorizer
	}
}

// Register registers the service on a gRPC server.
func (s *Service) Register(registrar grpc.ServiceRegistrar) {
	proto.RegisterSplitTunnelServiceServer(registrar, s)
}

// ServerOptions returns the gRPC options the daemon should apply when serving
// the split tunnel API: message size limits and the rate-limiting
// interceptors.
func (s *Service) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.maxRequestBytes),
		grpc.MaxSendMsgSize(s.maxResponseBytes),
		grpc.ChainUnaryInterceptor(s.UnaryInterceptor()),
		grpc.ChainStreamInterceptor(s.StreamInterceptor()),
	}
}

// Publish records an event in the bounded history and delivers it to current
// subscribers. The engine calls it for state changes clients need to observe.
func (s *Service) Publish(event Event) {
	s.events.publish(event)
}
