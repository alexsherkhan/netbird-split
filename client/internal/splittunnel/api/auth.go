package api

import (
	"context"
	"math"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// readIdentity authorizes a read operation. Every read requires a
// kernel-identified caller; a forwarded identity is accepted only through the
// existing IPC forwarding proof.
func (s *Service) readIdentity(ctx context.Context) (ipcauth.Identity, error) {
	caller, ok := ipcauth.CallerIdentity(ctx)
	if !ok || !caller.Known() {
		return ipcauth.Identity{}, errorWithReason(codes.Unauthenticated, ReasonUnauthenticated,
			"caller identity could not be verified on the daemon control channel", nil)
	}
	return caller, nil
}

// mutationIdentity authorizes a mutation operation. Mutations additionally
// require either the configured authorizer to allow the caller or, by default,
// a privileged caller. An unidentified caller is always refused.
func (s *Service) mutationIdentity(ctx context.Context) (ipcauth.Identity, error) {
	caller, err := s.readIdentity(ctx)
	if err != nil {
		return ipcauth.Identity{}, err
	}
	if s.mutationAuthorizer != nil {
		if err := s.mutationAuthorizer(ctx, caller); err != nil {
			if _, ok := status.FromError(err); ok {
				return ipcauth.Identity{}, err
			}
			return ipcauth.Identity{}, errorWithReason(codes.PermissionDenied,
				ReasonMutationDenied, "caller is not authorized to mutate split tunnel state", nil)
		}
		return caller, nil
	}
	if !ipcauth.IsPrivilegedCaller(caller) {
		return ipcauth.Identity{}, errorWithReason(codes.PermissionDenied, ReasonMutationDenied,
			"split tunnel mutations require a privileged caller", nil)
	}
	return caller, nil
}

// UnaryInterceptor applies the per-caller rate limit and a default deadline to
// unary requests.
func (s *Service) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := s.checkRate(ctx); err != nil {
			return nil, err
		}
		if s.timeout > 0 {
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, s.timeout)
				defer cancel()
			}
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor applies the per-caller rate limit to streaming requests.
// Streams keep the caller's deadline so a subscription can be long lived.
func (s *Service) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := s.checkRate(stream.Context()); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func (s *Service) checkRate(ctx context.Context) error {
	if s.limiter == nil {
		return nil
	}
	caller, ok := ipcauth.CallerIdentity(ctx)
	if !ok || !caller.Known() {
		// Authentication rejects the request on its own; charging a bucket
		// keyed by an unidentified caller would let one caller exhaust others.
		return nil
	}
	if !s.limiter.allow(caller.String()) {
		return errorWithReason(codes.ResourceExhausted, ReasonRateLimited,
			"split tunnel API rate limit exceeded", nil)
	}
	return nil
}

type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*tokenBucket),
	}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	bucket, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= 4096 {
			l.prune(now)
		}
		bucket = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = bucket
	}

	if elapsed := now.Sub(bucket.last).Seconds(); elapsed > 0 {
		bucket.tokens = math.Min(l.burst, bucket.tokens+elapsed*l.rate)
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *rateLimiter) prune(now time.Time) {
	for key, bucket := range l.buckets {
		if now.Sub(bucket.last) > time.Minute {
			delete(l.buckets, key)
		}
	}
}
