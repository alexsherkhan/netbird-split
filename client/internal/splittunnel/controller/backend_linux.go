//go:build linux && !android

package controller

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/diagnostics"
	"github.com/netbirdio/netbird/client/internal/splittunnel/platform/linux"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const platformBackendName = "linux"

type platformBackend struct {
	backend *linux.Backend
}

// NewPlatformBackend returns the Linux split tunnel backend.
func NewPlatformBackend() Backend {
	return &platformBackend{backend: linux.New()}
}

func backendName() string {
	return platformBackendName
}

func (b *platformBackend) Initialize(ctx context.Context) error {
	return b.backend.Initialize(ctx)
}

func (b *platformBackend) Recover(ctx context.Context) (RecoveryReport, error) {
	report, err := b.backend.Recover(ctx, nil)
	if err != nil && !errors.Is(err, linux.ErrRecoveryIntentRequired) {
		return RecoveryReport{}, err
	}
	status := b.backend.RecoveryStatus()
	return RecoveryReport{
		Action:              string(report.Action),
		JournalState:        string(report.JournalState),
		Revision:            report.Revision,
		Issues:              append([]string(nil), report.Issues...),
		ProtectionPreserved: status.ProtectionPreserved,
		RollbackFailed:      status.RollbackFailed,
		LastError:           status.LastError,
	}, nil
}

func (b *platformBackend) ApplyPolicy(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	return b.backend.ApplyPolicy(ctx, compiled, options)
}

func (b *platformBackend) InstallProtection(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
	options backend.PolicyOptions,
) error {
	return b.backend.InstallProtection(ctx, compiled, options)
}

func (b *platformBackend) UpdateDomainSets(
	ctx context.Context,
	updates []backend.DomainSetUpdate,
) error {
	return b.backend.UpdateDomainSets(ctx, updates)
}

func (b *platformBackend) Rollback(ctx context.Context) error {
	return b.backend.Rollback(ctx)
}

func (b *platformBackend) GetStatus(ctx context.Context) (backend.Status, error) {
	return b.backend.GetStatus(ctx)
}

func (b *platformBackend) TrafficCounters(ctx context.Context) (diagnostics.CounterSample, error) {
	return b.backend.TrafficCounters(ctx)
}

func (b *platformBackend) EmergencyReset(ctx context.Context) error {
	return b.backend.EmergencyReset(ctx)
}

func (b *platformBackend) Close(ctx context.Context) error {
	return b.backend.Close(ctx)
}
