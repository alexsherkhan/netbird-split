//go:build !linux || android

package controller

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

const platformBackendName = "unavailable"

var errUnsupportedPlatform = errors.New("split tunnel backend is not supported on this platform")

type platformBackend struct{}

// NewPlatformBackend returns a backend that keeps the daemon serving status and
// configuration reads while explaining that policy cannot be applied here.
func NewPlatformBackend() Backend {
	return platformBackend{}
}

func backendName() string {
	return platformBackendName
}

func (platformBackend) Initialize(context.Context) error {
	return nil
}

func (platformBackend) Recover(context.Context) (RecoveryReport, error) {
	return RecoveryReport{}, nil
}

func (platformBackend) ApplyPolicy(context.Context, *policy.CompiledPolicy, backend.PolicyOptions) error {
	return errUnsupportedPlatform
}

func (platformBackend) InstallProtection(context.Context, *policy.CompiledPolicy, backend.PolicyOptions) error {
	return errUnsupportedPlatform
}

func (platformBackend) UpdateDomainSets(context.Context, []backend.DomainSetUpdate) error {
	return errUnsupportedPlatform
}

func (platformBackend) Rollback(context.Context) error {
	return errUnsupportedPlatform
}

func (platformBackend) GetStatus(context.Context) (backend.Status, error) {
	return backend.Status{}, errUnsupportedPlatform
}

func (platformBackend) EmergencyReset(context.Context) error {
	return nil
}

func (platformBackend) Close(context.Context) error {
	return nil
}
