//go:build linux && !android

package controller

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/client/internal/splittunnel/application"
	"github.com/netbirdio/netbird/client/internal/splittunnel/backend"
	"github.com/netbirdio/netbird/client/internal/splittunnel/classifier"
	"github.com/netbirdio/netbird/client/internal/splittunnel/policy"
)

// NewPlatformApplications returns the Linux application registry and cgroup
// classifier. It never executes a desktop entry command; discovery only reads
// metadata.
func NewPlatformApplications() ApplicationProvider {
	registry := application.New(application.Options{})
	manager, err := classifier.New(registry, classifier.Options{})
	if err != nil {
		return &unavailableApplications{err: err}
	}
	return &classifierApplications{registry: registry, manager: manager}
}

type classifierApplications struct {
	registry *application.Registry
	manager  *classifier.Manager
}

func (a *classifierApplications) Reconcile(
	ctx context.Context,
	compiled *policy.CompiledPolicy,
) ([]backend.ApplicationScope, error) {
	return a.manager.Reconcile(ctx, compiled)
}

func (a *classifierApplications) List() []application.Application {
	return a.registry.List()
}

func (a *classifierApplications) Close() error {
	return a.manager.Close()
}

type unavailableApplications struct {
	err error
}

func (a *unavailableApplications) Reconcile(
	context.Context,
	*policy.CompiledPolicy,
) ([]backend.ApplicationScope, error) {
	return nil, errors.Join(errors.New("application classifier is unavailable"), a.err)
}

func (a *unavailableApplications) List() []application.Application {
	return nil
}

func (a *unavailableApplications) Close() error {
	return nil
}
