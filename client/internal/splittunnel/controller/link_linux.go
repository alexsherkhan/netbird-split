//go:build linux && !android

package controller

import "github.com/netbirdio/netbird/client/internal/splittunnel/platform/linux"

func newPlatformReconciler(reapplier PolicyReapplier) LinkReconciler {
	return linux.NewReconciler(nil, reapplier)
}
