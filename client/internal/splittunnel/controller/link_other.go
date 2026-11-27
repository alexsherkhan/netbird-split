//go:build !linux || android

package controller

func newPlatformReconciler(PolicyReapplier) LinkReconciler {
	return nil
}
