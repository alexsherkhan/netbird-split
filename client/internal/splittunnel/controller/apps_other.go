//go:build !linux || android

package controller

// NewPlatformApplications reports that application classification is not
// available on this platform. A policy that uses application rules fails
// closed instead of applying without the scopes it needs.
func NewPlatformApplications() ApplicationProvider {
	return nil
}
