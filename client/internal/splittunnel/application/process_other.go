//go:build !linux

package application

import "context"

func scanProcesses(context.Context, string, int) ([]Process, error) {
	return nil, ErrUnsupported
}
