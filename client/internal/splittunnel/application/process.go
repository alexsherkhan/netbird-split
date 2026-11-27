package application

import (
	"context"
	"errors"
)

const defaultProcRoot = "/proc"

// ErrUnsupported is returned by ScanProcesses on platforms without /proc.
var ErrUnsupported = errors.New("process scanning is not supported on this platform")

// Process is the identity of one live process. StartTime disambiguates a
// reused PID and Cgroup is the process's cgroup path when it can be read.
type Process struct {
	PID        int32
	StartTime  uint64
	UID        uint32
	Executable string
	Cgroup     string
}

// ProcessKey identifies a process across PID reuse.
type ProcessKey struct {
	PID       int32
	StartTime uint64
}

// Key returns the process identity key.
func (p Process) Key() ProcessKey {
	return ProcessKey{PID: p.PID, StartTime: p.StartTime}
}

// ScanProcesses reads live processes from procRoot, ordered by PID. A positive
// limit bounds the number of returned processes. Processes that disappear or
// cannot be read are skipped.
func ScanProcesses(ctx context.Context, procRoot string, limit int) ([]Process, error) {
	return scanProcesses(ctx, procRoot, limit)
}
