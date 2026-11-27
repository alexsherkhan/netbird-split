//go:build linux

package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var errMalformedStat = errors.New("malformed proc stat")

func scanProcesses(ctx context.Context, procRoot string, limit int) ([]Process, error) {
	if procRoot == "" {
		procRoot = defaultProcRoot
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}

	pids := make([]int32, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, int32(pid))
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	processes := make([]Process, 0, len(pids))
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return processes, err
		}
		if limit > 0 && len(processes) >= limit {
			break
		}
		process, ok := readProcess(procRoot, pid)
		if !ok {
			continue
		}
		processes = append(processes, process)
	}
	return processes, nil
}

func readProcess(procRoot string, pid int32) (Process, bool) {
	dir := filepath.Join(procRoot, strconv.FormatInt(int64(pid), 10))

	statData, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, false
	}
	startTime, err := parseStartTime(statData)
	if err != nil {
		return Process{}, false
	}

	uid, err := readProcessUID(filepath.Join(dir, "status"))
	if err != nil {
		return Process{}, false
	}

	executable, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil || executable == "" {
		return Process{}, false
	}

	cgroup := readCgroupPath(filepath.Join(dir, "cgroup"))

	return Process{
		PID:        pid,
		StartTime:  startTime,
		UID:        uid,
		Executable: executable,
		Cgroup:     cgroup,
	}, true
}

func parseStartTime(stat []byte) (uint64, error) {
	closeParen := bytes.LastIndexByte(stat, ')')
	if closeParen < 0 || closeParen+1 >= len(stat) {
		return 0, errMalformedStat
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, errMalformedStat
	}
	startTime, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, errMalformedStat
	}
	return startTime, nil
}

func readProcessUID(statusPath string) (uint32, error) {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			break
		}
		uid, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(uid), nil
	}
	return 0, fmt.Errorf("read UID from %s", statusPath)
}

func readCgroupPath(cgroupPath string) string {
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.SplitN(line, ":", 3)
	if len(fields) != 3 {
		return ""
	}
	return fields[2]
}
