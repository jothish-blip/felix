//go:build !windows

package browser

import (
	"os"
	"syscall"
)

type osJobHandle struct{}

func newOSJob() (*osJobHandle, error) {
	return &osJobHandle{}, nil
}

func (j *osJobHandle) assignProcess(pid int) error {
	return nil
}

func (j *osJobHandle) terminate(pid int) error {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return nil
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// GetChildPIDs returns child processes for POSIX platforms.
func GetChildPIDs(parentPID int) []int {
	return nil
}
