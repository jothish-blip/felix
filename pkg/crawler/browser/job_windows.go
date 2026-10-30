//go:build windows

package browser

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type osJobHandle struct {
	handle windows.Handle
}

func newOSJob() (*osJobHandle, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("windows.CreateJobObject failed: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	_, err = windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("windows.SetInformationJobObject failed: %w", err)
	}

	return &osJobHandle{handle: h}, nil
}

func (j *osJobHandle) assignProcess(pid int) error {
	if j == nil || j.handle == 0 || pid <= 0 {
		return nil
	}

	procHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("windows.OpenProcess failed for PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(procHandle)

	if err := windows.AssignProcessToJobObject(j.handle, procHandle); err != nil {
		return fmt.Errorf("windows.AssignProcessToJobObject failed for PID %d: %w", pid, err)
	}

	return nil
}

func (j *osJobHandle) terminate(pid int) error {
	if j != nil && j.handle != 0 {
		_ = windows.CloseHandle(j.handle)
		j.handle = 0
	}

	// Secondary safety net: if process tree persists, execute taskkill /F /T
	if pid > 0 && isPIDAlive(pid) {
		_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
	}

	return nil
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}

// GetChildPIDs queries the Windows kernel for all active child processes spawned by parentPID.
func GetChildPIDs(parentPID int) []int {
	if parentPID <= 0 {
		return nil
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}

	var children []int
	targetParent := uint32(parentPID)
	for {
		if entry.ParentProcessID == targetParent {
			children = append(children, int(entry.ProcessID))
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return children
}
