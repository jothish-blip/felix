//go:build windows

package oast

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	qpcSupported bool
	qpcFreq      int64
	qpcInitOnce  sync.Once

	modkernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procQueryPerformanceCounter   = modkernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modkernel32.NewProc("QueryPerformanceFrequency")
)

func initQPC() {
	var freq int64
	r1, _, _ := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	if r1 != 0 && freq > 0 {
		qpcFreq = freq
		qpcSupported = true
	}
}

// QPCFrequency returns the hardware QPC frequency in Hertz.
func QPCFrequency() int64 {
	qpcInitOnce.Do(initQPC)
	return qpcFreq
}

// QPCSupported returns whether high-resolution QPC is active on this system.
func QPCSupported() bool {
	qpcInitOnce.Do(initQPC)
	return qpcSupported
}

// monotonicNowNanoOS implements high-resolution monotonic time on Windows.
// It converts ticks to nanoseconds without 64-bit integer overflow:
//
//	sec := count / freq
//	rem := count % freq
//	nanos := (sec * 1_000_000_000) + ((rem * 1_000_000_000) / freq)
func monotonicNowNanoOS() int64 {
	qpcInitOnce.Do(initQPC)
	if qpcSupported {
		var count int64
		r1, _, _ := procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&count)))
		if r1 != 0 && count > 0 {
			sec := count / qpcFreq
			rem := count % qpcFreq
			return (sec * 1000000000) + ((rem * 1000000000) / qpcFreq)
		}
	}
	return time.Now().UnixNano()
}
