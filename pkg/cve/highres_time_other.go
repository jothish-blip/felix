//go:build !windows

package cve

import (
	"time"
)

// QPCFrequency returns 1,000,000,000 Hz (nanosecond precision) on non-Windows platforms.
func QPCFrequency() int64 {
	return 1000000000
}

// QPCSupported returns true on POSIX platforms where clock_gettime is native.
func QPCSupported() bool {
	return true
}

// monotonicNowNanoOS returns nanoseconds using Go's runtime clock on non-Windows platforms.
func monotonicNowNanoOS() int64 {
	return time.Now().UnixNano()
}
