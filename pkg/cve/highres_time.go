package cve

// MonotonicNowNano returns the current monotonic timestamp in nanoseconds.
// On Windows, it uses QueryPerformanceCounter (~100ns precision) with safe
// integer overflow handling. On POSIX systems, it uses Go's runtime monotonic clock.
func MonotonicNowNano() int64 {
	return monotonicNowNanoOS()
}
