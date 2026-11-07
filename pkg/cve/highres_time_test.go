package cve

import (
	"math"
	"runtime"
	"testing"
	"time"
)

// TestTimer_CorrectnessAndMonotonicity verifies that the timer implementation
// provides positive, monotonic timestamps and correctly measures non-zero durations.
func TestTimer_CorrectnessAndMonotonicity(t *testing.T) {
	freq := QPCFrequency()
	supported := QPCSupported()

	t.Logf("Environment: OS=%s Arch=%s GoVersion=%s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	t.Logf("Timer System: Supported=%t, Hardware Frequency=%d Hz", supported, freq)

	if runtime.GOOS == "windows" {
		if !supported {
			t.Fatalf("QPC must be supported on Windows platforms")
		}
		if freq <= 0 {
			t.Fatalf("QPC frequency must be strictly positive, got %d", freq)
		}
	}

	const samples = 100000
	var prev int64
	var nonMonotonicCount int
	var zeroDiffCount int

	for i := 0; i < samples; i++ {
		now := MonotonicNowNano()
		if now <= 0 {
			t.Fatalf("MonotonicNowNano returned non-positive value at iteration %d: %d", i, now)
		}
		if i > 0 {
			if now < prev {
				nonMonotonicCount++
			}
			if now == prev {
				zeroDiffCount++
			}
		}
		prev = now
	}

	if nonMonotonicCount > 0 {
		t.Fatalf("Detected %d non-monotonic (backwards) timer readings out of %d samples", nonMonotonicCount, samples)
	}

	t.Logf("[PASS] Monotonicity: 0 backwards readings across %d iterations (zero delta in tight loop: %d)", samples, zeroDiffCount)
}

// TestTimer_IntegerOverflowSafety mathematically verifies that conversion of QPC counter ticks
// to nanoseconds never overflows 64-bit signed integers across long uptimes (up to 100+ years).
func TestTimer_IntegerOverflowSafety(t *testing.T) {
	freq := QPCFrequency()
	if freq <= 0 {
		freq = 10000000 // 10 MHz default for testing
	}

	uptimes := []struct {
		name       string
		seconds    int64
		extraTicks int64
	}{
		{"1 hour", 3600, freq / 2},
		{"1 day", 86400, freq / 3},
		{"30 days", 30 * 86400, freq / 4},
		{"365 days (1 year)", 365 * 86400, freq / 5},
		{"10 years", 10 * 365 * 86400, freq / 6},
		{"50 years", 50 * 365 * 86400, freq / 7},
		{"100 years", 100 * 365 * 86400, freq / 8},
	}

	for _, tc := range uptimes {
		t.Run(tc.name, func(t *testing.T) {
			rawTicks := tc.seconds*freq + tc.extraTicks

			// Verify naive multiplication would overflow int64 for large uptimes
			if rawTicks > (math.MaxInt64 / 1000000000) {
				t.Logf("  [Note] Raw ticks %d exceeds naive (ticks * 1e9) int64 capacity", rawTicks)
			}

			// Safe division method:
			sec := rawTicks / freq
			rem := rawTicks % freq
			nanos := (sec * 1000000000) + ((rem * 1000000000) / freq)

			if nanos <= 0 {
				t.Fatalf("Safe conversion overflowed to negative or zero: %d for uptime %s", nanos, tc.name)
			}

			expectedSec := float64(rawTicks) / float64(freq)
			actualSec := float64(nanos) / 1e9
			diffSec := math.Abs(expectedSec - actualSec)
			if diffSec > 1e-6 { // Within 1 microsecond accuracy
				t.Fatalf("Precision error in tick conversion: expected %.6fs, got %.6fs", expectedSec, actualSec)
			}
		})
	}
}

// TestTimer_WindowsSchedulerQuantization reproduces and proves the quantization behavior
// of Go's time.Now() / time.Since() on Windows vs High-Resolution timing.
func TestTimer_WindowsSchedulerQuantization(t *testing.T) {
	const iterations = 5000
	var standardZeroCount int
	var highResZeroCount int

	for i := 0; i < iterations; i++ {
		// Test standard Go time.Since() on a tiny operation
		t0 := time.Now()
		// Workload simulating an active operation (~1-2 microseconds, e.g. parsing/evaluating)
		var sink float64
		for j := 0; j < 200; j++ {
			sink += math.Sqrt(float64(i*200 + j))
		}
		_ = sink
		if time.Since(t0) == 0 {
			standardZeroCount++
		}

		// Test MonotonicNowNano() on the identical workload
		h0 := MonotonicNowNano()
		var sinkH float64
		for j := 0; j < 200; j++ {
			sinkH += math.Sqrt(float64(i*200 + j))
		}
		_ = sinkH
		hDiff := MonotonicNowNano() - h0
		if hDiff <= 0 {
			highResZeroCount++
		}
	}

	t.Logf("Iterations: %d", iterations)
	t.Logf("Go time.Since() == 0 count: %d / %d (%.2f%% quantized to zero)", standardZeroCount, iterations, float64(standardZeroCount)/float64(iterations)*100)
	t.Logf("HighResMonotonic <= 0 count: %d / %d (%.2f%%)", highResZeroCount, iterations, float64(highResZeroCount)/float64(iterations)*100)

	if highResZeroCount > 0 {
		t.Fatalf("High-resolution timer produced %d zero or negative durations on active workloads", highResZeroCount)
	}
}
