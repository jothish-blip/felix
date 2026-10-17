package apk

import (
	"fmt"
	"math"
)

const (
	// DefaultMaxCompressedSize is 200 MiB, bounding the raw input APK size.
	DefaultMaxCompressedSize int64 = 200 * 1024 * 1024

	// DefaultMaxArchiveEntries limits total files/directories declared in the central directory.
	DefaultMaxArchiveEntries int = 20000

	// DefaultMaxEntrySize is 100 MiB, bounding any single uncompressed entry (e.g., classes.dex or assets).
	DefaultMaxEntrySize int64 = 100 * 1024 * 1024

	// DefaultMaxCumulativeDecompressedSize is 500 MiB, bounding total extracted payload across all entries.
	DefaultMaxCumulativeDecompressedSize int64 = 500 * 1024 * 1024

	// DefaultMaxCompressionRatio is 100:1, rejecting high-expansion decompression bombs.
	DefaultMaxCompressionRatio float64 = 100.0

	// DefaultMaxPathLength is 1024 characters for any entry path.
	DefaultMaxPathLength int = 1024

	// DefaultMaxPathDepth is 30 directory nesting levels.
	DefaultMaxPathDepth int = 30

	// RatioCheckThresholdBytes is the minimum decompressed bytes before evaluating compression ratios,
	// preventing false positives on tiny files (e.g., empty or small text files with high metadata overhead).
	RatioCheckThresholdBytes int64 = 256 * 1024
)

// Limits encapsulates the configurable resource bounds for APK archive ingestion.
type Limits struct {
	// MaxCompressedSize is the maximum permitted size of the input APK on disk.
	MaxCompressedSize int64

	// MaxArchiveEntries is the maximum number of archive entries permitted.
	MaxArchiveEntries int

	// MaxEntrySize is the maximum uncompressed bytes permitted for any single entry.
	MaxEntrySize int64

	// MaxCumulativeDecompressedSize is the maximum total uncompressed bytes across all entries.
	MaxCumulativeDecompressedSize int64

	// MaxCompressionRatio is the maximum allowed ratio of decompressed bytes to compressed bytes.
	MaxCompressionRatio float64

	// MaxPathLength is the maximum character length permitted for an entry filename.
	MaxPathLength int

	// MaxPathDepth is the maximum directory nesting depth permitted for an entry path.
	MaxPathDepth int
}

// DefaultLimits returns conservative, production-minded default bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxCompressedSize:             DefaultMaxCompressedSize,
		MaxArchiveEntries:             DefaultMaxArchiveEntries,
		MaxEntrySize:                  DefaultMaxEntrySize,
		MaxCumulativeDecompressedSize: DefaultMaxCumulativeDecompressedSize,
		MaxCompressionRatio:           DefaultMaxCompressionRatio,
		MaxPathLength:                 DefaultMaxPathLength,
		MaxPathDepth:                  DefaultMaxPathDepth,
	}
}

// Validate verifies that configured limits are strictly positive, coherent, and within safe numeric ranges.
func (l Limits) Validate() error {
	if l.MaxCompressedSize <= 0 {
		return fmt.Errorf("%w: MaxCompressedSize must be positive, got %d", ErrLimitExceeded, l.MaxCompressedSize)
	}
	if l.MaxArchiveEntries <= 0 {
		return fmt.Errorf("%w: MaxArchiveEntries must be positive, got %d", ErrLimitExceeded, l.MaxArchiveEntries)
	}
	if l.MaxEntrySize <= 0 {
		return fmt.Errorf("%w: MaxEntrySize must be positive, got %d", ErrLimitExceeded, l.MaxEntrySize)
	}
	if l.MaxCumulativeDecompressedSize <= 0 {
		return fmt.Errorf("%w: MaxCumulativeDecompressedSize must be positive, got %d", ErrLimitExceeded, l.MaxCumulativeDecompressedSize)
	}
	if l.MaxCumulativeDecompressedSize < l.MaxEntrySize {
		return fmt.Errorf("%w: MaxCumulativeDecompressedSize (%d) cannot be less than MaxEntrySize (%d)",
			ErrLimitExceeded, l.MaxCumulativeDecompressedSize, l.MaxEntrySize)
	}
	if l.MaxCompressionRatio < 1.0 || math.IsNaN(l.MaxCompressionRatio) || math.IsInf(l.MaxCompressionRatio, 0) {
		return fmt.Errorf("%w: MaxCompressionRatio must be >= 1.0, got %v", ErrLimitExceeded, l.MaxCompressionRatio)
	}
	if l.MaxPathLength <= 0 {
		return fmt.Errorf("%w: MaxPathLength must be positive, got %d", ErrLimitExceeded, l.MaxPathLength)
	}
	if l.MaxPathDepth <= 0 {
		return fmt.Errorf("%w: MaxPathDepth must be positive, got %d", ErrLimitExceeded, l.MaxPathDepth)
	}
	return nil
}

// CheckCumulativeGrowth verifies that adding entryBytes to currentBytes does not overflow or exceed maxBytes.
func CheckCumulativeGrowth(currentBytes, entryBytes, maxBytes int64) error {
	if entryBytes < 0 {
		return fmt.Errorf("%w: negative entry bytes (%d)", ErrLimitExceeded, entryBytes)
	}
	if currentBytes > math.MaxInt64-entryBytes {
		return fmt.Errorf("%w: cumulative byte calculation integer overflow", ErrLimitExceeded)
	}
	if currentBytes+entryBytes > maxBytes {
		return fmt.Errorf("%w: cumulative decompressed size would reach %d bytes, exceeding maximum allowed limit of %d bytes",
			ErrLimitExceeded, currentBytes+entryBytes, maxBytes)
	}
	return nil
}

// CheckCompressionRatio evaluates whether decompressedBytes / compressedBytes exceeds maxRatio.
func CheckCompressionRatio(decompressedBytes, compressedBytes int64, maxRatio float64) error {
	if decompressedBytes < RatioCheckThresholdBytes {
		return nil
	}
	// Avoid division by zero: if compressed bytes is 0 or negative for a non-trivial file, flag it
	if compressedBytes <= 0 {
		return fmt.Errorf("%w: extreme compression anomaly: %d decompressed bytes from %d compressed bytes",
			ErrLimitExceeded, decompressedBytes, compressedBytes)
	}
	ratio := float64(decompressedBytes) / float64(compressedBytes)
	if ratio > maxRatio {
		return fmt.Errorf("%w: compression ratio %.1f:1 exceeds maximum allowed limit of %.1f:1 (potential ZIP bomb)",
			ErrLimitExceeded, ratio, maxRatio)
	}
	return nil
}
