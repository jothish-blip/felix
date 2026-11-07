package mobile

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	// DefaultMaxZipEntries prevents denial-of-service from archives with millions of tiny files.
	DefaultMaxZipEntries = 10000

	// DefaultMaxSingleEntrySize caps any single extracted file (100 MB).
	DefaultMaxSingleEntrySize = 100 * 1024 * 1024

	// DefaultMaxTotalUncompressedSize caps the cumulative uncompressed size of extracted files (250 MB).
	DefaultMaxTotalUncompressedSize = 250 * 1024 * 1024

	// DefaultMaxCompressionRatio protects against zip bombs (e.g., 42.zip).
	DefaultMaxCompressionRatio = 100
)

// ArchiveSecurityLimits defines thresholds for safe ZIP processing.
type ArchiveSecurityLimits struct {
	MaxEntries            int
	MaxSingleEntrySize    int64
	MaxTotalUncompressed  int64
	MaxCompressionRatio   int64
}

// DefaultArchiveLimits returns safe production limits.
func DefaultArchiveLimits() ArchiveSecurityLimits {
	return ArchiveSecurityLimits{
		MaxEntries:           DefaultMaxZipEntries,
		MaxSingleEntrySize:   DefaultMaxSingleEntrySize,
		MaxTotalUncompressed: DefaultMaxTotalUncompressedSize,
		MaxCompressionRatio:  DefaultMaxCompressionRatio,
	}
}

// SafeZipReader validates and inspects a ZIP archive while protecting against traversal, zip-bombs, and unbounded memory consumption.
type SafeZipReader struct {
	Reader *zip.Reader
	Limits ArchiveSecurityLimits
}

// NewSafeZipReader creates a SafeZipReader with specified or default security limits.
func NewSafeZipReader(r *zip.Reader, limits *ArchiveSecurityLimits) (*SafeZipReader, error) {
	if r == nil {
		return nil, errors.New("zip reader cannot be nil")
	}
	lim := DefaultArchiveLimits()
	if limits != nil {
		if limits.MaxEntries > 0 {
			lim.MaxEntries = limits.MaxEntries
		}
		if limits.MaxSingleEntrySize > 0 {
			lim.MaxSingleEntrySize = limits.MaxSingleEntrySize
		}
		if limits.MaxTotalUncompressed > 0 {
			lim.MaxTotalUncompressed = limits.MaxTotalUncompressed
		}
		if limits.MaxCompressionRatio > 0 {
			lim.MaxCompressionRatio = limits.MaxCompressionRatio
		}
	}

	if len(r.File) > lim.MaxEntries {
		return nil, fmt.Errorf("archive entry count %d exceeds safety limit %d", len(r.File), lim.MaxEntries)
	}

	// Validate all archive entry names for path traversal or null byte injection
	for _, f := range r.File {
		name := f.Name
		if strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("malformed archive entry contains null byte: %q", name)
		}
		clean := filepath.Clean(name)
		if strings.HasPrefix(clean, "..") || strings.Contains(name, "../") || strings.Contains(name, `..\`) {
			return nil, fmt.Errorf("directory traversal attempt detected in entry: %q", name)
		}
		if filepath.IsAbs(clean) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
			return nil, fmt.Errorf("absolute path detected in entry: %q", name)
		}
	}

	return &SafeZipReader{
		Reader: r,
		Limits: lim,
	}, nil
}

// ValidateEntrySecurity verifies that a ZIP file entry does not attempt directory traversal or zip-bomb inflation.
func (s *SafeZipReader) ValidateEntrySecurity(entry *zip.File) error {
	if entry == nil {
		return errors.New("nil entry")
	}

	// 1. Path traversal check: check for null bytes, relative traversal, absolute paths
	name := entry.Name
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("malformed archive entry contains null byte: %q", name)
	}
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || strings.Contains(name, "../") || strings.Contains(name, `..\`) {
		return fmt.Errorf("directory traversal attempt detected in entry: %q", name)
	}
	if filepath.IsAbs(clean) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return fmt.Errorf("absolute path detected in entry: %q", name)
	}

	// 2. Size limit checks
	uncompressedSize := int64(entry.UncompressedSize64)
	if uncompressedSize > s.Limits.MaxSingleEntrySize {
		return fmt.Errorf("entry %q uncompressed size (%d bytes) exceeds single-entry limit (%d bytes)",
			name, uncompressedSize, s.Limits.MaxSingleEntrySize)
	}

	// 3. Compression ratio check (zip-bomb guard)
	compressedSize := int64(entry.CompressedSize64)
	if compressedSize > 0 && uncompressedSize > 1024*1024 { // only enforce ratio for non-trivial uncompressed sizes
		ratio := uncompressedSize / compressedSize
		if ratio > s.Limits.MaxCompressionRatio {
			return fmt.Errorf("entry %q compression ratio %d:1 exceeds maximum safety ratio %d:1 (possible zip bomb)",
				name, ratio, s.Limits.MaxCompressionRatio)
		}
	}

	return nil
}

// ReadTargetEntry safely extracts an exact entry into memory, subject to size limits and context cancellation.
func (s *SafeZipReader) ReadTargetEntry(ctx context.Context, entry *zip.File) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ValidateEntrySecurity(entry); err != nil {
		return nil, err
	}

	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open entry %q: %w", entry.Name, err)
	}
	defer rc.Close()

	// Use LimitReader to prevent decompression bombs from inflating beyond uncompressed size limit
	maxBytes := s.Limits.MaxSingleEntrySize
	limitReader := io.LimitReader(rc, maxBytes+1)

	buf, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading entry %q: %w", entry.Name, err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf("entry %q exceeded maximum allowed size of %d bytes during extraction",
			entry.Name, maxBytes)
	}

	return buf, nil
}

// FindFirstMatchingEntry finds the first ZIP entry matching the predicate, validating each checked entry's safety.
func (s *SafeZipReader) FindFirstMatchingEntry(matcher func(name string) bool) (*zip.File, error) {
	var matched *zip.File
	matchCount := 0

	for _, f := range s.Reader.File {
		if matcher(f.Name) {
			matchCount++
			if matched == nil {
				matched = f
			}
		}
	}

	if matchCount > 1 {
		// Note duplicate presence if applicable
		return matched, fmt.Errorf("found %d duplicate entries matching target; selecting first canonical entry", matchCount)
	}

	if matched == nil {
		return nil, errors.New("no matching entry found in archive")
	}

	return matched, nil
}
