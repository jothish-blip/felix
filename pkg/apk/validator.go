package apk

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	// zipMagicLocalHeader is the standard 4-byte signature for a ZIP local file header ("PK\x03\x04").
	zipMagicLocalHeader = []byte{0x50, 0x4B, 0x03, 0x04}

	// zipMagicEmptyArchive is the 4-byte signature for an empty ZIP end of central directory ("PK\x05\x06").
	zipMagicEmptyArchive = []byte{0x50, 0x4B, 0x05, 0x06}
)

// ValidateFileBasics inspects the filesystem properties of the input APK path.
// It ensures the target exists, is a regular file (not directory or device), is non-empty,
// and does not exceed the maximum configured compressed file size.
func ValidateFileBasics(inputPath string, maxCompressedSize int64) (os.FileInfo, *os.File, error) {
	if strings.TrimSpace(inputPath) == "" {
		return nil, nil, fmt.Errorf("%w: empty input path provided", ErrInvalidInput)
	}

	// Use os.Lstat first to detect symlinks and special files
	fi, err := os.Lstat(inputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%w: target file does not exist: %s", ErrInvalidInput, inputPath)
		}
		if os.IsPermission(err) {
			return nil, nil, fmt.Errorf("%w: permission denied accessing target file: %s", ErrInvalidInput, inputPath)
		}
		return nil, nil, fmt.Errorf("%w: failed to inspect input path: %v", ErrInvalidInput, err)
	}

	// If it is a symlink, evaluate the target safely
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(inputPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: failed to resolve symlink %q: %v", ErrInvalidInput, inputPath, err)
		}
		fi, err = os.Stat(resolved)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: symlink target is inaccessible: %v", ErrInvalidInput, err)
		}
	}

	// Enforce regular file requirement (reject directories, devices, sockets, FIFOs)
	if fi.IsDir() {
		return nil, nil, fmt.Errorf("%w: input path %q is a directory, not an APK file", ErrInvalidInput, inputPath)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: input path %q is not a regular file (mode: %s)", ErrInvalidInput, inputPath, fi.Mode().String())
	}

	// Reject empty file
	if fi.Size() == 0 {
		return nil, nil, fmt.Errorf("%w: input file %q is 0 bytes (empty file)", ErrInvalidInput, inputPath)
	}

	// Enforce compressed size limit before any decompression or deep archive inspection
	if fi.Size() > maxCompressedSize {
		return nil, nil, fmt.Errorf("%w: input file size (%d bytes) exceeds maximum compressed limit (%d bytes)",
			ErrLimitExceeded, fi.Size(), maxCompressedSize)
	}

	// Open read-only
	f, err := os.OpenFile(inputPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to open target file for reading: %v", ErrInvalidInput, err)
	}

	return fi, f, nil
}

// ValidateZIPMagic inspects the initial bytes of the file to verify valid ZIP archive magic.
func ValidateZIPMagic(r io.ReaderAt, size int64) error {
	if size < 4 {
		return fmt.Errorf("%w: file size too small for ZIP archive (%d bytes)", ErrMalformedArchive, size)
	}

	header := make([]byte, 4)
	if _, err := r.ReadAt(header, 0); err != nil {
		return fmt.Errorf("%w: failed reading archive signature: %v", ErrMalformedArchive, err)
	}

	// Standard APK / ZIP archives begin with PK\x03\x04
	if bytes.Equal(header, zipMagicLocalHeader) {
		return nil
	}

	// Empty ZIP archives begin with PK\x05\x06
	if bytes.Equal(header, zipMagicEmptyArchive) {
		return fmt.Errorf("%w: archive contains no files (empty ZIP)", ErrNotAnAPK)
	}

	return fmt.Errorf("%w: invalid archive magic signature 0x%X (expected ZIP 'PK\\x03\\x04')", ErrNotAnAPK, header)
}

// SanitizeArchiveEntry validates and canonicalizes an archive entry name.
// It strictly prevents path traversal, absolute paths, backslashes, drive letters, UNC shares,
// null bytes, and excessive path lengths or depths.
func SanitizeArchiveEntry(name string, limits Limits) (string, error) {
	if len(name) > limits.MaxPathLength {
		return "", fmt.Errorf("%w: entry path length (%d) exceeds limit (%d)",
			ErrLimitExceeded, len(name), limits.MaxPathLength)
	}

	if len(name) == 0 {
		return "", fmt.Errorf("%w: archive contains empty entry name", ErrSecurityViolation)
	}

	// Reject null bytes
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: entry name contains prohibited null byte: %q", ErrSecurityViolation, name)
	}

	// Reject backslashes outright to prevent cross-platform directory separator confusion and path bypasses
	if strings.Contains(name, "\\") {
		return "", fmt.Errorf("%w: entry name contains backslash separator %q (ZIP standard requires '/')",
			ErrSecurityViolation, name)
	}

	// Reject absolute paths
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: absolute path in archive entry: %q", ErrSecurityViolation, name)
	}

	// Reject UNC network shares
	if strings.HasPrefix(name, "//") {
		return "", fmt.Errorf("%w: UNC network path in archive entry: %q", ErrSecurityViolation, name)
	}

	// Reject Windows volume/drive specifications (e.g. C:, D:)
	if filepath.VolumeName(name) != "" || (len(name) >= 2 && name[1] == ':') {
		return "", fmt.Errorf("%w: drive letter specification in archive entry: %q", ErrSecurityViolation, name)
	}

	// Canonicalize using POSIX path Clean (ZIP paths are forward-slash delimited)
	clean := path.Clean(name)

	// Reject traversal indicators
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || strings.HasSuffix(clean, "/..") {
		return "", fmt.Errorf("%w: path traversal detected in archive entry: %q", ErrSecurityViolation, name)
	}

	if clean == "." || clean == "/" || clean == "" {
		return "", fmt.Errorf("%w: entry name resolves to root or empty: %q", ErrSecurityViolation, name)
	}

	// Enforce directory nesting depth limit
	segments := strings.Split(clean, "/")
	depth := 0
	for _, s := range segments {
		if s != "" && s != "." {
			depth++
		}
	}
	if depth > limits.MaxPathDepth {
		return "", fmt.Errorf("%w: entry nesting depth (%d) exceeds limit (%d): %q",
			ErrLimitExceeded, depth, limits.MaxPathDepth, clean)
	}

	return clean, nil
}

// VerifyExtractionTarget ensures that the resolved filesystem destination path is strictly
// inside the designated workspace directory and cannot overwrite parent or unrelated files.
func VerifyExtractionTarget(workspaceDir, relPath string) (string, error) {
	cleanWorkspace := filepath.Clean(workspaceDir)
	target := filepath.Join(cleanWorkspace, filepath.FromSlash(relPath))
	cleanTarget := filepath.Clean(target)

	expectedPrefix := cleanWorkspace + string(filepath.Separator)
	if cleanTarget != cleanWorkspace && !strings.HasPrefix(cleanTarget, expectedPrefix) {
		return "", fmt.Errorf("%w: entry path %q escapes workspace directory %q",
			ErrSecurityViolation, relPath, workspaceDir)
	}

	return cleanTarget, nil
}
