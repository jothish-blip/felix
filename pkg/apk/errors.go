package apk

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidInput indicates that the provided input path is inaccessible, missing, empty, or not a regular file.
	ErrInvalidInput = errors.New("invalid input: file is missing, empty, or not a regular file")

	// ErrNotAnAPK indicates that the file is not a valid Android package (e.g. not a ZIP or missing AndroidManifest.xml).
	ErrNotAnAPK = errors.New("input is not an Android APK: missing AndroidManifest.xml or invalid package structure")

	// ErrMalformedArchive indicates that the ZIP archive is corrupt, truncated, or has invalid central directory records.
	ErrMalformedArchive = errors.New("malformed archive: corrupted ZIP header, central directory, or truncated payload")

	// ErrLimitExceeded indicates that the APK or an entry exceeded a configured resource bound (size, entry count, ratio).
	ErrLimitExceeded = errors.New("resource limit exceeded: archive size, entry count, or decompression limit violated")

	// ErrSecurityViolation indicates an unsafe archive construct such as path traversal, symlink, or conflict.
	ErrSecurityViolation = errors.New("security violation: archive contains unsafe paths, symlinks, or conflicting entries")
)

// IntakeError provides detailed, non-sensitive context for intake failures.
type IntakeError struct {
	Op     string
	Reason string
	Err    error
}

func (e *IntakeError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("apk intake [%s]: %s: %v", e.Op, e.Reason, e.Err)
	}
	return fmt.Sprintf("apk intake [%s]: %v", e.Op, e.Err)
}

func (e *IntakeError) Unwrap() error {
	return e.Err
}

// WrapError constructs a structured IntakeError.
func WrapError(op, reason string, err error) error {
	if err == nil {
		return nil
	}
	return &IntakeError{
		Op:     op,
		Reason: reason,
		Err:    err,
	}
}
