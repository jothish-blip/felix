package apk

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// IntakeOptions parameterizes the intake and validation pipeline.
type IntakeOptions struct {
	// Limits specifies the resource boundaries. If empty or zero-value, DefaultLimits() is used.
	Limits Limits

	// TempDir specifies the parent directory for temporary workspaces. If empty, os.TempDir() is used.
	TempDir string

	// Extract indicates whether all safe archive entries should be extracted to disk.
	// When false, the archive is verified structurally, resource limits are enforced against
	// observed decompression streams, and only AndroidManifest.xml is staged in the workspace.
	Extract bool
}

// IntakeResult encapsulates the verified metadata and workspace handle resulting from successful intake.
type IntakeResult struct {
	// Workspace is the handle to the isolated temporary directory containing staged artifacts.
	Workspace *Workspace

	// SHA256 is the verified hexadecimal checksum of the input APK.
	SHA256 string

	// FileSize is the size of the APK file in bytes.
	FileSize int64

	// EntryCount is the number of valid archive entries.
	EntryCount int

	// TotalDecompressedBytes is the total observed uncompressed size of all entries.
	TotalDecompressedBytes int64

	// ManifestPresent confirms AndroidManifest.xml was present in the archive root.
	ManifestPresent bool

	// DexCount is the number of Dalvik Executable (.dex) files discovered in the package.
	DexCount int

	// DexFiles lists the relative paths of discovered .dex files.
	DexFiles []string
}

// Intake accepts, validates, and isolates an Android APK file.
// The operation is strictly static and offline: the APK is never executed, installed,
// dynamically instrumented, or evaluated against remote network endpoints.
func Intake(ctx context.Context, apkPath string, opts IntakeOptions) (*IntakeResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, WrapError("intake", "context cancelled before intake started", err)
	}

	// 1. Establish and validate resource limits
	limits := opts.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.Validate(); err != nil {
		return nil, WrapError("intake", "invalid limits configuration", err)
	}

	// 2. Inspect filesystem properties of target
	fi, f, err := ValidateFileBasics(apkPath, limits.MaxCompressedSize)
	if err != nil {
		return nil, WrapError("validate_file", "", err)
	}
	defer f.Close()

	// 3. Compute cryptographic SHA-256 digest streaming the input
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, WrapError("hash", "failed to compute SHA-256 digest of input", err)
	}
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer to beginning for archive parsing
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, WrapError("seek", "failed to rewind input file", err)
	}

	// 4. Validate ZIP magic signature
	if err := ValidateZIPMagic(f, fi.Size()); err != nil {
		return nil, WrapError("validate_magic", "", err)
	}

	// 5. Open ZIP Reader
	zipReader, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return nil, WrapError("zip_open", "corrupt or truncated ZIP archive structure", ErrMalformedArchive)
	}

	// 6. Validate entry count limits
	entryCount := len(zipReader.File)
	if entryCount == 0 {
		return nil, WrapError("zip_entries", "archive contains zero entries", ErrNotAnAPK)
	}
	if entryCount > limits.MaxArchiveEntries {
		return nil, WrapError("zip_entries",
			fmt.Sprintf("entry count %d exceeds maximum limit of %d", entryCount, limits.MaxArchiveEntries),
			ErrLimitExceeded)
	}

	// 7. Initialize secure isolated workspace
	ws, err := NewWorkspace(opts.TempDir)
	if err != nil {
		return nil, WrapError("workspace", "failed to initialize isolated workspace", err)
	}

	// Clean up workspace on any failure path
	var success bool
	defer func() {
		if !success && ws != nil {
			_ = ws.Close()
		}
	}()

	ws.APKPath = apkPath
	ws.SHA256 = sha256Hex
	ws.FileSize = fi.Size()
	ws.EntryCount = entryCount

	// 8. Process and validate all archive entries
	var (
		seenPaths                   = make(map[string]bool, entryCount)
		seenDirs                    = make(map[string]bool)
		hasManifest                 bool
		dexFiles                    []string
		cumulativeDecompressedBytes int64
	)

	// Single reusable buffer for discard reading (32 KiB)
	discardBuf := make([]byte, 32*1024)

	for _, entry := range zipReader.File {
		if err := ctx.Err(); err != nil {
			return nil, WrapError("entry_loop", "operation cancelled during entry processing", err)
		}

		// Reject symlinks, FIFOs, sockets, device files
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0 || mode&os.ModeDevice != 0 {
			return nil, WrapError("entry_mode",
				fmt.Sprintf("entry %q declares unsupported special file mode (%s)", entry.Name, mode.String()),
				ErrSecurityViolation)
		}

		// Sanitize path and prevent path traversal / ZipSlip
		cleanPath, err := SanitizeArchiveEntry(entry.Name, limits)
		if err != nil {
			return nil, WrapError("sanitize_path", "", err)
		}

		// Detect duplicate archive entries
		if seenPaths[cleanPath] {
			return nil, WrapError("duplicate_entry",
				fmt.Sprintf("duplicate archive entry path detected: %q", cleanPath),
				ErrSecurityViolation)
		}
		seenPaths[cleanPath] = true

		// Directory entry handling
		if entry.FileInfo().IsDir() {
			seenDirs[cleanPath] = true
			if opts.Extract {
				targetDir, err := VerifyExtractionTarget(ws.Dir, cleanPath)
				if err != nil {
					return nil, WrapError("verify_target", "", err)
				}
				if err := os.MkdirAll(targetDir, 0700); err != nil {
					return nil, WrapError("mkdir", fmt.Sprintf("failed to create directory %q: %v", targetDir, err), err)
				}
			}
			continue
		}

		// Check parent directory conflict: a file path cannot be an ancestor of another file
		parentDir := filepath.ToSlash(filepath.Dir(cleanPath))
		if seenPaths[parentDir] && !seenDirs[parentDir] {
			return nil, WrapError("path_conflict",
				fmt.Sprintf("entry %q conflicts with existing file at %q", cleanPath, parentDir),
				ErrSecurityViolation)
		}
		if parentDir != "." && parentDir != "" {
			seenDirs[parentDir] = true
		}

		// Check structural APK requirements
		if cleanPath == "AndroidManifest.xml" {
			hasManifest = true
		}
		if strings.HasSuffix(cleanPath, ".dex") {
			dexFiles = append(dexFiles, cleanPath)
		}

		// Bound declared uncompressed size
		if entry.UncompressedSize64 > uint64(limits.MaxEntrySize) {
			return nil, WrapError("entry_size",
				fmt.Sprintf("entry %q declared uncompressed size (%d) exceeds limit (%d)",
					cleanPath, entry.UncompressedSize64, limits.MaxEntrySize),
				ErrLimitExceeded)
		}

		// Check cumulative decompressed bytes projection using declared size
		if err := CheckCumulativeGrowth(cumulativeDecompressedBytes, int64(entry.UncompressedSize64), limits.MaxCumulativeDecompressedSize); err != nil {
			return nil, WrapError("cumulative_size",
				fmt.Sprintf("entry %q declared size would exceed cumulative limit", cleanPath),
				err)
		}

		// Determine if this entry must be written to workspace disk
		shouldWriteFile := opts.Extract || cleanPath == "AndroidManifest.xml"

		// Stream and verify actual decompressed bytes
		entryReader, err := entry.Open()
		if err != nil {
			return nil, WrapError("entry_open",
				fmt.Sprintf("failed to open decompression stream for entry %q: %v", cleanPath, err),
				ErrMalformedArchive)
		}

		// Wrap stream with LimitReader bounded to MaxEntrySize + 1 to detect expansion anomalies
		boundedReader := io.LimitReader(entryReader, limits.MaxEntrySize+1)

		var bytesRead int64
		if shouldWriteFile {
			targetPath, err := VerifyExtractionTarget(ws.Dir, cleanPath)
			if err != nil {
				entryReader.Close()
				return nil, WrapError("verify_target", "", err)
			}

			// Ensure parent directory exists with restrictive permissions
			if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
				entryReader.Close()
				return nil, WrapError("mkdir_parent", fmt.Sprintf("failed to create directory for %q: %v", targetPath, err), err)
			}

			// Write file with exclusive creation (O_EXCL) to prevent overwrite attacks
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
			if err != nil {
				entryReader.Close()
				return nil, WrapError("create_file", fmt.Sprintf("failed to create file %q: %v", targetPath, err), err)
			}

			bytesRead, err = io.Copy(outFile, boundedReader)
			outFile.Close()
			if err != nil {
				entryReader.Close()
				return nil, WrapError("write_file", fmt.Sprintf("failed writing entry %q: %v", cleanPath, err), err)
			}
		} else {
			// Discard read to verify decompression integrity, count actual bytes, and detect bombs
			for {
				n, err := boundedReader.Read(discardBuf)
				bytesRead += int64(n)
				if err != nil {
					if err == io.EOF {
						break
					}
					entryReader.Close()
					return nil, WrapError("read_stream", fmt.Sprintf("decompression error in entry %q: %v", cleanPath, err), ErrMalformedArchive)
				}
			}
		}
		entryReader.Close()

		// Verify that decompressed bytes did not exceed the single entry limit
		if bytesRead > limits.MaxEntrySize {
			return nil, WrapError("entry_expansion",
				fmt.Sprintf("entry %q decompressed bytes (%d) exceeded limit (%d)", cleanPath, bytesRead, limits.MaxEntrySize),
				ErrLimitExceeded)
		}

		// Update actual cumulative decompressed bytes
		if err := CheckCumulativeGrowth(cumulativeDecompressedBytes, bytesRead, limits.MaxCumulativeDecompressedSize); err != nil {
			return nil, WrapError("cumulative_expansion", "", err)
		}
		cumulativeDecompressedBytes += bytesRead

		// Verify compression ratio against actual decompressed bytes
		if err := CheckCompressionRatio(bytesRead, int64(entry.CompressedSize64), limits.MaxCompressionRatio); err != nil {
			return nil, WrapError("compression_ratio", fmt.Sprintf("entry %q: %v", cleanPath, err), err)
		}
	}

	// 9. Mandatory APK structural verification: AndroidManifest.xml must exist in root
	if !hasManifest {
		return nil, WrapError("verify_apk",
			"archive does not contain root AndroidManifest.xml (input is a generic ZIP, not an Android application package)",
			ErrNotAnAPK)
	}

	// 10. Finalize workspace state
	ws.DecompressedBytes = cumulativeDecompressedBytes
	ws.ManifestPath = "AndroidManifest.xml"
	ws.DexFiles = dexFiles

	success = true

	return &IntakeResult{
		Workspace:              ws,
		SHA256:                 sha256Hex,
		FileSize:               fi.Size(),
		EntryCount:             entryCount,
		TotalDecompressedBytes: cumulativeDecompressedBytes,
		ManifestPresent:        true,
		DexCount:               len(dexFiles),
		DexFiles:               dexFiles,
	}, nil
}
