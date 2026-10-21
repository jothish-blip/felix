package ci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const minExecutableBytes = 1024 * 1024 // 1 MB minimum valid executable size

// VerifyBinary inspects a candidate FELIX binary for file validity, magic headers,
// SHA256 integrity (if expected hash provided), and runs an isolated version probe.
func VerifyBinary(binPath, expectedVersion, expectedSHA256 string) error {
	return VerifyBinaryWithIntegrity(binPath, expectedVersion, expectedSHA256, false)
}

// VerifyBinaryWithIntegrity inspects a candidate FELIX binary.
//
// Trust Model Policy:
// - Downloaded or remote binaries MUST always be cryptographically verified against an independently
//   pinned 64-hex SHA-256 digest (requireSHA256=true), failing closed before execution.
// - Deliberately local, user-controlled binaries (e.g. built in the same runner from checked-out
//   workspace source) may omit checksum verification (requireSHA256=false), relying on local compiler
//   provenance and runtime format validation. If a checksum is supplied for a local binary, it is
//   strictly enforced before execution.
// - In all cases, missing required digests, malformed digests, or mismatched hashes fail closed
//   with an operational error before the executable is ever invoked.
func VerifyBinaryWithIntegrity(binPath, expectedVersion, expectedSHA256 string, requireSHA256 bool) error {
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		return fmt.Errorf("binary path cannot be empty")
	}

	cleanExpected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if requireSHA256 && cleanExpected == "" {
		return fmt.Errorf("cryptographic integrity verification required: expected SHA256 checksum must be provided from an independently pinned source")
	}

	if cleanExpected != "" {
		if len(cleanExpected) != 64 {
			return fmt.Errorf("malformed expected SHA256 checksum: must be exactly 64 hexadecimal characters, got %d", len(cleanExpected))
		}
		if _, err := hex.DecodeString(cleanExpected); err != nil {
			return fmt.Errorf("malformed expected SHA256 checksum: contains non-hexadecimal characters: %w", err)
		}
	}

	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("felix executable not found at %q: %w", binPath, err)
	}

	if info.IsDir() {
		return fmt.Errorf("specified binary path %q is a directory, not an executable", binPath)
	}

	// 1. Cryptographic integrity verification (must precede format checks and execution)
	if cleanExpected != "" {
		computedHash, err := computeSHA256(binPath)
		if err != nil {
			return fmt.Errorf("failed computing binary SHA256: %w", err)
		}
		if strings.ToLower(computedHash) != cleanExpected {
			return fmt.Errorf("SHA256 integrity verification failed: expected %s, calculated %s", cleanExpected, computedHash)
		}
	}

	// 2. Minimum size threshold check
	if info.Size() < minExecutableBytes {
		return fmt.Errorf("binary size (%d bytes) is below minimum valid threshold (%d bytes)", info.Size(), minExecutableBytes)
	}

	// 3. Verify magic bytes header according to current OS (executable format check)
	if err := checkMagicBytes(binPath, runtime.GOOS); err != nil {
		return fmt.Errorf("binary executable format validation failed: %w", err)
	}

	// Make executable on POSIX systems before executing
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binPath, 0755); err != nil {
			return fmt.Errorf("failed setting executable permissions on %q: %w", binPath, err)
		}
	}

	// Execute diagnostic version probe in isolated subprocess
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("binary execution test failed (%w): %s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "FELIX") && !strings.Contains(outStr, "Felix") {
		return fmt.Errorf("binary version probe did not return valid Felix banner/header: %s", outStr)
	}

	if strings.TrimSpace(expectedVersion) != "" {
		cleanExp := strings.TrimPrefix(strings.TrimSpace(expectedVersion), "v")
		if !strings.Contains(outStr, cleanExp) {
			return fmt.Errorf("binary reported unexpected version: expected %s, got output:\n%s", cleanExp, outStr)
		}
	}

	return nil
}

func checkMagicBytes(path, goos string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, 4)
	n, err := f.Read(header)
	if err != nil || n < 4 {
		return fmt.Errorf("unable to read executable magic header: %w", err)
	}

	switch goos {
	case "windows":
		// PE MZ header: 0x4D, 0x5A
		if header[0] != 0x4D || header[1] != 0x5A {
			return fmt.Errorf("invalid Windows executable: missing PE MZ magic header (got %02X %02X)", header[0], header[1])
		}
	case "linux":
		// ELF header: 0x7F, 'E', 'L', 'F'
		if !bytes.Equal(header, []byte{0x7F, 'E', 'L', 'F'}) {
			return fmt.Errorf("invalid Linux executable: missing ELF magic header")
		}
	case "darwin":
		// Mach-O: 0xCF, 0xFA, 0xED, 0xFE or 0xFE, 0xED, 0xFA, 0xCF
		isMachO := (header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
			(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && header[3] == 0xCF)
		if !isMachO {
			return fmt.Errorf("invalid macOS executable: missing Mach-O magic header")
		}
	}

	return nil
}

func computeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
