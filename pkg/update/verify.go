package update

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const MinExecutableBytes = 1 * 1024 * 1024 // 1 MB minimum valid binary size

// VerifyBinary checks file existence, size, magic bytes, and runs a diagnostic version probe.
func VerifyBinary(ctx context.Context, binPath, expectedVersion, goos string) error {
	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("binary not found at %s: %w", binPath, err)
	}

	if info.Size() < MinExecutableBytes {
		return fmt.Errorf("binary size (%d bytes) is below minimum threshold (%d bytes)", info.Size(), MinExecutableBytes)
	}

	// Verify magic bytes header
	if err := checkMagicBytes(binPath, goos); err != nil {
		return err
	}

	// Make executable on POSIX systems before executing
	if goos != "windows" {
		if err := os.Chmod(binPath, 0755); err != nil {
			return fmt.Errorf("failed setting executable permissions: %w", err)
		}
	}

	// Run binary with "version" flag/command in isolated sub-process
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, binPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("executable failed execution test (%w): %s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Felix") {
		return fmt.Errorf("binary execution test did not return Felix header: %s", outStr)
	}

	if expectedVersion != "" {
		cleanExp := CleanVersion(expectedVersion)
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
			return fmt.Errorf("invalid Linux executable: missing ELF magic header (got %02X %02X %02X %02X)", header[0], header[1], header[2], header[3])
		}
	case "darwin":
		// Mach-O 64-bit: 0xCF, 0xFA, 0xED, 0xFE (MH_MAGIC_64) or 0xFE, 0xED, 0xFA, 0xCF (MH_CIGAM_64)
		isMachO := (header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
			(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && header[3] == 0xCF)
		if !isMachO {
			return fmt.Errorf("invalid macOS executable: missing Mach-O magic header")
		}
	}

	return nil
}
