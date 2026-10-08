package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractArchive extracts a .zip or .tar.gz archive into destDir with strict ZipSlip protection.
func ExtractArchive(archivePath, destDir string) error {
	destDir = filepath.Clean(destDir)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	lower := strings.ToLower(archivePath)
	if strings.HasSuffix(lower, ".zip") {
		return extractZip(archivePath, destDir)
	} else if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return extractTarGz(archivePath, destDir)
	}

	return fmt.Errorf("unsupported archive format: %s (supported: .zip, .tar.gz)", archivePath)
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		targetPath, err := sanitizeExtractPath(destDir, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to read entry %s: %w", f.Name, err)
		}

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create file %s: %w", targetPath, err)
		}

		_, copyErr := io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if copyErr != nil {
			return fmt.Errorf("failed writing entry %s: %w", f.Name, copyErr)
		}
	}

	return nil
}

func extractTarGz(tarGzPath, destDir string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return fmt.Errorf("failed to open tar.gz archive: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed reading tar entry: %w", err)
		}

		targetPath, err := sanitizeExtractPath(destDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed writing file %s: %w", targetPath, err)
			}
			outFile.Close()
		default:
			// Ignore unsupported entry types (symlinks, special devices) for security
			continue
		}
	}

	return nil
}

// sanitizeExtractPath validates that an entry name does not escape destDir (ZipSlip mitigation).
func sanitizeExtractPath(destDir, entryName string) (string, error) {
	if strings.HasPrefix(entryName, "/") || strings.HasPrefix(entryName, "\\") || filepath.IsAbs(entryName) || filepath.VolumeName(entryName) != "" {
		return "", fmt.Errorf("security violation: absolute or drive-relative path detected in archive entry %q", entryName)
	}

	cleanName := filepath.Clean(entryName)
	if strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("security violation: path traversal detected in archive entry %q", entryName)
	}

	target := filepath.Join(destDir, cleanName)
	target = filepath.Clean(target)

	expectedPrefix := destDir + string(filepath.Separator)
	if target != destDir && !strings.HasPrefix(target, expectedPrefix) {
		return "", fmt.Errorf("security violation: archive entry %q resolves outside destination %q", entryName, destDir)
	}

	return target, nil
}

// LocateExecutable searches destDir for the platform executable.
func LocateExecutable(destDir, goos string) (string, error) {
	expectedName := ExecutableName(goos)
	direct := filepath.Join(destDir, expectedName)
	if fi, err := os.Stat(direct); err == nil && !fi.IsDir() {
		return direct, nil
	}

	var found string
	err := filepath.Walk(destDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.EqualFold(info.Name(), expectedName) {
			found = path
			return io.EOF
		}
		return nil
	})

	if err == io.EOF && found != "" {
		return found, nil
	}
	if err != nil && err != io.EOF {
		return "", err
	}

	return "", fmt.Errorf("executable %q not found in extracted archive", expectedName)
}
