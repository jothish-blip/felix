package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

// DebConfig configures a Debian package generation.
type DebConfig struct {
	Package      string
	Version      string
	Architecture string
	Maintainer   string
	Homepage     string
	Section      string
	Priority     string
	Description  string
	LongDesc     string
	BinaryPath   string
	LicensePath  string
	OutputPath   string
}

// BuildDeb constructs a bit-for-bit valid Debian .deb archive.
func BuildDeb(cfg DebConfig) error {
	binData, err := os.ReadFile(cfg.BinaryPath)
	if err != nil {
		return fmt.Errorf("reading binary %s: %w", cfg.BinaryPath, err)
	}

	// Calculate installed size in KB
	installedSizeKB := (len(binData) + 1023) / 1024

	// 1. Build data.tar.gz
	var dataBuf bytes.Buffer
	gwData := gzip.NewWriter(&dataBuf)
	twData := tar.NewWriter(gwData)

	now := time.Now().UTC()

	// Directories
	dirs := []string{
		"usr",
		"usr/bin",
		"usr/share",
		"usr/share/doc",
		"usr/share/doc/" + cfg.Package,
	}
	for _, d := range dirs {
		hdr := &tar.Header{
			Name:     "./" + d + "/",
			Mode:     0755,
			Typeflag: tar.TypeDir,
			ModTime:  now,
			Format:   tar.FormatGNU,
		}
		if err := twData.WriteHeader(hdr); err != nil {
			return err
		}
	}

	// Executable: usr/bin/felix
	binHdr := &tar.Header{
		Name:     "./usr/bin/" + cfg.Package,
		Mode:     0755,
		Size:     int64(len(binData)),
		Typeflag: tar.TypeReg,
		ModTime:  now,
		Format:   tar.FormatGNU,
	}
	if err := twData.WriteHeader(binHdr); err != nil {
		return err
	}
	if _, err := twData.Write(binData); err != nil {
		return err
	}

	// Copyright doc
	copyrightContent := []byte(fmt.Sprintf("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: %s\nSource: %s\n\nFiles: *\nCopyright: 2026 Jothish\nLicense: MIT\n", cfg.Package, cfg.Homepage))
	if cfg.LicensePath != "" {
		if lic, err := os.ReadFile(cfg.LicensePath); err == nil {
			copyrightContent = append(copyrightContent, lic...)
		}
	}
	cpyHdr := &tar.Header{
		Name:     "./usr/share/doc/" + cfg.Package + "/copyright",
		Mode:     0644,
		Size:     int64(len(copyrightContent)),
		Typeflag: tar.TypeReg,
		ModTime:  now,
		Format:   tar.FormatGNU,
	}
	if err := twData.WriteHeader(cpyHdr); err != nil {
		return err
	}
	if _, err := twData.Write(copyrightContent); err != nil {
		return err
	}

	if err := twData.Close(); err != nil {
		return err
	}
	if err := gwData.Close(); err != nil {
		return err
	}
	dataTarGz := dataBuf.Bytes()

	// 2. Build control.tar.gz
	var controlBuf bytes.Buffer
	gwCtrl := gzip.NewWriter(&controlBuf)
	twCtrl := tar.NewWriter(gwCtrl)

	// md5sums
	binMD5 := md5.Sum(binData)
	cpyMD5 := md5.Sum(copyrightContent)
	md5Content := fmt.Sprintf("%x  usr/bin/%s\n%x  usr/share/doc/%s/copyright\n", binMD5, cfg.Package, cpyMD5, cfg.Package)

	// control file
	controlText := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s\nInstalled-Size: %d\nSection: %s\nPriority: %s\nHomepage: %s\nDescription: %s\n%s\n",
		cfg.Package,
		cfg.Version,
		cfg.Architecture,
		cfg.Maintainer,
		installedSizeKB,
		cfg.Section,
		cfg.Priority,
		cfg.Homepage,
		cfg.Description,
		indentDesc(cfg.LongDesc),
	)

	// write control
	ctrlHdr := &tar.Header{
		Name:     "./control",
		Mode:     0644,
		Size:     int64(len(controlText)),
		Typeflag: tar.TypeReg,
		ModTime:  now,
		Format:   tar.FormatGNU,
	}
	if err := twCtrl.WriteHeader(ctrlHdr); err != nil {
		return err
	}
	if _, err := twCtrl.Write([]byte(controlText)); err != nil {
		return err
	}

	// write md5sums
	md5Hdr := &tar.Header{
		Name:     "./md5sums",
		Mode:     0644,
		Size:     int64(len(md5Content)),
		Typeflag: tar.TypeReg,
		ModTime:  now,
		Format:   tar.FormatGNU,
	}
	if err := twCtrl.WriteHeader(md5Hdr); err != nil {
		return err
	}
	if _, err := twCtrl.Write([]byte(md5Content)); err != nil {
		return err
	}

	if err := twCtrl.Close(); err != nil {
		return err
	}
	if err := gwCtrl.Close(); err != nil {
		return err
	}
	ctrlTarGz := controlBuf.Bytes()

	// 3. Assemble .deb (AR archive)
	// AR format: "!<arch>\n" header followed by 60-byte headers and file contents
	outDir := filepath.Dir(cfg.OutputPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	f, err := os.Create(cfg.OutputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// AR magic
	if _, err := f.WriteString("!<arch>\n"); err != nil {
		return err
	}

	// debian-binary member
	debianBinary := []byte("2.0\n")
	if err := writeArMember(f, "debian-binary", debianBinary, now); err != nil {
		return err
	}

	// control.tar.gz member
	if err := writeArMember(f, "control.tar.gz", ctrlTarGz, now); err != nil {
		return err
	}

	// data.tar.gz member
	if err := writeArMember(f, "data.tar.gz", dataTarGz, now); err != nil {
		return err
	}

	return nil
}

func indentDesc(desc string) string {
	lines := strings.Split(desc, "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			out = append(out, " .")
		} else {
			out = append(out, " "+l)
		}
	}
	return strings.Join(out, "\n")
}

func writeArMember(w io.Writer, name string, data []byte, t time.Time) error {
	// AR member header is 60 bytes:
	// 0..15  Filename (16 bytes, ASCII, space padded)
	// 16..27 File modification timestamp (12 bytes, decimal ASCII, space padded)
	// 28..33 Owner ID (6 bytes, decimal ASCII, space padded)
	// 34..39 Group ID (6 bytes, decimal ASCII, space padded)
	// 40..47 File mode (8 bytes, octal ASCII, space padded)
	// 48..57 File size (10 bytes, decimal ASCII, space padded)
	// 58..59 Ending characters (\x60\x0A)
	hdr := make([]byte, 60)
	for i := range hdr {
		hdr[i] = ' '
	}

	copy(hdr[0:16], []byte(name))
	tsStr := strconv.FormatInt(t.Unix(), 10)
	copy(hdr[16:28], []byte(tsStr))
	copy(hdr[28:34], []byte("0"))
	copy(hdr[34:40], []byte("0"))
	copy(hdr[40:48], []byte("100644"))
	sizeStr := strconv.FormatInt(int64(len(data)), 10)
	copy(hdr[48:58], []byte(sizeStr))
	hdr[58] = '`'
	hdr[59] = '\n'

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	// Pad to even byte boundary if length is odd
	if len(data)%2 != 0 {
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

// AptFileHash records hash and size metadata for an APT index entry.
type AptFileHash struct {
	RelPath string
	Size    int64
	MD5     string
	SHA1    string
	SHA256  string
}

// BuildAptRepo generates standard Debian APT repository structures.
func BuildAptRepo(repoDir string, debFiles []string, signer *openpgp.Entity) error {
	distStable := filepath.Join(repoDir, "dists", "stable")
	poolDir := filepath.Join(repoDir, "pool", "main", "f", "felix")
	if err := os.MkdirAll(poolDir, 0755); err != nil {
		return err
	}

	type ArchPackage struct {
		Arch     string
		Packages bytes.Buffer
	}
	archPks := map[string]*ArchPackage{
		"amd64": {Arch: "amd64"},
		"arm64": {Arch: "arm64"},
	}

	for _, debPath := range debFiles {
		data, err := os.ReadFile(debPath)
		if err != nil {
			return err
		}

		baseName := filepath.Base(debPath)
		destDeb := filepath.Join(poolDir, baseName)
		if err := os.WriteFile(destDeb, data, 0644); err != nil {
			return err
		}

		// Determine arch from filename (e.g. felix_2.0.0_amd64.deb)
		arch := "amd64"
		if strings.Contains(baseName, "arm64") {
			arch = "arm64"
		}

		// Calculate hashes
		md5Sum := fmt.Sprintf("%x", md5.Sum(data))
		sha1Sum := fmt.Sprintf("%x", sha1.Sum(data))
		sha256Sum := fmt.Sprintf("%x", sha256.Sum256(data))
		size := len(data)

		// Parse control file from deb
		ctrlText, err := extractControlFromDeb(data)
		if err != nil {
			return fmt.Errorf("parsing control from %s: %w", debPath, err)
		}

		poolRelPath := "pool/main/f/felix/" + baseName
		stanza := fmt.Sprintf("%s\nFilename: %s\nSize: %d\nMD5sum: %s\nSHA1: %s\nSHA256: %s\n\n",
			strings.TrimSpace(ctrlText),
			poolRelPath,
			size,
			md5Sum,
			sha1Sum,
			sha256Sum,
		)
		archPks[arch].Packages.WriteString(stanza)
	}

	var indexFiles []AptFileHash

	for arch, ap := range archPks {
		archDir := filepath.Join(distStable, "main", fmt.Sprintf("binary-%s", arch))
		if err := os.MkdirAll(archDir, 0755); err != nil {
			return err
		}

		pkgBytes := ap.Packages.Bytes()
		pkgPath := filepath.Join(archDir, "Packages")
		if err := os.WriteFile(pkgPath, pkgBytes, 0644); err != nil {
			return err
		}
		indexFiles = append(indexFiles, calcHash("main/binary-"+arch+"/Packages", pkgBytes))

		// Packages.gz
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		if _, err := gw.Write(pkgBytes); err != nil {
			return err
		}
		_ = gw.Close()
		pkgGzBytes := gzBuf.Bytes()
		pkgGzPath := filepath.Join(archDir, "Packages.gz")
		if err := os.WriteFile(pkgGzPath, pkgGzBytes, 0644); err != nil {
			return err
		}
		indexFiles = append(indexFiles, calcHash("main/binary-"+arch+"/Packages.gz", pkgGzBytes))
	}

	// Generate Release file
	nowStr := time.Now().UTC().Format(time.RFC1123)
	var relBuf bytes.Buffer
	relBuf.WriteString(fmt.Sprintf("Origin: Felix\n"))
	relBuf.WriteString(fmt.Sprintf("Label: Felix Security Auditor\n"))
	relBuf.WriteString(fmt.Sprintf("Suite: stable\n"))
	relBuf.WriteString(fmt.Sprintf("Codename: stable\n"))
	relBuf.WriteString(fmt.Sprintf("Version: 2.0.0\n"))
	relBuf.WriteString(fmt.Sprintf("Architectures: amd64 arm64\n"))
	relBuf.WriteString(fmt.Sprintf("Components: main\n"))
	relBuf.WriteString(fmt.Sprintf("Description: Official APT repository for Felix Security Auditor\n"))
	relBuf.WriteString(fmt.Sprintf("Date: %s\n", nowStr))

	relBuf.WriteString("MD5Sum:\n")
	for _, f := range indexFiles {
		relBuf.WriteString(fmt.Sprintf(" %s %d %s\n", f.MD5, f.Size, f.RelPath))
	}
	relBuf.WriteString("SHA1:\n")
	for _, f := range indexFiles {
		relBuf.WriteString(fmt.Sprintf(" %s %d %s\n", f.SHA1, f.Size, f.RelPath))
	}
	relBuf.WriteString("SHA256:\n")
	for _, f := range indexFiles {
		relBuf.WriteString(fmt.Sprintf(" %s %d %s\n", f.SHA256, f.Size, f.RelPath))
	}

	releaseBytes := relBuf.Bytes()
	releasePath := filepath.Join(distStable, "Release")
	if err := os.WriteFile(releasePath, releaseBytes, 0644); err != nil {
		return err
	}

	if signer != nil {
		// Clearsign InRelease
		inReleasePath := filepath.Join(distStable, "InRelease")
		inRelFile, err := os.Create(inReleasePath)
		if err != nil {
			return err
		}
		defer inRelFile.Close()

		clearsignWriter, err := clearsign.Encode(inRelFile, signer.PrivateKey, nil)
		if err != nil {
			return fmt.Errorf("clearsign: %w", err)
		}
		if _, err := clearsignWriter.Write(releaseBytes); err != nil {
			return err
		}
		_ = clearsignWriter.Close()

		// Detached signature Release.gpg
		releaseGpgPath := filepath.Join(distStable, "Release.gpg")
		relGpgFile, err := os.Create(releaseGpgPath)
		if err != nil {
			return err
		}
		defer relGpgFile.Close()

		if err := openpgp.ArmoredDetachSignText(relGpgFile, signer, bytes.NewReader(releaseBytes), nil); err != nil {
			return fmt.Errorf("detach sign: %w", err)
		}

		// Export public key in both binary (.gpg) and armored (.asc) formats
		pubGpgPath := filepath.Join(repoDir, "felix-archive-keyring.gpg")
		pubGpgFile, err := os.Create(pubGpgPath)
		if err != nil {
			return err
		}
		defer pubGpgFile.Close()
		if err := signer.Serialize(pubGpgFile); err != nil {
			return err
		}

		pubAscPath := filepath.Join(repoDir, "felix.gpg")
		pubAscFile, err := os.Create(pubAscPath)
		if err != nil {
			return err
		}
		defer pubAscFile.Close()
		armWriter, err := armor.Encode(pubAscFile, openpgp.PublicKeyType, nil)
		if err != nil {
			return err
		}
		if err := signer.Serialize(armWriter); err != nil {
			return err
		}
		_ = armWriter.Close()
	}

	return nil
}

func calcHash(rel string, data []byte) AptFileHash {
	return AptFileHash{
		RelPath: rel,
		Size:    int64(len(data)),
		MD5:     fmt.Sprintf("%x", md5.Sum(data)),
		SHA1:    fmt.Sprintf("%x", sha1.Sum(data)),
		SHA256:  fmt.Sprintf("%x", sha256.Sum256(data)),
	}
}

func extractControlFromDeb(debData []byte) (string, error) {
	// Simple reader for AR archive containing control.tar.gz
	r := bytes.NewReader(debData)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil {
		return "", err
	}
	if string(magic) != "!<arch>\n" {
		return "", fmt.Errorf("invalid ar magic")
	}

	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		name := strings.TrimSpace(string(hdr[0:16]))
		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return "", err
		}

		memberData := make([]byte, size)
		if _, err := io.ReadFull(r, memberData); err != nil {
			return "", err
		}
		if size%2 != 0 {
			_, _ = r.ReadByte() // skip padding
		}

		if name == "control.tar.gz" {
			gzr, err := gzip.NewReader(bytes.NewReader(memberData))
			if err != nil {
				return "", err
			}
			defer gzr.Close()

			tr := tar.NewReader(gzr)
			for {
				th, err := tr.Next()
				if err != nil {
					if err == io.EOF {
						break
					}
					return "", err
				}
				if th.Name == "./control" || th.Name == "control" {
					ctrlBytes, err := io.ReadAll(tr)
					if err != nil {
						return "", err
					}
					return string(ctrlBytes), nil
				}
			}
		}
	}
	return "", fmt.Errorf("control file not found in deb")
}

// GenerateGpgSigner creates or loads an OpenPGP entity for repository signing.
func GenerateGpgSigner(name, comment, email string) (*openpgp.Entity, error) {
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
	}
	return openpgp.NewEntity(name, comment, email, cfg)
}
