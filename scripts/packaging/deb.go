package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

	now := time.Now().UTC()

	// Copyright doc
	copyrightContent := []byte(fmt.Sprintf("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: %s\nSource: %s\n\nFiles: *\nCopyright: 2026 Jothish\nLicense: MIT\n", cfg.Package, cfg.Homepage))
	if cfg.LicensePath != "" {
		if lic, err := os.ReadFile(cfg.LicensePath); err == nil {
			copyrightContent = append(copyrightContent, lic...)
		}
	}

	changelogRaw, changelogGz, err := generateChangelog(cfg.Package, cfg.Version, cfg.Maintainer)
	if err != nil {
		return fmt.Errorf("generating changelog: %w", err)
	}

	manRaw, manGz, err := generateMan1(cfg.Package, cfg.Version)
	if err != nil {
		return fmt.Errorf("generating man page: %w", err)
	}

	bashComp := generateBashCompletion(cfg.Package)
	zshComp := generateZshCompletion(cfg.Package)
	fishComp := generateFishCompletion(cfg.Package)

	// Maintainer scripts
	postinstContent := generatePostinst(cfg.Package)
	prermContent := generatePrerm()
	postrmContent := generatePostrm(cfg.Package)

	// Calculate installed size in KB (uncompressed sizes of all packaged files)
	totalInstalledBytes := len(binData) + len(copyrightContent) + len(changelogRaw) + len(manRaw) + len(bashComp) + len(zshComp) + len(fishComp)
	installedSizeKB := (totalInstalledBytes + 1023) / 1024

	// 1. Build data.tar.gz
	var dataBuf bytes.Buffer
	gwData := gzip.NewWriter(&dataBuf)
	twData := tar.NewWriter(gwData)

	// Standard Debian hierarchy directories
	dirs := []string{
		"usr",
		"usr/bin",
		"usr/share",
		"usr/share/doc",
		"usr/share/doc/" + cfg.Package,
		"usr/share/man",
		"usr/share/man/man1",
		"usr/share/bash-completion",
		"usr/share/bash-completion/completions",
		"usr/share/zsh",
		"usr/share/zsh/vendor-completions",
		"usr/share/fish",
		"usr/share/fish/vendor_completions.d",
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

	type dataFileEntry struct {
		relPath string
		mode    int64
		data    []byte
	}

	dataFiles := []dataFileEntry{
		{relPath: "usr/bin/" + cfg.Package, mode: 0755, data: binData},
		{relPath: "usr/share/doc/" + cfg.Package + "/copyright", mode: 0644, data: copyrightContent},
		{relPath: "usr/share/doc/" + cfg.Package + "/changelog.Debian.gz", mode: 0644, data: changelogGz},
		{relPath: "usr/share/man/man1/" + cfg.Package + ".1.gz", mode: 0644, data: manGz},
		{relPath: "usr/share/bash-completion/completions/" + cfg.Package, mode: 0644, data: bashComp},
		{relPath: "usr/share/zsh/vendor-completions/_" + cfg.Package, mode: 0644, data: zshComp},
		{relPath: "usr/share/fish/vendor_completions.d/" + cfg.Package + ".fish", mode: 0644, data: fishComp},
	}

	var md5Lines []string
	for _, df := range dataFiles {
		hdr := &tar.Header{
			Name:     "./" + df.relPath,
			Mode:     df.mode,
			Size:     int64(len(df.data)),
			Typeflag: tar.TypeReg,
			ModTime:  now,
			Format:   tar.FormatGNU,
		}
		if err := twData.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := twData.Write(df.data); err != nil {
			return err
		}
		dfMD5 := md5.Sum(df.data)
		md5Lines = append(md5Lines, fmt.Sprintf("%x  %s", dfMD5, df.relPath))
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
	if err := writeTarReg(twCtrl, "./control", 0644, []byte(controlText), now); err != nil {
		return err
	}

	// write md5sums
	md5Content := strings.Join(md5Lines, "\n") + "\n"
	if err := writeTarReg(twCtrl, "./md5sums", 0644, []byte(md5Content), now); err != nil {
		return err
	}

	// write maintainer scripts
	if err := writeTarReg(twCtrl, "./postinst", 0755, postinstContent, now); err != nil {
		return err
	}
	if err := writeTarReg(twCtrl, "./prerm", 0755, prermContent, now); err != nil {
		return err
	}
	if err := writeTarReg(twCtrl, "./postrm", 0755, postrmContent, now); err != nil {
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

func writeTarReg(tw *tar.Writer, name string, mode int64, data []byte, t time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		ModTime:  t,
		Format:   tar.FormatGNU,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func generateChangelog(pkg, version, maintainer string) ([]byte, []byte, error) {
	raw := fmt.Sprintf("%s (%s-1) stable; urgency=medium\n\n  * %s release v%s for Debian and Kali Linux.\n  * Shell completions for Bash, Zsh, and Fish.\n  * Standard section 1 manual page.\n  * Preserves user assessment history and databases during package removal.\n\n -- %s  Mon, 12 Oct 2026 12:00:00 +0000\n",
		pkg, version, pkg, version, maintainer)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(raw)); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}
	return []byte(raw), buf.Bytes(), nil
}

func generateMan1(pkg, version string) ([]byte, []byte, error) {
	man := fmt.Sprintf(`.TH %s 1 "October 2026" "%s %s" "User Commands"
.SH NAME
%s \- deterministic, evidence-first web security auditing platform
.SH SYNOPSIS
.B %s
[\fIcommand\fR] [\fIarguments\fR]
.br
.B %s scan
\fITARGET\fR [\fIoptions\fR]
.br
.B %s assessment
\fIaction\fR [\fIoptions\fR]
.br
.B %s doctor
[\fIoptions\fR]
.SH DESCRIPTION
.B %s
is a deterministic, evidence-backed web security auditing platform written in Go.
It evaluates web applications, APIs, cloud backends, and JavaScript assets
using non-destructive safety boundaries and verifiable proof of exposure.
.SH COMMANDS
.TP
.B scan \fITARGET\fR
Audit target web applications for security exposures, secrets, and API endpoints.
.TP
.B report \fIFILE\fR
Generate assessment reports from existing scan results with zero network calls.
.TP
.B assessment \fIaction\fR
Manage authorized client assessments, scopes, findings, and attack paths.
.TP
.B client \fIaction\fR
Manage client organizations and authorization records.
.TP
.B doctor
Diagnose local runtime health, network stack, and permissions.
.TP
.B version
Display Felix version, git commit, and build environment.
.TP
.B update
Check for or install verified updates from official release channels.
.TP
.B completion \fISHELL\fR
Generate shell autocompletion script (bash, zsh, fish, powershell).
.SH OPTIONS
.TP
.BR \-t ", " \-\-timeout " \fIDURATION\fR"
Per-request network timeout (default: 10s).
.TP
.BR \-c ", " \-\-concurrency " \fICOUNT\fR"
Worker concurrency limit (default: 10).
.TP
.BR \-\-scope " \fIMODE\fR"
Crawl scope mode: same-origin (default), subdomains, or explicit.
.TP
.BR \-\-export " \fIPATH\fR"
Export assessment report to HTML, JSON, or SARIF file.
.TP
.BR \-\-json " [\fIPATH\fR]"
Export machine-readable JSON assessment results.
.TP
.BR \-q ", " \-\-quiet
Suppress terminal output and banners.
.TP
.BR \-v ", " \-\-verbose
Display detailed diagnostic and crawling messages.
.SH EXIT STATUS
.TP
.B 0
Clean execution, no high-risk findings, or successful informational command.
.TP
.B 1
Security findings detected, verification failure, or assessment errors.
.TP
.B 2
Invalid CLI flags, bad arguments, or unreachable target error.
.SH FILES
.TP
.I ~/.felix/assessments.db
Persistent SQLite assessment database, audit logs, and finding stores.
.TP
.I ~/.felix/config.json
CLI configuration file.
.SH AUTHOR
Jothish <jothishgandham2@gmail.com>
.SH COPYRIGHT
Copyright (c) 2026 Jothish. Released under the MIT License.
`, strings.ToUpper(pkg), pkg, version, pkg, pkg, pkg, pkg, pkg, pkg)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(man)); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}
	return []byte(man), buf.Bytes(), nil
}

func generateBashCompletion(pkg string) []byte {
	return []byte(fmt.Sprintf(`_%s_completions() {
    local cur prev commands flags
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan report client assessment operator config doctor version update install uninstall completion help"
    flags="--export --json --timeout -t --concurrency -c --scope --max-assets --max-response-size --quiet -q --verbose -v -l --user-agent --check --force --dry-run --client --name --target --authorizer --role --reference --valid-days"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
        return 0
    fi
}
complete -F _%s_completions %s
`, pkg, pkg, pkg))
}

func generateZshCompletion(pkg string) []byte {
	return []byte(fmt.Sprintf(`#compdef %s

_%s() {
    local -a commands
    commands=(
        'scan:Perform a web security audit against target'
        'report:Generate reports from an existing scan result without rescanning'
        'client:Manage clients and organizations for structured assessments'
        'assessment:Manage authorized security assessment projects and runs'
        'operator:Launch local-first operator console'
        'config:Manage Felix operational settings'
        'doctor:Diagnose Felix runtime and installation health'
        'version:Show Felix version and build details'
        'update:Check for or install verified updates from official releases'
        'install:Install Felix binary to user environment'
        'uninstall:Remove Felix binary and user environment settings'
        'completion:Generate shell autocomplete script'
        'help:Show help information'
    )
    _arguments \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            _describe -t commands '%s commands' commands
            ;;
        args)
            _arguments \
                '--export[Export assessment report]' \
                '--json[Save or output JSON result]' \
                '--timeout[Request timeout]' \
                '-t[Request timeout]' \
                '--concurrency[Worker count]' \
                '-c[Worker count]' \
                '--scope[Crawl scope]' \
                '--quiet[Suppress output]' \
                '-q[Suppress output]' \
                '--verbose[Detailed output]' \
                '-v[Detailed output]' \
                '--check[Check for updates only]' \
                '--force[Force installation]' \
                '--client[Client reference or ID]' \
                '--name[Assessment or client name]'
            ;;
    esac
}
_%s "$@"
`, pkg, pkg, pkg, pkg))
}

func generateFishCompletion(pkg string) []byte {
	return []byte(fmt.Sprintf(`# Fish completion for %s
complete -c %s -f
complete -c %s -n "__fish_use_subcommand" -a "scan" -d "Perform web security audit"
complete -c %s -n "__fish_use_subcommand" -a "report" -d "Generate report from existing scan result"
complete -c %s -n "__fish_use_subcommand" -a "client" -d "Manage clients and organizations"
complete -c %s -n "__fish_use_subcommand" -a "assessment" -d "Manage authorized assessments"
complete -c %s -n "__fish_use_subcommand" -a "operator" -d "Launch operator console"
complete -c %s -n "__fish_use_subcommand" -a "config" -d "Manage operational settings"
complete -c %s -n "__fish_use_subcommand" -a "doctor" -d "Diagnose runtime health"
complete -c %s -n "__fish_use_subcommand" -a "version" -d "Show version information"
complete -c %s -n "__fish_use_subcommand" -a "update" -d "Check for or install updates"
complete -c %s -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"
complete -c %s -n "__fish_use_subcommand" -a "help" -d "Show help"
`, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg))
}

func generatePostinst(pkg string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/sh
set -e

case "$1" in
    configure)
        if [ -f /usr/bin/%s ]; then
            chmod 0755 /usr/bin/%s
        fi
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        ;;
esac

exit 0
`, pkg, pkg))
}

func generatePrerm() []byte {
	return []byte(`#!/bin/sh
set -e

case "$1" in
    remove|upgrade|deconfigure)
        ;;
    failed-upgrade)
        ;;
    *)
        ;;
esac

exit 0
`)
}

func generatePostrm(pkg string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/sh
set -e

case "$1" in
    remove)
        # Note: Debian packaging policy strictly preserves user assessment databases,
        # configurations, and generated reports located in ~/.felix/
        ;;
    purge)
        # On complete purge, remove system configuration directory if present
        if [ -d /etc/%s ]; then
            rm -rf /etc/%s
        fi
        ;;
    upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
        ;;
    *)
        ;;
esac

exit 0
`, pkg, pkg))
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
	archPks := make(map[string]*ArchPackage)
	var archList []string

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
		if _, exists := archPks[arch]; !exists {
			archPks[arch] = &ArchPackage{Arch: arch}
			archList = append(archList, arch)
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
	relBuf.WriteString(fmt.Sprintf("Architectures: %s\n", strings.Join(archList, " ")))
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
		var inRelBuf bytes.Buffer
		clearsignWriter, err := clearsign.Encode(&inRelBuf, signer.PrivateKey, nil)
		if err != nil {
			return fmt.Errorf("clearsign: %w", err)
		}
		if _, err := clearsignWriter.Write(releaseBytes); err != nil {
			return err
		}
		_ = clearsignWriter.Close()

		inRelContent := inRelBuf.String()
		if err := VerifyArmoredSignatureRFC4880(inRelContent); err != nil {
			return fmt.Errorf("InRelease RFC 4880 validation failed: %w", err)
		}
		if err := os.WriteFile(inReleasePath, []byte(inRelContent), 0644); err != nil {
			return err
		}

		// Detached signature Release.gpg
		releaseGpgPath := filepath.Join(distStable, "Release.gpg")
		var relGpgBuf bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&relGpgBuf, signer, bytes.NewReader(releaseBytes), nil); err != nil {
			return fmt.Errorf("detach sign: %w", err)
		}
		relGpgContent := relGpgBuf.String()
		if err := VerifyArmoredSignatureRFC4880(relGpgContent); err != nil {
			return fmt.Errorf("Release.gpg RFC 4880 validation failed: %w", err)
		}
		if err := os.WriteFile(releaseGpgPath, []byte(relGpgContent), 0644); err != nil {
			return err
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

// GenerateGpgSigner creates an in-memory OpenPGP entity for testing or ephemeral signing.
func GenerateGpgSigner(name, comment, email string) (*openpgp.Entity, error) {
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
	}
	return openpgp.NewEntity(name, comment, email, cfg)
}

// LoadOrCreateGpgSigner loads a persistent OpenPGP signing key or generates one if missing.
// It searches in order:
// 1. Environment variable FELIX_APT_SIGNING_KEY (armored private key string)
// 2. File keysDir/apt-signing-key.priv.asc
// 3. Generates a new 4096-bit RSA key, writing private and public keys to keysDir.
func LoadOrCreateGpgSigner(keysDir, name, comment, email string) (*openpgp.Entity, error) {
	if envKey := strings.TrimSpace(os.Getenv("FELIX_APT_SIGNING_KEY")); envKey != "" {
		return LoadGpgEntityFromArmored([]byte(envKey))
	}

	privPath := filepath.Join(keysDir, "apt-signing-key.priv.asc")
	if data, err := os.ReadFile(privPath); err == nil && len(data) > 0 {
		return LoadGpgEntityFromArmored(data)
	}

	// Generate persistent key
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return nil, fmt.Errorf("creating keys directory: %w", err)
	}

	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		RSABits:                4096,
	}

	entity, err := openpgp.NewEntity(name, comment, email, cfg)
	if err != nil {
		return nil, fmt.Errorf("generating GPG entity: %w", err)
	}

	// Save armored private key
	privFile, err := os.Create(privPath)
	if err != nil {
		return nil, fmt.Errorf("creating private key file: %w", err)
	}
	defer privFile.Close()

	privArm, err := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := entity.SerializePrivate(privArm, nil); err != nil {
		return nil, err
	}
	_ = privArm.Close()

	// Save public binary keyring
	pubGpgPath := filepath.Join(keysDir, "felix-archive-keyring.gpg")
	pubGpgFile, err := os.Create(pubGpgPath)
	if err == nil {
		_ = entity.Serialize(pubGpgFile)
		_ = pubGpgFile.Close()
	}

	// Save public armored key
	pubAscPath := filepath.Join(keysDir, "felix.gpg")
	pubAscFile, err := os.Create(pubAscPath)
	if err == nil {
		if pubArm, err := armor.Encode(pubAscFile, openpgp.PublicKeyType, nil); err == nil {
			_ = entity.Serialize(pubArm)
			_ = pubArm.Close()
		}
		_ = pubAscFile.Close()
	}

	return entity, nil
}

// LoadGpgEntityFromArmored parses an armored OpenPGP private key into an Entity.
func LoadGpgEntityFromArmored(armoredData []byte) (*openpgp.Entity, error) {
	block, err := armor.Decode(bytes.NewReader(armoredData))
	if err != nil {
		return nil, fmt.Errorf("decoding armored private key: %w", err)
	}
	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("reading private key ring: %w", err)
	}
	if len(entityList) == 0 {
		return nil, fmt.Errorf("no entities found in private key ring")
	}
	return entityList[0], nil
}

// VerifyArmoredSignatureRFC4880 parses an armored OpenPGP signature and verifies
// that every RSA MPI in the signature packet strictly satisfies RFC 4880 §3.2:
// "The leading bit of an MPI MUST be 1."
// This guarantees that strict OpenPGP verifiers, such as Sequoia PGP (/usr/bin/sqv)
// employed by Debian and Kali Linux APT, will not fail verification due to
// uncanonical leading zero bits or mismatched bit length declarations.
func VerifyArmoredSignatureRFC4880(armored string) error {
	lines := strings.Split(armored, "\n")
	var b64Lines []string
	capture := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "-----BEGIN PGP SIGNATURE-----" {
			capture = true
			continue
		}
		if l == "-----END PGP SIGNATURE-----" {
			break
		}
		if capture && l != "" && !strings.HasPrefix(l, "=") {
			b64Lines = append(b64Lines, l)
		}
	}
	rawB64 := strings.Join(b64Lines, "")
	sigBytes, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}

	if len(sigBytes) < 15 {
		return fmt.Errorf("signature packet too short: %d bytes", len(sigBytes))
	}

	version := sigBytes[3]
	if version != 4 {
		return fmt.Errorf("expected signature version 4, got %d", version)
	}

	hashedLen := int(sigBytes[7])<<8 | int(sigBytes[8])
	offset := 9 + hashedLen
	if offset+2 > len(sigBytes) {
		return fmt.Errorf("malformed packet: hashed length %d exceeds packet size", hashedLen)
	}
	unhashedLen := int(sigBytes[offset])<<8 | int(sigBytes[offset+1])
	offset += 2 + unhashedLen
	offset += 2 // skip 2-byte hash digest prefix
	if offset+2 > len(sigBytes) {
		return fmt.Errorf("malformed packet: offset %d exceeds packet size", offset)
	}

	mpiBitLen := int(sigBytes[offset])<<8 | int(sigBytes[offset+1])
	mpiBytes := sigBytes[offset+2:]
	expectedBytes := (mpiBitLen + 7) / 8
	if len(mpiBytes) != expectedBytes {
		return fmt.Errorf("MPI payload length mismatch: got %d bytes, expected %d for %d bits", len(mpiBytes), expectedBytes, mpiBitLen)
	}

	firstByte := mpiBytes[0]
	expectedLeadingBitPos := (mpiBitLen - 1) % 8
	bitSet := (firstByte >> expectedLeadingBitPos) & 1
	if bitSet != 1 {
		return fmt.Errorf("RFC 4880 §3.2 violation: leading bit (bit %d from LSB) in first byte 0x%02x is 0 (not set)", expectedLeadingBitPos, firstByte)
	}

	return nil
}
