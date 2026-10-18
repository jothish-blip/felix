package apk

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMobileAuditReportName is the canonical file name for the mobile security audit report.
const DefaultMobileAuditReportName = "mobile_audit.html"

// GenerateMobileAuditHTML renders the mobile audit report to standalone HTML bytes using safe templating.
func GenerateMobileAuditHTML(data *MobileReportData) ([]byte, error) {
	if data == nil {
		return nil, WrapError("report", "report data is nil", ErrInvalidInput)
	}

	tmpl, err := template.New("mobile_audit.html").Parse(mobileAuditHTMLTemplate)
	if err != nil {
		return nil, WrapError("report", "failed parsing mobile audit report template", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, WrapError("report", "failed executing mobile audit report template", err)
	}

	return buf.Bytes(), nil
}

// WriteMobileAuditReport safely serializes the HTML report to disk using an atomic write strategy.
// It verifies that the output destination does not overwrite the source APK file.
func WriteMobileAuditReport(data *MobileReportData, outputPath string, apkPath string) error {
	if data == nil {
		return WrapError("report", "report data is nil", ErrInvalidInput)
	}

	cleanOut := strings.TrimSpace(outputPath)
	if cleanOut == "" {
		cleanOut = DefaultMobileAuditReportName
	}
	cleanOut = filepath.Clean(cleanOut)

	// Guard against accidental overwrite of the input APK package
	if apkPath != "" {
		cleanAPK := filepath.Clean(apkPath)
		if cleanOut == cleanAPK {
			return WrapError("report", fmt.Sprintf("refusing to overwrite input APK at %q", apkPath), ErrInvalidInput)
		}
	}

	// Generate report HTML bytes
	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		return err
	}

	// Ensure destination directory exists
	outDir := filepath.Dir(cleanOut)
	if outDir != "" && outDir != "." {
		if err := os.MkdirAll(outDir, 0750); err != nil {
			return WrapError("report", fmt.Sprintf("failed creating destination directory %q", outDir), err)
		}
	}

	// Atomic write using a temporary sibling file
	tmpFile, err := os.CreateTemp(outDir, ".tmp-mobile-audit-*.html")
	if err != nil {
		return WrapError("report", fmt.Sprintf("failed creating temporary report file in %q", outDir), err)
	}
	tmpName := tmpFile.Name()

	// Ensure temporary file cleanup on failure
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.Write(htmlBytes); err != nil {
		_ = tmpFile.Close()
		return WrapError("report", fmt.Sprintf("failed writing report contents to %q", tmpName), err)
	}
	if err := tmpFile.Close(); err != nil {
		return WrapError("report", fmt.Sprintf("failed closing temporary report file %q", tmpName), err)
	}

	// Atomically replace destination file (remove first on Windows to avoid access refusal)
	_ = os.Remove(cleanOut)
	if err := os.Rename(tmpName, cleanOut); err != nil {
		return WrapError("report", fmt.Sprintf("failed renaming temporary report %q to %q", tmpName, cleanOut), err)
	}

	cleanup = false
	return nil
}
