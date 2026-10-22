package main

import (
	"strings"
	"testing"

	"felix/pkg/clierror"
)

// TestCLI_RootCommandAndExitCodes tests root CLI dispatch, help, and exit code contracts.
func TestCLI_RootCommandAndExitCodes(t *testing.T) {
	// 1. Empty arguments prints root help and exits with ExitSuccess (0)
	var code int
	out, _ := captureOutput(func() {
		code = run([]string{})
	})
	if code != clierror.ExitSuccess {
		t.Errorf("empty args exit code = %d, want %d (ExitSuccess)", code, clierror.ExitSuccess)
	}
	if !strings.Contains(out, "Commands:") || !strings.Contains(out, "scan") {
		t.Errorf("expected root help output, got: %s", out)
	}

	// 2. Unknown command returns ExitOperational (2) and reports unknown command on stderr
	var codeUnknown int
	_, errOut := captureOutput(func() {
		codeUnknown = run([]string{"unknown-subcommand-xyz"})
	})
	if codeUnknown != clierror.ExitOperational {
		t.Errorf("unknown command exit code = %d, want %d (ExitOperational)", codeUnknown, clierror.ExitOperational)
	}
	if !strings.Contains(errOut, "[-] Unknown command: unknown-subcommand-xyz") {
		t.Errorf("expected unknown command error message, got: %s", errOut)
	}

	// 3. Version command returns ExitSuccess (0)
	var codeVer int
	outVer, _ := captureOutput(func() {
		codeVer = run([]string{"version"})
	})
	if codeVer != clierror.ExitSuccess {
		t.Errorf("version exit code = %d, want %d", codeVer, clierror.ExitSuccess)
	}
	if !strings.Contains(outVer, "Felix") {
		t.Errorf("version output missing 'Felix': %s", outVer)
	}

	// 4. Help subcommands return ExitSuccess (0)
	var codeHelp int
	outHelp, _ := captureOutput(func() {
		codeHelp = run([]string{"help", "scan"})
	})
	if codeHelp != clierror.ExitSuccess {
		t.Errorf("help scan exit code = %d, want %d", codeHelp, clierror.ExitSuccess)
	}
	if !strings.Contains(outHelp, "Usage:") {
		t.Errorf("help scan output missing usage: %s", outHelp)
	}
}

// TestCLI_ErrorPathsAndSafeMessages tests CLI argument handling and non-disclosure of internal details.
func TestCLI_ErrorPathsAndSafeMessages(t *testing.T) {
	// 1. Scan command missing target returns ExitOperational (2)
	var codeScan int
	_, errScan := captureOutput(func() {
		codeScan = run([]string{"scan"})
	})
	if codeScan != clierror.ExitOperational {
		t.Errorf("scan without target exit code = %d, want %d", codeScan, clierror.ExitOperational)
	}
	if !strings.Contains(errScan, "Usage") && !strings.Contains(errScan, "target") {
		t.Errorf("unexpected scan error output: %s", errScan)
	}

	// 2. Report command with non-existent file returns ExitOperational (2)
	var codeRep int
	_, errRep := captureOutput(func() {
		codeRep = run([]string{"report", "non_existent_file_12345.json"})
	})
	if codeRep != clierror.ExitOperational {
		t.Errorf("report non-existent file exit code = %d, want %d", codeRep, clierror.ExitOperational)
	}
	// Verify error output does not leak absolute private filesystem roots
	if strings.Contains(errRep, "/var/log/private") || strings.Contains(errRep, "SELECT * FROM") {
		t.Errorf("error output disclosed internal details: %s", errRep)
	}

	// 3. APK command without argument returns ExitOperational (2)
	var codeAPK int
	_, errAPK := captureOutput(func() {
		codeAPK = run([]string{"apk"})
	})
	if codeAPK != clierror.ExitOperational {
		t.Errorf("apk without args exit code = %d, want %d", codeAPK, clierror.ExitOperational)
	}
	if !strings.Contains(strings.ToLower(errAPK), "apk") {
		t.Errorf("unexpected apk error output: %s", errAPK)
	}
}

// TestCLI_EvidenceReview_ZeroSecretLeaks tests that CLI argument validation and error output
// never leak sensitive credentials, passwords, or tokens in stdout or stderr.
func TestCLI_EvidenceReview_ZeroSecretLeaks(t *testing.T) {
	testSecretPassword := "FELIX_TEST_SECRET_PASS_CLI_P@ssw0rd999"
	testSecretToken := "FELIX_TEST_SECRET_TOKEN_CLI_a1b2c3d4e5f6"

	// 1. Scan command targeting a credential-bearing URL: embedded password must be redacted
	targetWithPass := "https://felix_admin:" + testSecretPassword + "@127.0.0.1:8443/api"
	var codeScan int
	stdoutScan, stderrScan := captureOutput(func() {
		codeScan = run([]string{"scan", targetWithPass})
	})
	if codeScan != clierror.ExitOperational {
		t.Errorf("scan with credential URL exit code = %d, want %d", codeScan, clierror.ExitOperational)
	}
	combinedScan := stdoutScan + "\n" + stderrScan
	if strings.Contains(combinedScan, testSecretPassword) {
		t.Fatalf("CLI scan output leaked synthetic password marker: %s", combinedScan)
	}
	if !strings.Contains(combinedScan, "felix_admin:[REDACTED]@127.0.0.1:8443") {
		t.Errorf("Expected sanitized URL placeholder in CLI stderr, got: %s", combinedScan)
	}

	// 2. Scan command targeting a malformed URL with token query parameter
	targetWithToken := "http://[invalid-host]:8080/auth?token=" + testSecretToken + "&secret=FELIX_TEST_SECRET_SEC_999"
	var codeToken int
	stdoutToken, stderrToken := captureOutput(func() {
		codeToken = run([]string{"scan", targetWithToken})
	})
	if codeToken != clierror.ExitOperational {
		t.Errorf("scan with malformed target exit code = %d, want %d", codeToken, clierror.ExitOperational)
	}
	combinedToken := stdoutToken + "\n" + stderrToken
	if strings.Contains(combinedToken, testSecretToken) || strings.Contains(combinedToken, "FELIX_TEST_SECRET") {
		t.Fatalf("CLI error output leaked sensitive query token: %s", combinedToken)
	}
}
