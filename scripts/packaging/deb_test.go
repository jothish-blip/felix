package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestBuildDebAndAptRepo(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a dummy executable
	dummyBinPath := filepath.Join(tmpDir, "dummy_felix")
	if err := os.WriteFile(dummyBinPath, []byte("#!/bin/sh\necho Felix 2.0.0\n"), 0755); err != nil {
		t.Fatalf("failed to create dummy binary: %v", err)
	}

	// 2. Build .deb
	debPath := filepath.Join(tmpDir, "felix_2.0.0_amd64.deb")
	cfg := DebConfig{
		Package:      "felix",
		Version:      "2.0.0",
		Architecture: "amd64",
		Maintainer:   "Test Maintainer <test@example.com>",
		Homepage:     "https://github.com/jothish-blip/felix",
		Section:      "utils",
		Priority:     "optional",
		Description:  "Deterministic web security auditor",
		LongDesc:     "Felix test package description",
		BinaryPath:   dummyBinPath,
		OutputPath:   debPath,
	}

	if err := BuildDeb(cfg); err != nil {
		t.Fatalf("BuildDeb failed: %v", err)
	}

	// 3. Verify .deb AR structure
	debBytes, err := os.ReadFile(debPath)
	if err != nil {
		t.Fatalf("reading deb: %v", err)
	}
	if !strings.HasPrefix(string(debBytes), "!<arch>\n") {
		t.Fatalf("expected !<arch>\\n magic, got: %q", string(debBytes[:8]))
	}

	members, err := extractArMembers(debBytes)
	if err != nil {
		t.Fatalf("extractArMembers failed: %v", err)
	}

	if _, ok := members["debian-binary"]; !ok {
		t.Errorf("missing debian-binary member in deb")
	}
	if _, ok := members["control.tar.gz"]; !ok {
		t.Errorf("missing control.tar.gz member in deb")
	}
	if _, ok := members["data.tar.gz"]; !ok {
		t.Errorf("missing data.tar.gz member in deb")
	}

	// 4. Verify control extraction and maintainer scripts
	ctrlFiles, ctrlHeaders, err := parseTarGzWithHeaders(members["control.tar.gz"])
	if err != nil {
		t.Fatalf("parsing control.tar.gz: %v", err)
	}

	ctrlText := string(ctrlFiles["./control"])
	if !strings.Contains(ctrlText, "Package: felix") {
		t.Errorf("expected 'Package: felix' in control, got:\n%s", ctrlText)
	}
	if !strings.Contains(ctrlText, "Version: 2.0.0") {
		t.Errorf("expected 'Version: 2.0.0' in control, got:\n%s", ctrlText)
	}
	if !strings.Contains(ctrlText, "Architecture: amd64") {
		t.Errorf("expected 'Architecture: amd64' in control, got:\n%s", ctrlText)
	}

	// Verify maintainer scripts existence and executable permissions (0755)
	for _, script := range []string{"./postinst", "./prerm", "./postrm"} {
		hdr, ok := ctrlHeaders[script]
		if !ok {
			t.Errorf("missing %s in control.tar.gz", script)
			continue
		}
		if hdr.Mode != 0755 {
			t.Errorf("%s mode = %o, expected 0755", script, hdr.Mode)
		}
	}

	postinstScript := string(ctrlFiles["./postinst"])
	if !strings.Contains(postinstScript, "/usr/local/bin") {
		t.Errorf("postinst must inspect /usr/local/bin for shadowing executables")
	}
	if !strings.Contains(postinstScript, "! -s") {
		t.Errorf("postinst must detect and remove 0-byte corrupt files")
	}
	if !strings.Contains(postinstScript, "version") {
		t.Errorf("postinst must perform self-verification of the installed binary")
	}

	postrmScript := string(ctrlFiles["./postrm"])
	if !strings.Contains(postrmScript, "purge") || !strings.Contains(postrmScript, "/etc/felix") {
		t.Errorf("postrm should clean /etc/felix on purge, got:\n%s", postrmScript)
	}
	if strings.Contains(postrmScript, "rm -rf ~/.felix") || strings.Contains(postrmScript, "rm -rf $HOME/.felix") {
		t.Errorf("postrm must NEVER delete user assessment databases in ~/.felix")
	}

	// 5. Verify data.tar.gz contents (binary, man page, completions, changelog)
	dataFiles, dataHeaders, err := parseTarGzWithHeaders(members["data.tar.gz"])
	if err != nil {
		t.Fatalf("parsing data.tar.gz: %v", err)
	}

	expectedDataFiles := map[string]int64{
		"./usr/bin/felix":                                     0755,
		"./usr/share/doc/felix/copyright":                     0644,
		"./usr/share/doc/felix/changelog.Debian.gz":           0644,
		"./usr/share/man/man1/felix.1.gz":                     0644,
		"./usr/share/bash-completion/completions/felix":       0644,
		"./usr/share/zsh/vendor-completions/_felix":           0644,
		"./usr/share/fish/vendor_completions.d/felix.fish":    0644,
	}

	for path, expectedMode := range expectedDataFiles {
		hdr, ok := dataHeaders[path]
		if !ok {
			t.Errorf("missing %s in data.tar.gz", path)
			continue
		}
		if hdr.Mode != expectedMode {
			t.Errorf("%s mode = %o, expected %o", path, hdr.Mode, expectedMode)
		}
		if len(dataFiles[path]) == 0 {
			t.Errorf("%s is empty in data.tar.gz", path)
		}
	}

	// 6. Verify md5sums
	md5Text := string(ctrlFiles["./md5sums"])
	for path := range expectedDataFiles {
		rel := strings.TrimPrefix(path, "./")
		content := dataFiles[path]
		expectedSum := fmt.Sprintf("%x  %s", md5.Sum(content), rel)
		if !strings.Contains(md5Text, expectedSum) {
			t.Errorf("md5sums missing or invalid for %s: expected %q in:\n%s", rel, expectedSum, md5Text)
		}
	}

	// 7. Test APT Repository Generation
	repoDir := filepath.Join(tmpDir, "apt")
	signer, err := GenerateGpgSigner("Felix Test Signer", "Test Repo Key", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateGpgSigner failed: %v", err)
	}

	if err := BuildAptRepo(repoDir, []string{debPath}, signer); err != nil {
		t.Fatalf("BuildAptRepo failed: %v", err)
	}

	// Verify APT files
	expectedRepoFiles := []string{
		"dists/stable/Release",
		"dists/stable/InRelease",
		"dists/stable/Release.gpg",
		"dists/stable/main/binary-amd64/Packages",
		"dists/stable/main/binary-amd64/Packages.gz",
		"pool/main/f/felix/felix_2.0.0_amd64.deb",
		"felix-archive-keyring.gpg",
		"felix.gpg",
	}

	for _, rel := range expectedRepoFiles {
		p := filepath.Join(repoDir, filepath.FromSlash(rel))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("missing expected APT repo file: %s", rel)
		}
	}

	// Verify Packages content
	pkgBytes, err := os.ReadFile(filepath.Join(repoDir, "dists", "stable", "main", "binary-amd64", "Packages"))
	if err != nil {
		t.Fatalf("reading Packages: %v", err)
	}
	pkgContent := string(pkgBytes)
	if !strings.Contains(pkgContent, "Filename: pool/main/f/felix/felix_2.0.0_amd64.deb") {
		t.Errorf("Packages missing Filename line, got:\n%s", pkgContent)
	}
	if !strings.Contains(pkgContent, "SHA256:") {
		t.Errorf("Packages missing SHA256 line, got:\n%s", pkgContent)
	}

	// Verify InRelease is signed and conforms to RFC 4880 MPI specification
	inRelBytes, err := os.ReadFile(filepath.Join(repoDir, "dists", "stable", "InRelease"))
	if err != nil {
		t.Fatalf("reading InRelease: %v", err)
	}
	if !strings.Contains(string(inRelBytes), "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Errorf("InRelease is not clearsigned, got:\n%s", string(inRelBytes))
	}
	if err := VerifyArmoredSignatureRFC4880(string(inRelBytes)); err != nil {
		t.Errorf("InRelease failed RFC 4880 MPI verification: %v", err)
	}

	// Verify Release.gpg is detached signed and conforms to RFC 4880 MPI specification
	relGpgBytes, err := os.ReadFile(filepath.Join(repoDir, "dists", "stable", "Release.gpg"))
	if err != nil {
		t.Fatalf("reading Release.gpg: %v", err)
	}
	if err := VerifyArmoredSignatureRFC4880(string(relGpgBytes)); err != nil {
		t.Errorf("Release.gpg failed RFC 4880 MPI verification: %v", err)
	}

	// Verify public keyring
	keyringBytes, err := os.ReadFile(filepath.Join(repoDir, "felix-archive-keyring.gpg"))
	if err != nil {
		t.Fatalf("reading felix-archive-keyring.gpg: %v", err)
	}
	parsedKeyring, err := openpgp.ReadKeyRing(bytes.NewReader(keyringBytes))
	if err != nil {
		t.Fatalf("parsing felix-archive-keyring.gpg: %v", err)
	}
	if len(parsedKeyring) == 0 {
		t.Fatalf("felix-archive-keyring.gpg has no entities")
	}
	if !bytes.Equal(parsedKeyring[0].PrimaryKey.Fingerprint, signer.PrimaryKey.Fingerprint) {
		t.Errorf("keyring fingerprint %X != signer fingerprint %X", parsedKeyring[0].PrimaryKey.Fingerprint, signer.PrimaryKey.Fingerprint)
	}
}

func TestOpenPGPMPIComplianceRFC4880(t *testing.T) {
	// Statistically verify that 100 consecutive signatures strictly conform to RFC 4880 §3.2.
	// In the old golang.org/x/crypto/openpgp, roughly 50% of 2048-bit signatures violated RFC 4880
	// due to padding with uncanonical leading zero bits and declaring 2048-bit length when the
	// actual integer length was smaller.
	signer, err := GenerateGpgSigner("Felix Auditor", "Test", "felix@example.com")
	if err != nil {
		t.Fatalf("GenerateGpgSigner failed: %v", err)
	}

	testPayload := []byte("Origin: Felix\nSuite: stable\nVersion: 2.0.0\n")

	for i := 0; i < 100; i++ {
		// Test clearsign
		var inRelBuf bytes.Buffer
		w, err := clearsign.Encode(&inRelBuf, signer.PrivateKey, nil)
		if err != nil {
			t.Fatalf("clearsign run %d failed: %v", i, err)
		}
		if _, err := w.Write(testPayload); err != nil {
			t.Fatalf("clearsign write run %d failed: %v", i, err)
		}
		_ = w.Close()

		if err := VerifyArmoredSignatureRFC4880(inRelBuf.String()); err != nil {
			t.Fatalf("clearsign signature %d violated RFC 4880: %v", i, err)
		}

		// Test detached sign
		var detachBuf bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&detachBuf, signer, bytes.NewReader(testPayload), nil); err != nil {
			t.Fatalf("detach sign run %d failed: %v", i, err)
		}
		if err := VerifyArmoredSignatureRFC4880(detachBuf.String()); err != nil {
			t.Fatalf("detached signature %d violated RFC 4880: %v", i, err)
		}
	}
}

func TestLoadPersistentGpgSigner(t *testing.T) {
	tempKeysDir := t.TempDir()

	signer, err := LoadOrCreateGpgSigner(tempKeysDir, "Felix Test Signer", "Isolated Test Fixture", "test-fixture@felix.local")
	if err != nil {
		t.Fatalf("LoadOrCreateGpgSigner failed: %v", err)
	}

	if signer == nil || signer.PrimaryKey == nil {
		t.Fatalf("expected non-nil signer entity with PrimaryKey")
	}

	actualFP := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	if actualFP == CompromisedAptKeyFingerprint {
		t.Fatalf("CRITICAL SECURITY ERROR: generated/loaded test signer matches compromised fingerprint %s", CompromisedAptKeyFingerprint)
	}

	// Verify key identity
	foundIdentity := false
	for _, id := range signer.Identities {
		if strings.Contains(id.Name, "Felix Test Signer") {
			foundIdentity = true
			break
		}
	}
	if !foundIdentity {
		t.Errorf("expected identity 'Felix Test Signer' in loaded key")
	}

	// Verify idempotency: second call loads the same persisted test fixture
	signer2, err := LoadOrCreateGpgSigner(tempKeysDir, "Felix Test Signer", "Isolated Test Fixture", "test-fixture@felix.local")
	if err != nil {
		t.Fatalf("second LoadOrCreateGpgSigner failed: %v", err)
	}
	actualFP2 := fmt.Sprintf("%X", signer2.PrimaryKey.Fingerprint)
	if actualFP2 != actualFP {
		t.Errorf("expected idempotent fingerprint %s, got %s", actualFP, actualFP2)
	}
}

func encodeArmoredPrivateKeyForTest(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	arm, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode failed: %v", err)
	}
	if err := entity.SerializePrivateWithoutSigning(arm, nil); err != nil {
		t.Fatalf("SerializePrivateWithoutSigning failed: %v", err)
	}
	if err := arm.Close(); err != nil {
		t.Fatalf("armor close failed: %v", err)
	}
	return buf.String()
}

func TestCompromisedKeyRejection(t *testing.T) {
	if CompromisedAptKeyFingerprint != "8ABF68D0253A139577CA06E7154B088FE357A53D" {
		t.Fatalf("unexpected CompromisedAptKeyFingerprint constant: %s", CompromisedAptKeyFingerprint)
	}

	// Compromised private key must not exist in repository working tree
	repoPrivPath := filepath.Join("keys", "apt-signing-key.priv.asc")
	if _, err := os.Stat(repoPrivPath); !os.IsNotExist(err) {
		t.Fatalf("security violation: compromised key file still exists at %s", repoPrivPath)
	}

	// Generate an ephemeral entity and mark its fingerprint as compromised via test hook
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		RSABits:                2048,
	}
	entity, err := openpgp.NewEntity("Compromised Fixture", "Test", "revoked@example.invalid", cfg)
	if err != nil {
		t.Fatalf("openpgp.NewEntity failed: %v", err)
	}
	fp := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
	testExtraCompromisedAptFingerprints[fp] = true
	t.Cleanup(func() {
		delete(testExtraCompromisedAptFingerprints, fp)
	})

	armoredPriv := encodeArmoredPrivateKeyForTest(t, entity)

	if !IsCompromisedKey(entity) {
		t.Errorf("expected IsCompromisedKey to return true for registered compromised key %s", entity.PrimaryKey.KeyIdString())
	}

	// Test 1: Production loader fails if FELIX_APT_SIGNING_KEY is absent
	t.Setenv("FELIX_APT_SIGNING_KEY", "")
	t.Setenv("FELIX_APT_SIGNING_KEY_PASSPHRASE", "")
	if _, err := LoadProductionGpgSigner(); err == nil {
		t.Errorf("expected LoadProductionGpgSigner to fail when env var is empty")
	}

	// Test 2: Production loader strictly rejects compromised key even if supplied in FELIX_APT_SIGNING_KEY
	t.Setenv("FELIX_APT_SIGNING_KEY", armoredPriv)
	if _, err := LoadProductionGpgSigner(); err == nil {
		t.Errorf("expected LoadProductionGpgSigner to reject compromised key, but it succeeded!")
	} else if !strings.Contains(err.Error(), "security violation: FELIX_APT_SIGNING_KEY matches known compromised key") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Test 3: LoadOrCreateGpgSigner fails closed in production mode when missing or compromised
	tempKeysDir := t.TempDir()
	t.Setenv("FELIX_REQUIRE_PRODUCTION_SIGNING", "true")
	t.Setenv("FELIX_APT_SIGNING_KEY", "")
	if _, err := LoadOrCreateGpgSigner(tempKeysDir, "Name", "Comment", "email@example.com"); err == nil {
		t.Errorf("expected LoadOrCreateGpgSigner to fail closed in production mode when secret is missing")
	}

	// Test 4: LoadTestFixtureGpgSigner strictly rejects compromised fixture if present on disk
	t.Setenv("FELIX_REQUIRE_PRODUCTION_SIGNING", "false")
	t.Setenv("GITHUB_ACTIONS", "false")
	t.Setenv("FELIX_APT_SIGNING_KEY", "")
	compromisedFixturePath := filepath.Join(tempKeysDir, "test-fixture-signing-key.priv.asc")
	if err := os.WriteFile(compromisedFixturePath, []byte(armoredPriv), 0600); err != nil {
		t.Fatalf("failed writing temp compromised fixture: %v", err)
	}
	if _, err := LoadTestFixtureGpgSigner(tempKeysDir, "Name", "Comment", "email@example.com"); err == nil {
		t.Errorf("expected LoadTestFixtureGpgSigner to reject compromised test-fixture-signing-key.priv.asc, but it succeeded!")
	} else if !strings.Contains(err.Error(), "security violation") {
		t.Errorf("expected security violation error, got: %v", err)
	}
}

func TestLoadProductionGpgSigner_PassphraseEncryptedKey(t *testing.T) {
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		RSABits:                2048,
	}
	entity, err := openpgp.NewEntity("Felix CI Key", "Passphrase Test", "ci-test@example.invalid", cfg)
	if err != nil {
		t.Fatalf("openpgp.NewEntity failed: %v", err)
	}

	passphrase := []byte("correct-horse-battery-staple-99!")
	if err := entity.PrivateKey.Encrypt(passphrase); err != nil {
		t.Fatalf("encrypting primary key: %v", err)
	}
	for i := range entity.Subkeys {
		if entity.Subkeys[i].PrivateKey != nil {
			if err := entity.Subkeys[i].PrivateKey.Encrypt(passphrase); err != nil {
				t.Fatalf("encrypting subkey: %v", err)
			}
		}
	}

	armoredEncrypted := encodeArmoredPrivateKeyForTest(t, entity)
	t.Setenv("FELIX_APT_SIGNING_KEY", armoredEncrypted)

	// Missing passphrase must fail closed
	t.Setenv("FELIX_APT_SIGNING_KEY_PASSPHRASE", "")
	if _, err := LoadProductionGpgSigner(); err == nil || !strings.Contains(err.Error(), "FELIX_APT_SIGNING_KEY_PASSPHRASE is required") {
		t.Fatalf("expected fail-closed error for missing passphrase, got: %v", err)
	}

	// Wrong passphrase must fail closed
	t.Setenv("FELIX_APT_SIGNING_KEY_PASSPHRASE", "wrong-passphrase")
	if _, err := LoadProductionGpgSigner(); err == nil {
		t.Fatalf("expected error for wrong passphrase, got nil")
	}

	// Correct passphrase must decrypt entity and allow RFC 4880 signing
	t.Setenv("FELIX_APT_SIGNING_KEY_PASSPHRASE", string(passphrase))
	loaded, err := LoadProductionGpgSigner()
	if err != nil {
		t.Fatalf("LoadProductionGpgSigner with valid passphrase failed: %v", err)
	}
	if loaded.PrivateKey == nil || loaded.PrivateKey.Encrypted {
		t.Fatalf("expected decrypted primary private key, got encrypted=%v", loaded.PrivateKey != nil && loaded.PrivateKey.Encrypted)
	}

	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, loaded, strings.NewReader("release-manifest\n"), nil); err != nil {
		t.Fatalf("ArmoredDetachSign with decrypted key failed: %v", err)
	}
	if err := VerifyArmoredSignatureRFC4880(sigBuf.String()); err != nil {
		t.Fatalf("VerifyArmoredSignatureRFC4880 failed on signature from decrypted key: %v", err)
	}
}

func TestRepoKeyringsAndPrivateKeyAbsence(t *testing.T) {
	keysDir := filepath.Join("keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		t.Fatalf("failed reading scripts/packaging/keys: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if strings.Contains(lower, ".priv") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".pem") {
			t.Errorf("forbidden private key filename found in repo keys dir: %s", name)
		}
		if !entry.IsDir() {
			data, err := os.ReadFile(filepath.Join(keysDir, name))
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			if bytes.Contains(data, []byte("PRIVATE KEY BLOCK")) {
				t.Errorf("private key material found inside %s", name)
			}
		}
	}

	const expectedFP = "09688145E2E9EA7E8DA7D3F2B2D54E928F5C3920"

	armoredData, err := os.ReadFile(filepath.Join(keysDir, "felix.gpg"))
	if err != nil {
		t.Fatalf("reading keys/felix.gpg: %v", err)
	}
	armoredList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredData))
	if err != nil || len(armoredList) != 1 {
		t.Fatalf("parsing keys/felix.gpg failed: len=%d err=%v", len(armoredList), err)
	}
	if IsCompromisedKey(armoredList[0]) {
		t.Fatalf("keys/felix.gpg contains compromised key fingerprint")
	}
	if got := strings.ToUpper(fmt.Sprintf("%X", armoredList[0].PrimaryKey.Fingerprint)); got != expectedFP {
		t.Errorf("keys/felix.gpg fingerprint mismatch: expected %s, got %s", expectedFP, got)
	}

	binData, err := os.ReadFile(filepath.Join(keysDir, "felix-archive-keyring.gpg"))
	if err != nil {
		t.Fatalf("reading keys/felix-archive-keyring.gpg: %v", err)
	}
	binList, err := openpgp.ReadKeyRing(bytes.NewReader(binData))
	if err != nil || len(binList) != 1 {
		t.Fatalf("parsing keys/felix-archive-keyring.gpg failed: len=%d err=%v", len(binList), err)
	}
	if IsCompromisedKey(binList[0]) {
		t.Fatalf("keys/felix-archive-keyring.gpg contains compromised key fingerprint")
	}
	if got := strings.ToUpper(fmt.Sprintf("%X", binList[0].PrimaryKey.Fingerprint)); got != expectedFP {
		t.Errorf("keys/felix-archive-keyring.gpg fingerprint mismatch: expected %s, got %s", expectedFP, got)
	}
}

func TestGpgvVerificationIfAvailable(t *testing.T) {
	gpgvPath := "gpgv"
	if _, err := exec.LookPath(gpgvPath); err != nil {
		// Check Git's standard gpgv on Windows
		gitGpgv := "C:\\Program Files\\Git\\usr\\bin\\gpgv.exe"
		if _, err := os.Stat(gitGpgv); err == nil {
			gpgvPath = gitGpgv
		} else {
			t.Skip("gpgv not available on system; skipping external subprocess verification")
		}
	}

	tmpDir := t.TempDir()
	signer, err := GenerateGpgSigner("Felix Subprocess Test", "Test", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateGpgSigner failed: %v", err)
	}

	repoDir := filepath.Join(tmpDir, "repo")
	dummyDeb := filepath.Join(tmpDir, "dummy_2.0.0_amd64.deb")
	_ = os.WriteFile(dummyDeb, []byte("!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n"), 0644)

	// Create dummy control file for extraction
	var dummyCtrlBuf bytes.Buffer
	gw := gzip.NewWriter(&dummyCtrlBuf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0644, Size: 24, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("Package: felix\nVersion: 2\n"))
	_ = tw.Close()
	_ = gw.Close()

	// Rebuild valid deb AR with control.tar.gz
	var debBuf bytes.Buffer
	debBuf.WriteString("!<arch>\n")
	_ = writeArMember(&debBuf, "debian-binary", []byte("2.0\n"), time.Now())
	_ = writeArMember(&debBuf, "control.tar.gz", dummyCtrlBuf.Bytes(), time.Now())
	_ = os.WriteFile(dummyDeb, debBuf.Bytes(), 0644)

	if err := BuildAptRepo(repoDir, []string{dummyDeb}, signer); err != nil {
		t.Fatalf("BuildAptRepo failed: %v", err)
	}

	keyringPath := filepath.Join(repoDir, "felix-archive-keyring.gpg")
	inReleasePath := filepath.Join(repoDir, "dists", "stable", "InRelease")
	releasePath := filepath.Join(repoDir, "dists", "stable", "Release")
	relGpgPath := filepath.Join(repoDir, "dists", "stable", "Release.gpg")

	// 1. Verify InRelease
	cmd1 := exec.Command(gpgvPath, "--keyring", filepath.ToSlash(keyringPath), filepath.ToSlash(inReleasePath))
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Errorf("gpgv InRelease verification failed: %v\nOutput: %s", err, string(out1))
	}

	// 2. Verify Release.gpg + Release
	cmd2 := exec.Command(gpgvPath, "--keyring", filepath.ToSlash(keyringPath), filepath.ToSlash(relGpgPath), filepath.ToSlash(releasePath))
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Errorf("gpgv Release.gpg verification failed: %v\nOutput: %s", err, string(out2))
	}

	// 3. Verify that tampered Release fails
	tamperedRelease := append([]byte("TAMPERED\n"), releasePath...)
	tamperedPath := filepath.Join(tmpDir, "TamperedRelease")
	_ = os.WriteFile(tamperedPath, tamperedRelease, 0644)

	cmd3 := exec.Command(gpgvPath, "--keyring", filepath.ToSlash(keyringPath), filepath.ToSlash(relGpgPath), filepath.ToSlash(tamperedPath))
	if err := cmd3.Run(); err == nil {
		t.Errorf("gpgv should have failed verification on tampered Release file")
	}
}

func extractArMembers(debData []byte) (map[string][]byte, error) {
	members := make(map[string][]byte)
	r := bytes.NewReader(debData)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("invalid ar magic: %q", string(magic))
	}

	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		name := strings.TrimSpace(string(hdr[0:16]))
		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return nil, err
		}

		memberData := make([]byte, size)
		if _, err := io.ReadFull(r, memberData); err != nil {
			return nil, err
		}
		if size%2 != 0 {
			_, _ = r.ReadByte() // skip padding
		}
		members[name] = memberData
	}
	return members, nil
}

func parseTarGzWithHeaders(data []byte) (map[string][]byte, map[string]*tar.Header, error) {
	files := make(map[string][]byte)
	headers := make(map[string]*tar.Header)
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, err
			}
			files[hdr.Name] = b
			headers[hdr.Name] = hdr
		}
	}
	return files, headers, nil
}

func TestPostinstShadowingExecution(t *testing.T) {
	shPath := findSh()
	if shPath == "" {
		t.Skip("sh/bash not available; skipping maintainer script simulation")
	}

	tmpDir := t.TempDir()
	mockUsrBin := filepath.Join(tmpDir, "usr", "bin")
	mockUsrLocalBin := filepath.Join(tmpDir, "usr", "local", "bin")
	_ = os.MkdirAll(mockUsrBin, 0755)
	_ = os.MkdirAll(mockUsrLocalBin, 0755)

	mockBin := filepath.Join(mockUsrBin, "felix")
	_ = os.WriteFile(mockBin, []byte("#!/bin/sh\necho Felix 2.0.0\n"), 0755)

	mockShadow := filepath.Join(mockUsrLocalBin, "felix")

	// Helper to run simulated postinst with mock paths
	runMockPostinst := func() error {
		scriptContent := string(generatePostinst("felix"))
		// Redirect system paths to sandbox paths
		scriptContent = strings.ReplaceAll(scriptContent, "/usr/bin/felix", filepath.ToSlash(mockBin))
		scriptContent = strings.ReplaceAll(scriptContent, "/usr/local/bin", filepath.ToSlash(mockUsrLocalBin))
		scriptContent = strings.ReplaceAll(scriptContent, "/usr/local/sbin", filepath.ToSlash(mockUsrLocalBin))

		scriptPath := filepath.Join(tmpDir, "postinst_test.sh")
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
			return err
		}

		cmd := exec.Command(shPath, filepath.ToSlash(scriptPath), "configure")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("postinst failed: %w, out: %s", err, string(out))
		}
		return nil
	}

	// Case A: 0-byte corrupt shadowing file must be REMOVED
	if err := os.WriteFile(mockShadow, []byte(""), 0755); err != nil {
		t.Fatalf("creating 0-byte file: %v", err)
	}
	if err := runMockPostinst(); err != nil {
		t.Fatalf("runMockPostinst failed: %v", err)
	}
	if _, err := os.Stat(mockShadow); !os.IsNotExist(err) {
		t.Errorf("expected 0-byte shadowing file to be removed by postinst, but it still exists")
	}

	// Case B: Non-empty user binary must be PRESERVED
	nonEmptyContent := []byte("#!/bin/sh\necho custom-felix\n")
	if err := os.WriteFile(mockShadow, nonEmptyContent, 0755); err != nil {
		t.Fatalf("creating non-empty file: %v", err)
	}
	if err := runMockPostinst(); err != nil {
		t.Fatalf("runMockPostinst failed: %v", err)
	}
	data, err := os.ReadFile(mockShadow)
	if err != nil {
		t.Errorf("expected non-empty user file to be preserved, but read failed: %v", err)
	} else if string(data) != string(nonEmptyContent) {
		t.Errorf("non-empty user file content altered")
	}

	// Case C: Corrupt HTML download must be REMOVED
	htmlCorrupt := []byte("<html><head><title>404: Not Found</title></head><body>Error</body></html>")
	if err := os.WriteFile(mockShadow, htmlCorrupt, 0755); err != nil {
		t.Fatalf("creating HTML corrupt file: %v", err)
	}
	if err := runMockPostinst(); err != nil {
		t.Fatalf("runMockPostinst failed: %v", err)
	}
	if _, err := os.Stat(mockShadow); !os.IsNotExist(err) {
		t.Errorf("expected corrupt HTML file to be removed by postinst, but it still exists")
	}
}

func findSh() string {
	if p, err := exec.LookPath("sh"); err == nil {
		return p
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	gitSh := "C:\\Program Files\\Git\\bin\\sh.exe"
	if _, err := os.Stat(gitSh); err == nil {
		return gitSh
	}
	return ""
}
