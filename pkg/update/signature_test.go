package update

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// generateTestEntity creates an in-memory OpenPGP entity for testing.
func generateTestEntity(t *testing.T, name, comment, email string) *openpgp.Entity {
	t.Helper()
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		RSABits:                2048,
	}
	entity, err := openpgp.NewEntity(name, comment, email, cfg)
	if err != nil {
		t.Fatalf("failed generating test entity: %v", err)
	}
	return entity
}

// signManifest creates an armored detached signature over manifest data.
func signManifest(t *testing.T, entity *openpgp.Entity, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSignText(&buf, entity, bytes.NewReader(data), nil); err != nil {
		t.Fatalf("failed to detach sign data: %v", err)
	}
	return buf.Bytes()
}

// Scenario 1: Valid signature and trusted identity
func TestSignature_Scenario1_ValidSignatureAndTrustedIdentity(t *testing.T) {
	keyA := generateTestEntity(t, "Release Officer", "Official Signer", "release@felix.local")
	manifest := []byte("a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef  felix_2.0.0_linux_amd64.tar.gz\n")
	sig := signManifest(t, keyA, manifest)

	keyring := openpgp.EntityList{keyA}
	expectedFP := fmt.Sprintf("%X", keyA.PrimaryKey.Fingerprint)

	signer, err := VerifyManifestSignature(manifest, sig, keyring, expectedFP)
	if err != nil {
		t.Fatalf("expected valid signature to verify successfully, got: %v", err)
	}

	actualFP := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	if actualFP != expectedFP {
		t.Errorf("expected signer fingerprint %s, got %s", expectedFP, actualFP)
	}
}

// Scenario 2: Invalid signature
func TestSignature_Scenario2_InvalidSignature(t *testing.T) {
	keyA := generateTestEntity(t, "Release Officer", "Official Signer", "release@felix.local")
	manifest := []byte("a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef  felix_2.0.0_linux_amd64.tar.gz\n")
	sig := signManifest(t, keyA, manifest)

	// Corrupt signature payload by modifying a base64 character in the body
	sigLines := strings.Split(string(sig), "\n")
	corrupted := false
	for i := range sigLines {
		line := strings.TrimSpace(sigLines[i])
		if !strings.HasPrefix(line, "-----") && !strings.HasPrefix(line, "=") && !strings.Contains(line, ":") && len(line) > 10 {
			r := []rune(sigLines[i])
			if r[5] == 'A' {
				r[5] = 'B'
			} else {
				r[5] = 'A'
			}
			sigLines[i] = string(r)
			corrupted = true
			break
		}
	}
	if !corrupted {
		t.Fatal("failed to locate base64 signature body line to corrupt")
	}
	corruptedSig := []byte(strings.Join(sigLines, "\n"))

	keyring := openpgp.EntityList{keyA}
	_, err := VerifyManifestSignature(manifest, corruptedSig, keyring, "")
	if err == nil {
		t.Fatal("expected corrupted signature to fail verification, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Scenario 3: Missing signature fails closed
func TestSignature_Scenario3_MissingSignature_FailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
		// Missing SHA256SUMS.asc entirely
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{
		TargetVersion:    "2.0.0",
		DryRun:           true,
		RequireSignature: true, // Strict fail-closed verification
	})
	if err == nil {
		t.Fatal("expected missing signature to fail closed, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature manifest SHA256SUMS.asc is missing") {
		t.Errorf("expected missing signature error, got: %v", err)
	}
}

// Scenario 4: Unexpected signer / untrusted fingerprint
func TestSignature_Scenario4_UnexpectedSignerFingerprint(t *testing.T) {
	keyA := generateTestEntity(t, "Official Signer", "Authorized", "official@felix.local")
	keyB := generateTestEntity(t, "Attacker Signer", "Unauthorized", "attacker@evil.local")

	manifest := []byte("1111111111111111111111111111111111111111111111111111111111111111  felix.tar.gz\n")
	// Signed by Key B (attacker)
	sigB := signManifest(t, keyB, manifest)

	// Verifier trusts Key A's fingerprint
	expectedFP := fmt.Sprintf("%X", keyA.PrimaryKey.Fingerprint)
	keyring := openpgp.EntityList{keyA, keyB}

	_, err := VerifyManifestSignature(manifest, sigB, keyring, expectedFP)
	if err == nil {
		t.Fatal("expected unexpected signer fingerprint to be rejected, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "unexpected signer fingerprint") {
		t.Errorf("expected unexpected signer fingerprint error, got: %v", err)
	}
}

// Scenario 5: Tampered artifact
func TestSignature_Scenario5_TamperedArtifact(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	keyA := generateTestEntity(t, "Official Signer", "Authorized", "official@felix.local")
	legitContent := "legitimate-official-felix-binary-content"
	h := sha256.Sum256([]byte(legitContent))
	legitHash := hex.EncodeToString(h[:])

	manifest := fmt.Sprintf("%s  %s\n", legitHash, archiveName)
	sig := signManifest(t, keyA, []byte(manifest))

	tamperedContent := "backdoored-or-corrupted-felix-payload"

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               int64(len(tamperedContent)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               int64(len(manifest)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
		{
			ID:                 3,
			Name:               "SHA256SUMS.asc",
			Size:               int64(len(sig)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS.asc",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "SHA256SUMS.asc"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(sig)),
				Header:     make(http.Header),
			}, nil
		case strings.HasSuffix(url, "SHA256SUMS"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(manifest)),
				Header:     make(http.Header),
			}, nil
		default:
			// Returns tampered content for archive
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(tamperedContent)),
				Header:     make(http.Header),
			}, nil
		}
	})

	opts := UpdateOptions{
		TargetVersion:          "2.0.0",
		DryRun:                 true,
		RequireSignature:       true,
		TrustedKeyRing:         openpgp.EntityList{keyA},
		ExpectedKeyFingerprint: fmt.Sprintf("%X", keyA.PrimaryKey.Fingerprint),
	}

	_, err = u.Update(context.Background(), opts)
	if err == nil {
		t.Fatal("expected tampered artifact to fail checksum verification, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "CRITICAL: SHA256 mismatch") {
		t.Errorf("expected SHA256 mismatch error, got: %v", err)
	}
}

// Scenario 6: Tampered checksum manifest
func TestSignature_Scenario6_TamperedChecksumManifest(t *testing.T) {
	keyA := generateTestEntity(t, "Official Signer", "Authorized", "official@felix.local")
	manifest := []byte("2222222222222222222222222222222222222222222222222222222222222222  felix.tar.gz\n")
	sig := signManifest(t, keyA, manifest)

	// Tamper with the manifest content (attacker alters target hash)
	tamperedManifest := []byte("3333333333333333333333333333333333333333333333333333333333333333  felix.tar.gz\n")

	keyring := openpgp.EntityList{keyA}
	_, err := VerifyManifestSignature(tamperedManifest, sig, keyring, "")
	if err == nil {
		t.Fatal("expected tampered manifest to fail signature verification, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature verification failed") {
		t.Errorf("expected signature verification failure, got: %v", err)
	}
}

// Scenario 7: Artifact and manifest replaced together
func TestSignature_Scenario7_ArtifactAndManifestReplacedTogether(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	keyA := generateTestEntity(t, "Legit Signer", "Authorized", "legit@felix.local")
	keyAttacker := generateTestEntity(t, "Attacker Key", "Rogue Signer", "attacker@evil.local")

	attackerPayload := "rogue-compromised-binary-content"
	h := sha256.Sum256([]byte(attackerPayload))
	attackerHash := hex.EncodeToString(h[:])

	// Attacker generates matching manifest and signs with their own key
	attackerManifest := fmt.Sprintf("%s  %s\n", attackerHash, archiveName)
	attackerSig := signManifest(t, keyAttacker, []byte(attackerManifest))

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               int64(len(attackerPayload)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               int64(len(attackerManifest)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
		{
			ID:                 3,
			Name:               "SHA256SUMS.asc",
			Size:               int64(len(attackerSig)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS.asc",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "SHA256SUMS.asc"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(attackerSig)),
				Header:     make(http.Header),
			}, nil
		case strings.HasSuffix(url, "SHA256SUMS"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(attackerManifest)),
				Header:     make(http.Header),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(attackerPayload)),
				Header:     make(http.Header),
			}, nil
		}
	})

	// Client updater strictly trusts Key A
	opts := UpdateOptions{
		TargetVersion:          "2.0.0",
		DryRun:                 true,
		RequireSignature:       true,
		TrustedKeyRing:         openpgp.EntityList{keyA}, // Attacker key is NOT in keyring
		ExpectedKeyFingerprint: fmt.Sprintf("%X", keyA.PrimaryKey.Fingerprint),
	}

	_, err = u.Update(context.Background(), opts)
	if err == nil {
		t.Fatal("expected replaced artifact and manifest to fail verification because signer is untrusted, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "cryptographic signature verification failed") {
		t.Errorf("expected signature failure, got: %v", err)
	}
}

// Scenario 8: Missing signing credentials fails closed
func TestSignature_Scenario8_MissingSigningCredentialsFailsClosed(t *testing.T) {
	manifest := []byte("4444444444444444444444444444444444444444444444444444444444444444  felix.tar.gz\n")
	sig := []byte("dummy-signature")

	// Call VerifyManifestSignature with nil keyring
	_, err := VerifyManifestSignature(manifest, sig, nil, "")
	if err == nil {
		t.Fatal("expected error when keyring is nil, got nil")
	}
	if !strings.Contains(err.Error(), "no trusted keyring provided") {
		t.Errorf("expected no trusted keyring error, got: %v", err)
	}
}

// Scenario 9: Verification tool failure / malformed packets
func TestSignature_Scenario9_MalformedPackets(t *testing.T) {
	keyA := generateTestEntity(t, "Official Signer", "Authorized", "official@felix.local")
	manifest := []byte("5555555555555555555555555555555555555555555555555555555555555555  felix.tar.gz\n")
	malformedSig := []byte("-----BEGIN PGP SIGNATURE-----\n\nnot-valid-base64-packet!!!\n-----END PGP SIGNATURE-----\n")

	keyring := openpgp.EntityList{keyA}
	_, err := VerifyManifestSignature(manifest, malformedSig, keyring, "")
	if err == nil {
		t.Fatal("expected malformed packet to fail verification, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature verification failed") {
		t.Errorf("expected signature failure, got: %v", err)
	}
}

// Scenario 10: Update rejection without changing existing executable / config / db
func TestSignature_Scenario10_UpdateRejectionWithoutModifyingTargetOrState(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Establish state: existing binary, config, database
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	existingBinPath := filepath.Join(tempDir, binName)
	existingBinContent := []byte("pre-existing-felix-v1.0.0-binary-content")
	if err := os.WriteFile(existingBinPath, existingBinContent, 0755); err != nil {
		t.Fatalf("failed to create existing binary: %v", err)
	}

	configPath := filepath.Join(tempDir, "config.json")
	configContent := []byte(`{"version":"1.0.0","strict_mode":true}`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	dbPath := filepath.Join(tempDir, "felix.db")
	dbContent := []byte("sqlite-database-records-pre-existing")
	if err := os.WriteFile(dbPath, dbContent, 0644); err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	// 2. Configure mock updater targeting a tampered release
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusOK,
				// Manifest with bad checksum
				Body:   io.NopCloser(strings.NewReader(fmt.Sprintf("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  %s\n", archiveName))),
				Header: make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("candidate-download-content")),
			Header:     make(http.Header),
		}, nil
	})

	// Run update (which will fail at hash verification before install)
	_, updateErr := u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0"})
	if updateErr == nil {
		t.Fatal("expected update to fail, but it succeeded!")
	}

	// 3. Verify that existing binary, config, and database are 100% UNTOUCHED!
	actualBin, err := os.ReadFile(existingBinPath)
	if err != nil || !bytes.Equal(actualBin, existingBinContent) {
		t.Fatalf("CRITICAL INTEGRITY FAILURE: target executable was modified or deleted despite failed update!")
	}

	actualConfig, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(actualConfig, configContent) {
		t.Fatalf("CRITICAL INTEGRITY FAILURE: configuration file was modified during failed update!")
	}

	actualDB, err := os.ReadFile(dbPath)
	if err != nil || !bytes.Equal(actualDB, dbContent) {
		t.Fatalf("CRITICAL INTEGRITY FAILURE: database was modified during failed update!")
	}
}

// Scenario 11: Verification bypass attempts (e.g. force flags or missing signature) fail closed
func TestSignature_Scenario11_VerificationBypassAttempts_FailClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	assetsWithoutSig := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assetsWithoutSig, func(url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	// Test 11A: Force flag cannot bypass missing signature when RequireSignature is true
	optsForce := UpdateOptions{
		TargetVersion:    "2.0.0",
		Force:            true, // Attacker attempts bypass with --force
		DryRun:           true,
		RequireSignature: true,
	}
	_, err = u.Update(context.Background(), optsForce)
	if err == nil {
		t.Fatal("expected update with missing signature to fail even with Force=true, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature manifest SHA256SUMS.asc is missing") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Test 11B: FELIX_UPDATE_REQUIRE_SIGNATURE environment variable enforces fail-closed behavior
	t.Setenv("FELIX_UPDATE_REQUIRE_SIGNATURE", "true")
	optsDefault := UpdateOptions{
		TargetVersion: "2.0.0",
		DryRun:        true,
	}
	_, err = u.Update(context.Background(), optsDefault)
	if err == nil {
		t.Fatal("expected update to fail closed when FELIX_UPDATE_REQUIRE_SIGNATURE=true, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "detached signature manifest SHA256SUMS.asc is missing") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Scenario 12: Compromised signer in keyring is strictly rejected even if validly signed
func TestSignature_Scenario12_CompromisedSignerInKeyring_StrictlyRejected(t *testing.T) {
	// Read the known compromised key fixture
	keysDir := filepath.Join("..", "..", "scripts", "packaging", "keys")
	privPath := filepath.Join(keysDir, "apt-signing-key.priv.asc")
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		t.Skip("compromised key fixture not found relative to pkg/update")
	}

	keyData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed reading compromised key fixture: %v", err)
	}

	compromisedEntity, err := LoadArmoredPublicKeyring(keyData)
	if err != nil {
		// If private key block, read entity via openpgp
		var blockErr error
		compromisedEntity, blockErr = openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
		if blockErr != nil {
			t.Fatalf("failed parsing compromised entity: %v", blockErr)
		}
	}

	manifest := []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  felix.tar.gz\n")
	sig := signManifest(t, compromisedEntity[0], manifest)

	// Even if an operator or attacker injects the compromised key into the trusted keyring:
	keyring := openpgp.EntityList{compromisedEntity[0]}

	_, err = VerifyManifestSignature(manifest, sig, keyring, "")
	if err == nil {
		t.Fatal("CRITICAL: VerifyManifestSignature allowed signature from known compromised key!")
	}
	if !strings.Contains(err.Error(), "security violation: signature signed by known compromised key") {
		t.Errorf("expected security violation error, got: %v", err)
	}
}

// Scenario 13: Untrusted remote manifest / assets cannot inject or override local trust root
func TestSignature_Scenario13_UntrustedManifestCannotOverrideTrustRoot(t *testing.T) {
	// Attacker generates their own key and signs a malicious manifest
	attackerKey := generateTestEntity(t, "Adversary", "Malicious Key", "adversary@evil.local")
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	rawArchive := []byte("compromised-binary-payload")
	archiveHash := sha256.Sum256(rawArchive)
	archiveHashHex := hex.EncodeToString(archiveHash[:])

	maliciousManifest := []byte(fmt.Sprintf("%s  %s\n", archiveHashHex, archiveName))
	maliciousSig := signManifest(t, attackerKey, maliciousManifest)

	// Legitimate operator has their own trusted key
	legitKey := generateTestEntity(t, "Legitimate Release", "Official Key", "release@felix.local")
	trustedKeyring := openpgp.EntityList{legitKey}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               int64(len(rawArchive)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               int64(len(maliciousManifest)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
		{
			ID:                 3,
			Name:               "SHA256SUMS.asc",
			Size:               int64(len(maliciousSig)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS.asc",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS.asc") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(maliciousSig)),
				Header:     make(http.Header),
			}, nil
		}
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(maliciousManifest)),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(rawArchive)),
			Header:     make(http.Header),
		}, nil
	})

	// Operator executes update with trusted keyring
	opts := UpdateOptions{
		TargetVersion:    "2.0.0",
		DryRun:           true,
		RequireSignature: true,
		TrustedKeyRing:   trustedKeyring,
	}

	_, err = u.Update(context.Background(), opts)
	if err == nil {
		t.Fatal("CRITICAL: Update succeeded with signature from untrusted key not in trusted keyring!")
	}
	if !strings.Contains(err.Error(), "cryptographic signature verification failed") {
		t.Errorf("expected cryptographic signature verification failure, got: %v", err)
	}
}

// Scenario 14: LoadKeyringFile strictly rejects keyrings containing the compromised key
func TestSignature_Scenario14_LoadKeyringFile_RejectsCompromisedKey(t *testing.T) {
	keysDir := filepath.Join("..", "..", "scripts", "packaging", "keys")
	pubKeyPath := filepath.Join(keysDir, "felix.gpg")
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		t.Skip("felix.gpg public key fixture not found")
	}

	// Attempt to load felix.gpg which has the compromised fingerprint
	_, err := LoadKeyringFile(pubKeyPath)
	if err == nil {
		t.Fatal("CRITICAL: LoadKeyringFile loaded public key with compromised fingerprint!")
	}
	if !strings.Contains(err.Error(), "security violation: keyring contains known permanently compromised key fingerprint") {
		t.Errorf("expected security violation error message, got: %v", err)
	}
}

// Scenario 15: LoadKeyringFile successfully loads an uncompromised trusted public keyring
func TestSignature_Scenario15_LoadKeyringFile_ValidKeyring(t *testing.T) {
	tempDir := t.TempDir()
	keyringFile := filepath.Join(tempDir, "trusted.asc")

	validEntity := generateTestEntity(t, "Trusted Release", "Official Key", "security@felix.local")
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor encode failed: %v", err)
	}
	if err := validEntity.Serialize(w); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	w.Close()

	if err := os.WriteFile(keyringFile, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write keyring file failed: %v", err)
	}

	loaded, err := LoadKeyringFile(keyringFile)
	if err != nil {
		t.Fatalf("expected LoadKeyringFile to succeed with valid key, got: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 entity in loaded keyring, got %d", len(loaded))
	}

	expectedFP := fmt.Sprintf("%X", validEntity.PrimaryKey.Fingerprint)
	actualFP := fmt.Sprintf("%X", loaded[0].PrimaryKey.Fingerprint)
	if expectedFP != actualFP {
		t.Errorf("fingerprint mismatch: expected %s, got %s", expectedFP, actualFP)
	}
}

// Scenario 16: Update with RequireSignature fails closed when no keyring is configured
func TestSignature_Scenario16_NoKeyringConfigured_FailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
		{
			ID:                 3,
			Name:               "SHA256SUMS.asc",
			Size:               512,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS.asc",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  %s\n", archiveName))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-signature-or-content")),
			Header:     make(http.Header),
		}, nil
	})

	t.Setenv("FELIX_UPDATE_KEYRING", "")
	t.Setenv("FELIX_UPDATE_EXPECTED_KEY", "")

	opts := UpdateOptions{
		TargetVersion:    "2.0.0",
		DryRun:           true,
		RequireSignature: true,
		TrustedKeyRing:   nil, // Intentionally unconfigured
	}

	_, err = u.Update(context.Background(), opts)
	if err == nil {
		t.Fatal("expected update to fail closed when no keyring is configured, but it succeeded!")
	}
	if !strings.Contains(err.Error(), "no trusted keyring provided") {
		t.Errorf("expected 'no trusted keyring provided' error, got: %v", err)
	}
}
