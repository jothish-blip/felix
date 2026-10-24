package update

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// CompromisedKeyFingerprint identifies the permanently compromised APT/release key
// that must be strictly rejected even if present in a keyring.
const CompromisedKeyFingerprint = "8ABF68D0253A139577CA06E7154B088FE357A53D"

// VerifyManifestSignature verifies an armored detached OpenPGP signature for a given manifest.
// It enforces that:
// 1. Both manifest and signature data are non-empty.
// 2. The signature is mathematically valid according to RFC 4880.
// 3. The signing key is present in the provided trusted keyring.
// 4. The signing key does NOT match the known compromised key fingerprint.
// 5. If expectedFingerprint is provided, the signing key's fingerprint matches it exactly.
func VerifyManifestSignature(manifestData, sigData []byte, keyring openpgp.KeyRing, expectedFingerprint string) (*openpgp.Entity, error) {
	if len(manifestData) == 0 {
		return nil, errors.New("empty manifest data")
	}
	if len(sigData) == 0 {
		return nil, errors.New("empty signature data")
	}
	if keyring == nil {
		return nil, errors.New("no trusted keyring provided for signature verification (configure --keyring or FELIX_UPDATE_KEYRING)")
	}

	signer, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		bytes.NewReader(manifestData),
		bytes.NewReader(sigData),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("detached signature verification failed: %w", err)
	}
	if signer == nil || signer.PrimaryKey == nil {
		return nil, errors.New("signature verified but signer entity is nil")
	}

	actualFP := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)

	// Invariant: strictly reject known compromised key
	if strings.EqualFold(actualFP, CompromisedKeyFingerprint) {
		return nil, fmt.Errorf("security violation: signature signed by known compromised key (%s)", CompromisedKeyFingerprint)
	}

	// Validate expected fingerprint if specified
	if expectedFingerprint != "" {
		cleanExpected := strings.ToUpper(strings.ReplaceAll(expectedFingerprint, " ", ""))
		if !strings.EqualFold(actualFP, cleanExpected) {
			return nil, fmt.Errorf("unexpected signer fingerprint: expected %s, got %s", cleanExpected, actualFP)
		}
	}

	return signer, nil
}

// LoadArmoredPublicKeyring parses an armored public key or keyring string into an openpgp.EntityList.
// Rejects any key matching the compromised key fingerprint.
func LoadArmoredPublicKeyring(armoredKey []byte) (openpgp.EntityList, error) {
	block, err := armor.Decode(bytes.NewReader(armoredKey))
	if err != nil {
		return nil, fmt.Errorf("decoding armored public key: %w", err)
	}
	if block.Type != openpgp.PublicKeyType {
		return nil, fmt.Errorf("unexpected armor block type: %s (expected %s)", block.Type, openpgp.PublicKeyType)
	}
	el, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing public keyring: %w", err)
	}
	if len(el) == 0 {
		return nil, errors.New("no public keys found in keyring")
	}
	for _, entity := range el {
		if entity != nil && entity.PrimaryKey != nil {
			fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
			if strings.EqualFold(fp, CompromisedKeyFingerprint) {
				return nil, fmt.Errorf("security violation: keyring contains known permanently compromised key fingerprint (%s)", CompromisedKeyFingerprint)
			}
		}
	}
	return el, nil
}

// LoadKeyringFile reads an armored or binary OpenPGP public keyring from disk.
// Rejects keyrings containing the known compromised key fingerprint.
func LoadKeyringFile(path string) (openpgp.EntityList, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading keyring file %s: %w", cleanPath, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty keyring file %s", cleanPath)
	}

	// If armored ASCII keyring
	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		return LoadArmoredPublicKeyring(data)
	}

	// Try binary public keyring
	el, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing keyring file %s: %w", cleanPath, err)
	}
	if len(el) == 0 {
		return nil, fmt.Errorf("no public keys found in keyring %s", cleanPath)
	}
	for _, entity := range el {
		if entity != nil && entity.PrimaryKey != nil {
			fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
			if strings.EqualFold(fp, CompromisedKeyFingerprint) {
				return nil, fmt.Errorf("security violation: keyring contains known permanently compromised key fingerprint (%s)", CompromisedKeyFingerprint)
			}
		}
	}
	return el, nil
}
