package compliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoKeyConfigured is returned when no signing or verification key is available in the provider.
	ErrNoKeyConfigured = errors.New("no compliance signing or verification key configured")

	// ErrInvalidKeyMaterial is returned when key bytes are shorter than the required minimum length.
	ErrInvalidKeyMaterial = errors.New("invalid integrity key material: minimum 256 bits (32 bytes) required for HMAC-SHA256")

	// ErrInvalidKeyID is returned when a key ID is empty or malformed.
	ErrInvalidKeyID = errors.New("invalid key identifier: non-empty identifier required")

	// ErrKeyRetired is returned when attempting to use a retired key for signing.
	ErrKeyRetired = errors.New("integrity key has been retired from active signing")
)

// MinimumHMACKeyBytes defines the minimum key length for HMAC-SHA256 (32 bytes = 256 bits).
const MinimumHMACKeyBytes = 32

// IntegrityKey represents a cryptographic key used for signing or verifying compliance evaluations.
// Invariant: Secret material is NEVER serialized to JSON, printed in String(), or logged.
type IntegrityKey struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"` // e.g. AlgorithmHMACSHA256
	Material  []byte    `json:"-"`         // Redacted from JSON representation
	CreatedAt time.Time `json:"created_at,omitempty"`
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// String implements fmt.Stringer to ensure key bytes are never exposed in log output or errors.
func (k *IntegrityKey) String() string {
	if k == nil {
		return "<nil IntegrityKey>"
	}
	retired := ""
	if !k.RetiredAt.IsZero() {
		retired = fmt.Sprintf(", retired_at=%s", k.RetiredAt.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("IntegrityKey(id=%q, alg=%q%s)", k.ID, k.Algorithm, retired)
}

// Validate verifies that the key conforms to cryptographic length and identifier requirements.
func (k *IntegrityKey) Validate() error {
	if k == nil {
		return fmt.Errorf("%w: key cannot be nil", ErrInvalidKeyMaterial)
	}
	if strings.TrimSpace(k.ID) == "" {
		return fmt.Errorf("%w: empty key id", ErrInvalidKeyID)
	}
	if k.Algorithm == "" {
		k.Algorithm = AlgorithmHMACSHA256
	}
	if k.Algorithm != AlgorithmHMACSHA256 {
		return fmt.Errorf("unsupported key algorithm %q; must be %s", k.Algorithm, AlgorithmHMACSHA256)
	}
	if len(k.Material) < MinimumHMACKeyBytes {
		return fmt.Errorf("%w: got %d bytes, need at least %d bytes",
			ErrInvalidKeyMaterial, len(k.Material), MinimumHMACKeyBytes)
	}
	return nil
}

// IsRetired returns true if the key has been marked retired.
func (k *IntegrityKey) IsRetired() bool {
	if k == nil || k.RetiredAt.IsZero() {
		return false
	}
	return time.Now().UTC().After(k.RetiredAt)
}

// GenerateIntegrityKey generates a new cryptographically secure 256-bit HMAC key using crypto/rand.
func GenerateIntegrityKey(keyID string) (*IntegrityKey, error) {
	cleanID := strings.TrimSpace(keyID)
	if cleanID == "" {
		return nil, ErrInvalidKeyID
	}

	material := make([]byte, MinimumHMACKeyBytes)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("failed generating random key material: %w", err)
	}

	return &IntegrityKey{
		ID:        cleanID,
		Algorithm: AlgorithmHMACSHA256,
		Material:  material,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// KeyProvider defines the abstraction for obtaining signing and verification keys.
type KeyProvider interface {
	// GetSigningKey returns the active key to use for computing authenticity tags on new records.
	GetSigningKey(ctx context.Context) (*IntegrityKey, error)

	// GetVerificationKey retrieves the key corresponding to a specific keyID (for verifying historical records).
	GetVerificationKey(ctx context.Context, keyID string) (*IntegrityKey, error)
}

// StaticKeyProvider is a thread-safe in-memory KeyProvider supporting active signing and historical verification keys.
type StaticKeyProvider struct {
	mu               sync.RWMutex
	signingKey       *IntegrityKey
	verificationKeys map[string]*IntegrityKey
}

// NewStaticKeyProvider creates a StaticKeyProvider initialized with an optional signing key.
func NewStaticKeyProvider(signingKey *IntegrityKey) (*StaticKeyProvider, error) {
	p := &StaticKeyProvider{
		verificationKeys: make(map[string]*IntegrityKey),
	}
	if signingKey != nil {
		if err := signingKey.Validate(); err != nil {
			return nil, err
		}
		p.signingKey = signingKey
		p.verificationKeys[signingKey.ID] = signingKey
	}
	return p, nil
}

// AddVerificationKey registers a historical verification key (e.g. for key rotation).
func (p *StaticKeyProvider) AddVerificationKey(key *IntegrityKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verificationKeys[key.ID] = key
	return nil
}

// SetSigningKey sets or rotates the active signing key.
func (p *StaticKeyProvider) SetSigningKey(key *IntegrityKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if key.IsRetired() {
		return ErrKeyRetired
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signingKey = key
	p.verificationKeys[key.ID] = key
	return nil
}

// GetSigningKey returns the active signing key.
func (p *StaticKeyProvider) GetSigningKey(ctx context.Context) (*IntegrityKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.signingKey == nil {
		return nil, ErrNoKeyConfigured
	}
	if p.signingKey.IsRetired() {
		return nil, ErrKeyRetired
	}
	return p.signingKey, nil
}

// GetVerificationKey retrieves a verification key by ID.
func (p *StaticKeyProvider) GetVerificationKey(ctx context.Context, keyID string) (*IntegrityKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, exists := p.verificationKeys[strings.TrimSpace(keyID)]
	if !exists {
		return nil, fmt.Errorf("%w: key_id %q not found", ErrUnknownKey, keyID)
	}
	return key, nil
}

// EnvKeyProvider loads signing and verification key material from environment variables.
// Default env var: FELIX_COMPLIANCE_SIGNING_KEY formatted as "<key_id>:<hex_encoded_key>"
// or a raw 32+ character string with default key ID "env-default".
type EnvKeyProvider struct {
	envVar string
	mu     sync.RWMutex
	cache  *IntegrityKey
}

// NewEnvKeyProvider creates a new EnvKeyProvider. If envVar is empty, "FELIX_COMPLIANCE_SIGNING_KEY" is used.
func NewEnvKeyProvider(envVar string) *EnvKeyProvider {
	if envVar == "" {
		envVar = "FELIX_COMPLIANCE_SIGNING_KEY"
	}
	return &EnvKeyProvider{envVar: envVar}
}

func (p *EnvKeyProvider) loadKey() (*IntegrityKey, error) {
	p.mu.RLock()
	if p.cache != nil {
		defer p.mu.RUnlock()
		return p.cache, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache != nil {
		return p.cache, nil
	}

	val := strings.TrimSpace(os.Getenv(p.envVar))
	if val == "" {
		return nil, ErrNoKeyConfigured
	}

	keyID := "env-default"
	keyStr := val

	if idx := strings.Index(val, ":"); idx != -1 {
		keyID = strings.TrimSpace(val[:idx])
		keyStr = strings.TrimSpace(val[idx+1:])
	}

	var material []byte
	// Try hex decoding first
	if decoded, err := hex.DecodeString(keyStr); err == nil && len(decoded) >= MinimumHMACKeyBytes {
		material = decoded
	} else {
		// Use raw string bytes
		material = []byte(keyStr)
	}

	key := &IntegrityKey{
		ID:        keyID,
		Algorithm: AlgorithmHMACSHA256,
		Material:  material,
		CreatedAt: time.Now().UTC(),
	}

	if err := key.Validate(); err != nil {
		return nil, err
	}

	p.cache = key
	return key, nil
}

func (p *EnvKeyProvider) GetSigningKey(ctx context.Context) (*IntegrityKey, error) {
	return p.loadKey()
}

func (p *EnvKeyProvider) GetVerificationKey(ctx context.Context, keyID string) (*IntegrityKey, error) {
	key, err := p.loadKey()
	if err != nil {
		return nil, err
	}
	if key.ID != strings.TrimSpace(keyID) {
		return nil, fmt.Errorf("%w: env key has id %q, expected %q", ErrUnknownKey, key.ID, keyID)
	}
	return key, nil
}

// LoadKeyFromFile securely reads HMAC key material from a file on disk.
// Key material may be raw bytes or a hex-encoded string of at least 32 bytes (256 bits).
// Secret key bytes are never leaked in error messages or logs.
func LoadKeyFromFile(path string, keyID string) (*IntegrityKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading key file: %w", err)
	}
	raw := strings.TrimRight(string(data), "\r\n")

	var material []byte
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= MinimumHMACKeyBytes {
		material = decoded
	} else {
		material = []byte(raw)
	}

	cleanID := strings.TrimSpace(keyID)
	if cleanID == "" {
		cleanID = "file-default"
	}

	key := &IntegrityKey{
		ID:        cleanID,
		Algorithm: AlgorithmHMACSHA256,
		Material:  material,
		CreatedAt: time.Now().UTC(),
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}

// FileKeyProvider loads signing and verification key material from a protected key file.
type FileKeyProvider struct {
	path  string
	keyID string
	mu    sync.RWMutex
	cache *IntegrityKey
}

// NewFileKeyProvider creates a FileKeyProvider for the given file path.
func NewFileKeyProvider(path, keyID string) *FileKeyProvider {
	return &FileKeyProvider{path: path, keyID: keyID}
}

func (p *FileKeyProvider) loadKey() (*IntegrityKey, error) {
	p.mu.RLock()
	if p.cache != nil {
		defer p.mu.RUnlock()
		return p.cache, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache != nil {
		return p.cache, nil
	}

	key, err := LoadKeyFromFile(p.path, p.keyID)
	if err != nil {
		return nil, err
	}
	p.cache = key
	return key, nil
}

func (p *FileKeyProvider) GetSigningKey(ctx context.Context) (*IntegrityKey, error) {
	return p.loadKey()
}

func (p *FileKeyProvider) GetVerificationKey(ctx context.Context, keyID string) (*IntegrityKey, error) {
	key, err := p.loadKey()
	if err != nil {
		return nil, err
	}
	if key.ID != strings.TrimSpace(keyID) {
		return nil, fmt.Errorf("%w: file key has id %q, expected %q", ErrUnknownKey, key.ID, keyID)
	}
	return key, nil
}

// NoOpKeyProvider implements KeyProvider returning ErrNoKeyConfigured, allowing safe plain-hash mode.
type NoOpKeyProvider struct{}

func (NoOpKeyProvider) GetSigningKey(ctx context.Context) (*IntegrityKey, error) {
	return nil, ErrNoKeyConfigured
}

func (NoOpKeyProvider) GetVerificationKey(ctx context.Context, keyID string) (*IntegrityKey, error) {
	return nil, ErrNoKeyConfigured
}
