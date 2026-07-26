package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// AtRest encrypts on-disk data — the write-ahead log and the local blob cache —
// with AES-256-GCM (authenticated). It is opt-in: NewAtRest returns nil when no
// key is configured, and every method treats a nil receiver as a pass-through, so
// callers hold a *AtRest unconditionally and encryption changes nothing when off.
type AtRest struct {
	aead cipher.AEAD
}

// NewAtRest builds an AtRest from VCS_ENCRYPTION_KEY (64 hex chars = a 32-byte
// AES-256 key). Returns (nil, nil) when unset — encryption disabled.
func NewAtRest() (*AtRest, error) {
	return NewAtRestFromKey(os.Getenv("VCS_ENCRYPTION_KEY"))
}

// NewAtRestFromKey builds an AtRest from a hex-encoded 32-byte key. An empty key
// returns (nil, nil) — encryption disabled (a nil *AtRest is a pass-through).
func NewAtRestFromKey(raw string) (*AtRest, error) {
	if raw == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("secure: VCS_ENCRYPTION_KEY must be 64 hex characters (a 32-byte key)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AtRest{aead: aead}, nil
}

// Enabled reports whether encryption is configured.
func (a *AtRest) Enabled() bool { return a != nil }

// Seal returns nonce || ciphertext || tag (a fresh random nonce per call). A nil
// receiver returns the plaintext unchanged. The returned slice is independent of
// plaintext (safe to retain).
func (a *AtRest) Seal(plaintext []byte) ([]byte, error) {
	if a == nil {
		return plaintext, nil
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// dst=nonce so the output is nonce||ciphertext||tag.
	return a.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal, verifying the authentication tag. A nil receiver returns the
// data unchanged. A tampered/corrupt blob fails (GCM authentication), so at-rest
// corruption can never be returned as valid plaintext.
func (a *AtRest) Open(data []byte) ([]byte, error) {
	if a == nil {
		return data, nil
	}
	ns := a.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("secure: ciphertext shorter than the nonce")
	}
	return a.aead.Open(nil, data[:ns], data[ns:], nil)
}
