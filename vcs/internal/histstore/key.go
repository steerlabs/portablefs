// Package histstore is the exact-key immutable object storage layer of the
// history worker: one narrow Store interface over two production backends —
// a confined local filesystem (openat-style traversal, temp+fsync+atomic
// rename, parent durability) and an S3-compatible endpoint (SigV4, streaming
// bodies, deadlines, no whole-object buffering).
//
// Keys are EXACT and recorded: the worker derives a key once, immediately
// before the first PUT, from the full object identity
// (tenant, kind, digest, incarnation) plus the store's configured prefix,
// and records the returned key in the database copy receipt. Every later
// read, scrub, repair, and delete presents a DB-recorded key verbatim.
// Nothing in this package (or its callers) treats a digest-derived path as
// the location of truth: a recorded key is the only address of a copy, and
// bytes fetched through it are always re-verified against the recorded
// size and digest by the caller.
package histstore

import (
	"errors"
	"fmt"
	"strings"
)

// Errors classify storage outcomes for the fenced worker loops.
var (
	// ErrNotFound is proven absence at an exact key (a HEAD/GET miss).
	ErrNotFound = errors.New("histstore: object not found")
	// ErrInvalidKey rejects a key that fails strict validation before any
	// filesystem or network work happens.
	ErrInvalidKey = errors.New("histstore: invalid storage key")
	// ErrExists reports a refused overwrite of a differing existing object
	// where the backend could prove the conflict cheaply.
	ErrExists = errors.New("histstore: object already exists")
)

// ObjectID is the full logical identity of one stored object. Physical keys
// embed every field, so two incarnations of the same digest can never
// collide and a delayed delete of incarnation N cannot remove N+1.
type ObjectID struct {
	Tenant      string
	Kind        string // "pft2" today; validated, never interpolated raw
	DigestHex   string // 64 lowercase hex chars (no "sha256:" prefix)
	Incarnation int64
}

// Validate checks every field against the same bounds the database enforces.
func (id ObjectID) Validate() error {
	if id.Tenant == "" || len(id.Tenant) > 256 {
		return fmt.Errorf("%w: tenant must be 1..256 chars", ErrInvalidKey)
	}
	if id.Kind != "pft2" {
		return fmt.Errorf("%w: object kind %q is unknown", ErrInvalidKey, id.Kind)
	}
	if !isLowerHex64(id.DigestHex) {
		return fmt.Errorf("%w: digest must be 64 lowercase hex chars", ErrInvalidKey)
	}
	if id.Incarnation < 1 {
		return fmt.Errorf("%w: incarnation must be >= 1", ErrInvalidKey)
	}
	return nil
}

// Key derives the exact relative storage key for this identity. The caller
// records the store's fully prefixed form (Store.ExactKey) in the database
// and never re-derives it for reads.
func (id ObjectID) Key() (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("t/%s/%s/sha256/%s/%s/i%d",
		EscapeComponent(id.Tenant), id.Kind,
		id.DigestHex[:2], id.DigestHex, id.Incarnation), nil
}

// EscapeComponent maps an arbitrary identity string (for example a tenant
// id) onto one safe key path component: bytes outside [A-Za-z0-9._-] are
// percent-encoded (uppercase hex), '%' itself included, so the mapping is
// injective and the result never contains '/', NUL, or dot-only names.
func EscapeComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || !isSafeKeyByte(c) {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	out := b.String()
	// "." and ".." are valid outputs of the byte filter but invalid path
	// components; encode the leading dot to keep the mapping injective.
	if out == "." || out == ".." {
		out = "%2E" + out[1:]
	}
	return out
}

func isSafeKeyByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// maxKeyBytes matches the database's storage_key CHECK bound.
const maxKeyBytes = 1024

// ValidateKey enforces the strict shape of every key this package touches:
// bounded length, slash-separated components, each component non-empty, not
// "." or "..", and drawn from the safe byte set (letters, digits, "._-",
// and '%' from escaping). Backends call this before ANY path or URL work,
// so path traversal is rejected structurally, not by the OS.
func ValidateKey(key string) error {
	if key == "" || len(key) > maxKeyBytes {
		return fmt.Errorf("%w: key must be 1..%d bytes", ErrInvalidKey, maxKeyBytes)
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return fmt.Errorf("%w: key must not begin or end with '/'", ErrInvalidKey)
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" {
			return fmt.Errorf("%w: key contains an empty component", ErrInvalidKey)
		}
		if part == "." || part == ".." {
			return fmt.Errorf("%w: key contains a dot path component", ErrInvalidKey)
		}
		for i := 0; i < len(part); i++ {
			if c := part[i]; c != '%' && !isSafeKeyByte(c) {
				return fmt.Errorf("%w: key byte %q is outside the safe set", ErrInvalidKey, c)
			}
		}
	}
	return nil
}

// JoinPrefix joins a validated configured prefix with a relative key.
// Prefixes are optional; when present they follow the same component rules.
func JoinPrefix(prefix, key string) (string, error) {
	if prefix == "" {
		return key, nil
	}
	joined := prefix + "/" + key
	if err := ValidateKey(joined); err != nil {
		return "", err
	}
	return joined, nil
}
