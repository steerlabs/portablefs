package archivestore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxKeyBytes bounds a derived object key. S3 permits 1024 bytes; half of that
// is far beyond what this grammar can produce and leaves the bound obviously
// unreachable rather than marginally satisfied.
const MaxKeyBytes = 512

var (
	// uuidPattern matches the lowercase canonical UUID form, exactly as
	// cellplan validates volume and attempt identities.
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// objectPattern is the closed grammar for the last key component:
	// "manifest", "pack-000001", and nothing that could introduce a path
	// separator, a dot segment, or a character needing percent-encoding.
	objectPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// ManifestObjectName is the pinned last key component of an attempt's manifest
// object. It is the only entry point into an attempt: the archive is never
// listed.
const ManifestObjectName = "manifest"

// PackObjectName is the pinned last key component of pack object index. Keys
// are derived, never carried, so the writer (archiver), the reader (hydrator),
// and the independent verifier (archiveverify/Manager) MUST all derive from
// this one definition — three private spellings once let the verifier derive a
// key no archiver ever wrote, refusing every real archive. The zero-padded form
// satisfies objectPattern for every index the format allows (archive.MaxPacks).
func PackObjectName(index int) string { return fmt.Sprintf("pack-%06d", index) }

// KeyFor derives the one object key for an archive attempt's object:
//
//	<prefix>/<volumeID>/<epoch>-<attempt>/<object>
//
// Every component is validated; the derivation is total and injective, so two
// distinct identity tuples can never collide on a key, and no caller-supplied
// string can escape the pinned prefix. Attempt UUIDs are never reused, which
// is what makes every key an immutable create (identity-lifecycle §2).
func KeyFor(prefix, volumeID string, epoch uint64, attempt, object string) (string, error) {
	if err := validateKeyPrefix(prefix); err != nil {
		return "", err
	}
	if !uuidPattern.MatchString(volumeID) {
		return "", fmt.Errorf("%w: volume ID must be a lowercase canonical UUID", ErrInvalid)
	}
	if epoch == 0 {
		return "", fmt.Errorf("%w: sealed epoch must be non-zero", ErrInvalid)
	}
	if !uuidPattern.MatchString(attempt) {
		return "", fmt.Errorf("%w: attempt must be a lowercase canonical UUID", ErrInvalid)
	}
	if !objectPattern.MatchString(object) {
		return "", fmt.Errorf("%w: object name must match ^[a-z0-9-]{1,64}$", ErrInvalid)
	}
	var builder strings.Builder
	if prefix != "" {
		builder.WriteString(prefix)
		builder.WriteByte('/')
	}
	builder.WriteString(volumeID)
	builder.WriteByte('/')
	builder.WriteString(strconv.FormatUint(epoch, 10))
	builder.WriteByte('-')
	builder.WriteString(attempt)
	builder.WriteByte('/')
	builder.WriteString(object)
	key := builder.String()
	if len(key) > MaxKeyBytes {
		return "", fmt.Errorf("%w: derived key exceeds %d bytes", ErrInvalid, MaxKeyBytes)
	}
	return key, nil
}

// KeyFor derives a key under this client's root-pinned prefix.
func (c *Client) KeyFor(volumeID string, epoch uint64, attempt, object string) (string, error) {
	return KeyFor(c.config.KeyPrefix, volumeID, epoch, attempt, object)
}

// validateKey checks a key handed to an operation. Operations accept only keys
// this package could have derived, so a key from anywhere else — a manifest
// field, a plan, an operator argument — is refused at the boundary rather than
// percent-encoded into something the store would accept.
func validateKey(key string) error {
	if key == "" || len(key) > MaxKeyBytes {
		return fmt.Errorf("%w: key must be 1..%d bytes", ErrInvalid, MaxKeyBytes)
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return fmt.Errorf("%w: key must not begin or end with a slash", ErrInvalid)
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: key has an empty or relative segment", ErrInvalid)
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return fmt.Errorf("%w: key segment %q has a disallowed character", ErrInvalid, segment)
			}
		}
	}
	return nil
}
