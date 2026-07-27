package histstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Store is one failure domain's exact-key object surface. Every operation
// addresses a complete recorded key; no operation derives a location from a
// digest. Implementations must be safe for concurrent use.
type Store interface {
	// Domain is the operator-declared failure-domain identifier this store
	// was configured under (an attestation of independence, never derived
	// from endpoints).
	Domain() string

	// ExactKey returns the fully prefixed storage key for one object
	// identity — the exact string the caller records in the database copy
	// receipt and presents verbatim to every later Get/Head/Delete.
	ExactKey(id ObjectID) (string, error)

	// Put streams exactly size bytes to the exact key. digestHex is the
	// lowercase sha256 of those bytes (content addressing is proven by the
	// caller before Put and re-proven by read-after-write afterwards; S3
	// additionally signs the payload hash). Put never buffers the whole
	// object. An existing identical object makes Put a success.
	Put(ctx context.Context, key string, size int64, digestHex string, body io.Reader) error

	// Get opens the exact key for streaming reads. The returned size is the
	// stored byte count; the caller re-verifies size and digest over the
	// streamed bytes and must Close the reader.
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)

	// Head proves presence (with stored size) or returns ErrNotFound.
	Head(ctx context.Context, key string) (int64, error)

	// Delete removes the exact key. Deleting an absent key is success
	// (idempotent); callers separately prove absence with Head.
	Delete(ctx context.Context, key string) error
}

// ReadVerified streams the exact key, enforcing the expected size as a hard
// bound and proving the sha256 digest over the complete bytes before
// returning them. This is the ONLY way worker code turns a recorded key
// into trusted bytes.
func ReadVerified(ctx context.Context, store Store, key string, expectSize int64, expectDigestHex string) ([]byte, error) {
	if expectSize < 0 {
		return nil, fmt.Errorf("%w: negative expected size", ErrInvalidKey)
	}
	body, storedSize, err := store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if storedSize >= 0 && storedSize != expectSize {
		return nil, fmt.Errorf("histstore: %s/%s holds %d bytes, recorded size is %d",
			store.Domain(), key, storedSize, expectSize)
	}
	buf := make([]byte, 0, int(expectSize))
	limited := io.LimitReader(body, expectSize+1)
	chunk := make([]byte, 64<<10)
	hasher := sha256.New()
	for {
		n, readErr := limited.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			hasher.Write(chunk[:n])
			if int64(len(buf)) > expectSize {
				return nil, fmt.Errorf("histstore: %s/%s streamed beyond the recorded %d bytes",
					store.Domain(), key, expectSize)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("histstore: %s/%s read: %w", store.Domain(), key, readErr)
		}
	}
	if int64(len(buf)) != expectSize {
		return nil, fmt.Errorf("histstore: %s/%s streamed %d bytes, recorded size is %d (short read)",
			store.Domain(), key, len(buf), expectSize)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != expectDigestHex {
		return nil, fmt.Errorf("histstore: %s/%s content hash %s does not match recorded %s",
			store.Domain(), key, got, expectDigestHex)
	}
	return buf, nil
}

// VerifyStream streams the exact key WITHOUT retaining bytes (scrub): it
// proves size and digest over the complete stream with constant memory.
func VerifyStream(ctx context.Context, store Store, key string, expectSize int64, expectDigestHex string) error {
	if expectSize < 0 {
		return fmt.Errorf("%w: negative expected size", ErrInvalidKey)
	}
	body, storedSize, err := store.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	if storedSize >= 0 && storedSize != expectSize {
		return fmt.Errorf("histstore: %s/%s holds %d bytes, recorded size is %d",
			store.Domain(), key, storedSize, expectSize)
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(body, expectSize+1))
	if err != nil {
		return fmt.Errorf("histstore: %s/%s read: %w", store.Domain(), key, err)
	}
	if n != expectSize {
		return fmt.Errorf("histstore: %s/%s streamed %d bytes, recorded size is %d",
			store.Domain(), key, n, expectSize)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != expectDigestHex {
		return fmt.Errorf("histstore: %s/%s content hash %s does not match recorded %s",
			store.Domain(), key, got, expectDigestHex)
	}
	return nil
}
