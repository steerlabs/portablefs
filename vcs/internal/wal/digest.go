package wal

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// The digest-chain primitives the remote journal, the SQL layer, and the file
// WAL all agree on. The chain formula is pinned cross-language by golden
// vectors (digest_test.go here, journal.test.ts in metadata-db).

// ErrJournalDiverged reports a remote journal whose own state or record chain
// failed verification (corruption or a concurrent identity change). Callers
// fail closed without publishing anything.
var ErrJournalDiverged = errors.New("wal: durable journal state failed verification")

// ChainDigestBytes advances the WAL digest chain over one canonical payload:
// sha256(prev[32] || be64(len(payload)) || payload). It is recordDigest
// expressed over the opaque payload bytes, so a reader that only has the
// stored bytes (the journal service, or a replaying client) reproduces the
// identical chain.
func ChainDigestBytes(prev [32]byte, payload []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(prev[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(payload)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RecordHash is the zero-anchored canonical hash of one record (the identity
// used for exact-duplicate detection across the journal and the file WAL).
func RecordHash(r Record) ([32]byte, error) {
	return recordDigest([32]byte{}, r)
}
