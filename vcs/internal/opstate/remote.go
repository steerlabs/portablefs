package opstate

import (
	"encoding/json"
	"fmt"
)

// RemoteDocument is the versioned whole-document repository a remote
// OperationStore persists through (implemented by remotejournal against
// pfj.opstate). The document is the same versioned JSON contract as the local
// file; the version is the database's copy-on-write CAS counter.
//
// Store must be exact: it returns the new version only after a committed
// database transaction replaced version expectedVersion. A version conflict
// (a foreign writer moved the document) and an unresolvable outcome must both
// surface as errors — never a fabricated success.
type RemoteDocument interface {
	// Load returns the current document and its version. found=false with a
	// nil error is an absent document (fresh branch); version 0 then inserts.
	Load() (raw []byte, version int64, found bool, err error)
	// Store atomically replaces version expectedVersion (0 inserts) with raw
	// and returns the new version.
	Store(raw []byte, expectedVersion int64) (int64, error)
}

// OpenRemote loads and validates the remote operation-state document, giving
// production the exact semantics of the local file store — the same
// versioned JSON contract, the same validation, pruning, bounds, and
// non-forgetful receipt model — without ever creating a local file.
//
// A persistence failure through a RemoteDocument poisons the store: whether
// the copy-on-write transaction landed is no longer locally decidable, and a
// poisoned store fails every subsequent lifecycle decision closed until the
// process is replaced (cold start reloads the durable truth).
func OpenRemote(doc RemoteDocument) (*Store, error) {
	raw, version, found, err := doc.Load()
	if err != nil {
		return nil, fmt.Errorf("opstate: load remote document: %w", err)
	}
	s := &Store{
		path: "remote:pfj.opstate",
		st:   state{Version: CurrentVersion, Operations: []Operation{}},
	}
	currentVersion := version
	if !found {
		currentVersion = 0
	} else {
		if len(raw) > maxStoreBytes {
			return nil, fmt.Errorf("opstate: remote document is %d bytes (maximum %d)", len(raw), maxStoreBytes)
		}
		var st state
		if err := decodeStrict(raw, &st); err != nil {
			return nil, fmt.Errorf("opstate: decode remote document: %w", err)
		}
		if st.Operations == nil {
			st.Operations = []Operation{}
		}
		prune(&st, retentionTimestamp(&st))
		if err := st.validate(s.path); err != nil {
			return nil, err
		}
		s.st = st
	}
	s.persist = func(_ string, candidate *state) (targetReplaced bool, err error) {
		encoded, err := encodeState(candidate)
		if err != nil {
			return false, err
		}
		next, err := doc.Store(encoded, currentVersion)
		if err != nil {
			// The document may or may not have been replaced; fail closed.
			return true, err
		}
		currentVersion = next
		return true, nil
	}
	return s, nil
}

// encodeState marshals a state exactly like the local file writer (bounded,
// custom uint64-as-decimal-string codec via the state's MarshalJSON path).
func encodeState(candidate *state) ([]byte, error) {
	raw, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("opstate: encode: %w", err)
	}
	if len(raw)+1 > maxStoreBytes {
		return nil, fmt.Errorf("opstate: encoded state is %d bytes (maximum %d)", len(raw)+1, maxStoreBytes)
	}
	return raw, nil
}
