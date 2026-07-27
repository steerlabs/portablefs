package pft2

import (
	"context"
	"sync"
)

// Fetcher retrieves the exact complete bytes of one immutable object by
// reference. Implementations (for example the replicated blob layer) must
// fail closed when no replica's bytes verify; the reader independently
// re-verifies size and digest on every fetch and never publishes unverified
// bytes.
type Fetcher interface {
	Fetch(ctx context.Context, ref Ref) ([]byte, error)
}

// MemoryStore is an in-memory object store implementing NodeSink, PackSink,
// and Fetcher. It is the reference store for tests, golden-vector
// construction, and small tools.
type MemoryStore struct {
	mu      sync.RWMutex
	objects map[Ref][]byte
}

// NewMemoryStore creates an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{objects: map[Ref][]byte{}}
}

// PutNode stores one encoded metadata node.
func (s *MemoryStore) PutNode(ref Ref, encoded []byte) error { return s.put(ref, encoded) }

// PutPack stores one packed data object.
func (s *MemoryStore) PutPack(ref Ref, data []byte) error { return s.put(ref, data) }

func (s *MemoryStore) put(ref Ref, data []byte) error {
	if err := VerifyObjectBytes(ref, data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[ref]; !exists {
		s.objects[ref] = append([]byte(nil), data...)
	}
	return nil
}

// Fetch returns the exact stored bytes, or ErrNotFound.
func (s *MemoryStore) Fetch(_ context.Context, ref Ref) ([]byte, error) {
	s.mu.RLock()
	data, ok := s.objects[ref]
	s.mu.RUnlock()
	if !ok {
		return nil, corruptf("object %s missing from store", ref.Hex())
	}
	return data, nil
}

// Len reports the number of stored objects.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.objects)
}
