package controlplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRefusesASecondWriterAcrossCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager.state")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for sequence := 0; sequence < compactEvery; sequence++ {
		requestID := fmt.Sprintf("request-%d", sequence)
		if _, _, err := store.Transact(requestID, "test", sequence, int64(sequence+1), func(*State) (any, error) {
			return sequence, nil
		}); err != nil {
			t.Fatalf("transaction %d: %v", sequence, err)
		}
	}

	second, err := OpenStore(path)
	if second != nil {
		_ = second.Close()
		t.Fatal("second writer opened the compacted manager state")
	}
	if err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("second writer error = %v", err)
	}
}

func TestStoreReplaysExactReceiptAndRecoversTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).Unix()
	apply := func(state *State) (any, error) { return map[string]string{"result": "one"}, nil }
	first, replay, err := store.Transact("request-1", "test", map[string]string{"a": "b"}, now, apply)
	if err != nil || replay {
		t.Fatalf("first transaction = %s, %v, %v", first, replay, err)
	}
	second, replay, err := store.Transact("request-1", "test", map[string]string{"a": "b"}, now, func(*State) (any, error) {
		t.Fatal("exact receipt replay executed the mutation again")
		return nil, nil
	})
	if err != nil || !replay || string(first) != string(second) {
		t.Fatalf("replay = %s, %v, %v", second, replay, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	third, replay, err := reopened.Transact("request-1", "test", map[string]string{"a": "b"}, now, apply)
	if err != nil || !replay || string(first) != string(third) {
		t.Fatalf("recovered receipt = %s, %v, %v", third, replay, err)
	}
}

func TestStoreCompactsLongHashChainWithoutLosingReceipts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).Unix()
	for index := 0; index < compactEvery+40; index++ {
		id := fmt.Sprintf("request-%d", index)
		if _, _, err := store.Transact(id, "test", index, now+int64(index), func(*State) (any, error) { return index, nil }); err != nil {
			t.Fatalf("transaction %d: %v", index, err)
		}
	}
	if store.sequence >= compactEvery {
		t.Fatalf("store sequence %d was not compacted", store.sequence)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	lastID := fmt.Sprintf("request-%d", compactEvery+39)
	result, replay, err := reopened.Transact(lastID, "test", compactEvery+39, now, func(*State) (any, error) {
		t.Fatal("compaction lost an exact receipt")
		return nil, nil
	})
	if err != nil || !replay || string(result) != fmt.Sprint(compactEvery+39) {
		t.Fatalf("compacted replay = %s, %v, %v", result, replay, err)
	}
}

func TestStoreReceiptRetentionIsExactAndBounded(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1_900_000_000, 0).Unix()
	if _, replay, err := store.Transact("bounded", "test", "first", now, func(*State) (any, error) {
		return "first-result", nil
	}); err != nil || replay {
		t.Fatalf("initial transaction replay=%v err=%v", replay, err)
	}
	if _, _, err := store.Transact("bounded", "other", "changed", now+receiptRetentionSeconds, func(*State) (any, error) {
		return nil, nil
	}); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("receipt at the retention boundary was not protected: %v", err)
	}
	applied := false
	result, replay, err := store.Transact("bounded", "other", "changed", now+receiptRetentionSeconds+1, func(*State) (any, error) {
		applied = true
		return "new-result", nil
	})
	if err != nil || replay || !applied || string(result) != `"new-result"` {
		t.Fatalf("expired receipt result=%s replay=%v applied=%v err=%v", result, replay, applied, err)
	}
}
