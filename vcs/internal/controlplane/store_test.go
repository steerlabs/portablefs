package controlplane

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateStateV1ToV2IsExplicitValidatedAndNonDestructive(t *testing.T) {
	directory := t.TempDir()
	from, to := filepath.Join(directory, "manager-v1.state"), filepath.Join(directory, "manager-v2.state")
	cellID := "11111111-1111-4111-8111-111111111111"
	volumeID := "22222222-2222-4222-8222-222222222222"
	endpoint := "v-22222222222242228222222222222222.cell.test"
	legacy := stateV1{SchemaVersion: 1, Cells: map[string]cellV1{}, Volumes: map[string]volumeV1{}, Receipts: map[string]Receipt{},
		AuthorizationNonces: map[string]AuthorizationNonce{}, MountEnrollments: map[string]MountEnrollment{},
		MountAuthorizationContexts: map[string]MountAuthorizationContext{}, RenewalFences: map[string]uint64{}}
	legacy.Cells[cellID] = cellV1{ID: cellID, AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, AllocatedBytes: 1 << 30, AllocatedInodes: 100_000,
		NextProjectID: 10001, NextServiceUID: 200001, NextPort: 20001, PlanGeneration: 1, PlanReleaseID: "v1-manager",
		PlanIssuedUnix: 100, PlanExpiresUnix: 200, Health: CellUnknown}
	legacy.Volumes[volumeID] = volumeV1{ID: volumeID, AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "product",
		ProductPublicKeyPEM: "product-key", CellID: cellID, QuotaBytes: 1 << 30, QuotaInodes: 100_000, ProjectID: 10000,
		ServiceUID: 200000, ServiceGID: 200000, ListenPort: 20000, AuthorityID: endpoint, AuthorityServerName: endpoint,
		AuthorityGeneration: 7, State: legacyVolumeRetired, CreatedUnix: 100, UpdatedUnix: 100}
	stateJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(rawStoreEnvelope{Sequence: 1, PreviousHash: strings.Repeat("0", 64), State: stateJSON})
	if err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(payload)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	bytes := append([]byte(storeMagic), length[:]...)
	bytes = append(bytes, payload...)
	bytes = append(bytes, checksum[:]...)
	if err := os.WriteFile(from, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	originalDigest := sha256.Sum256(bytes)
	if version, err := StateFileVersion(from); err != nil || version != 1 {
		t.Fatalf("StateFileVersion(v1) = %d, %v", version, err)
	}
	if store, err := OpenStore(from); store != nil || err == nil || !strings.Contains(err.Error(), "migrate-state") {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("OpenStore(v1) = %v, want migrate-state guidance", err)
	}
	if err := MigrateStateV1ToV2(from, to); err != nil {
		t.Fatal(err)
	}
	if version, err := StateFileVersion(to); err != nil || version != StateSchemaVersion {
		t.Fatalf("StateFileVersion(v2) = %d, %v", version, err)
	}
	if err := MigrateStateV1ToV2(from, to); err == nil {
		t.Fatal("migration overwrote an existing v2 target")
	}
	after, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(after); digest != originalDigest {
		t.Fatalf("v1 rollback artifact changed: %s != %s", hex.EncodeToString(digest[:]), hex.EncodeToString(originalDigest[:]))
	}
	store, err := OpenStore(to)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.View(func(state State) error {
		volume := state.Volumes[volumeID]
		if state.SchemaVersion != 2 || state.Cells[cellID].Pool != PoolProduct || volume.State != VolumeDestroying || volume.AuthorityEpoch != 7 ||
			volume.PlacementSequence != 1 || volume.Placement == nil || volume.Placement.Sequence != 1 || volume.Placement.AuthorityServerName != endpoint ||
			volume.Placement.UsedBytes != 0 || volume.Placement.PendingBytes != 0 || !volume.DeletionRequested || volume.ArchiveCycleStep != "destroying" {
			t.Fatalf("migrated state = %+v", state)
		}
		return state.Validate()
	}); err != nil {
		t.Fatal(err)
	}
}

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

func TestStoreCompactionAndReloadPreserveRenewalFenceHighWater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := renewalFenceKey("opensteer", "cloud-private-state:computer-1")
	if _, err := store.TransactNatural("seed-renewal-fence", 1, func(state *State) (any, bool, error) {
		if state.RenewalFences == nil {
			state.RenewalFences = make(map[string]uint64)
		}
		state.RenewalFences[key] = 17
		return RenewalFence{Scope: "cloud-private-state:computer-1", Epoch: 17}, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < compactEvery-1; index++ {
		requestID := fmt.Sprintf("compact-fence-%d", index)
		if _, _, err := store.Transact(requestID, "compact-fence-test", index, int64(index+2), func(*State) (any, error) {
			return index, nil
		}); err != nil {
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
	if err := reopened.View(func(state State) error {
		if got := state.RenewalFences[key]; got != 17 {
			t.Fatalf("reloaded renewal fence = %d, want 17", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
