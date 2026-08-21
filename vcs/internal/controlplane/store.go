package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	storeMagic              = "PFSMGR1\n"
	maxStoreRecord          = 64 << 20
	compactEvery            = 256
	receiptRetentionSeconds = int64(24 * 60 * 60)
)

type storeEnvelope struct {
	Sequence     uint64 `json:"sequence"`
	PreviousHash string `json:"previous_sha256"`
	State        State  `json:"state"`
}

type rawStoreEnvelope struct {
	Sequence     uint64          `json:"sequence"`
	PreviousHash string          `json:"previous_sha256"`
	State        json.RawMessage `json:"state"`
}

type Store struct {
	mu       sync.Mutex
	file     *os.File
	lockFile *os.File
	path     string
	state    State
	sequence uint64
	lastHash [32]byte
}

func OpenStore(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: state path must be clean and absolute", ErrInvalid)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lockFile, err := openStoreLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("open manager state: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		_ = lockFile.Close()
		return nil, errors.New("open manager state returned no file")
	}
	fail := func(err error) (*Store, error) {
		_ = file.Close()
		_ = lockFile.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fail(errors.New("manager state must be a regular file unreadable by group and other users"))
	}
	store := &Store{file: file, lockFile: lockFile, path: path, state: NewState()}
	if info.Size() == 0 {
		if _, err := file.Write([]byte(storeMagic)); err != nil {
			return fail(err)
		}
		if err := file.Sync(); err != nil {
			return fail(err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return fail(err)
		}
		return store, nil
	}
	if err := store.load(); err != nil {
		return fail(err)
	}
	return store, nil
}

// openStoreLock holds an exclusive lock on a stable adjacent inode for the
// lifetime of the store. Locking the state file itself would be unsafe because
// compaction atomically replaces that inode, allowing a second process to lock
// and open the replacement while the first manager is still running.
func openStoreLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open manager state lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open manager state lock returned no file")
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat manager state lock: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fail(errors.New("manager state lock must be a regular file unreadable by group and other users"))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return fail(errors.New("manager state is already owned by another process"))
		}
		return fail(fmt.Errorf("lock manager state: %w", err))
	}
	return file, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result error
	if store.file != nil {
		result = store.file.Close()
		store.file = nil
	}
	if store.lockFile != nil {
		if err := store.lockFile.Close(); result == nil {
			result = err
		}
		store.lockFile = nil
	}
	return result
}

func (store *Store) load() error {
	legacyOnly, sawV2 := false, false
	sequence, checksum, err := readStoreChain(store.file, store.recoverTail, func(envelope rawStoreEnvelope) error {
		version, err := stateVersion(envelope.State)
		if err != nil {
			return err
		}
		switch version {
		case StateSchemaVersion:
			if legacyOnly {
				return errors.New("manager state hash chain mixes schema versions")
			}
			sawV2 = true
			state, err := decodeStrict[State](envelope.State)
			if err != nil {
				return fmt.Errorf("decode manager state: %w", err)
			}
			if err := state.Validate(); err != nil {
				return fmt.Errorf("validate manager state: %w", err)
			}
			store.state = state
		case 1:
			if sawV2 {
				return errors.New("manager state hash chain mixes schema versions")
			}
			state, err := decodeStrict[stateV1](envelope.State)
			if err != nil {
				return fmt.Errorf("decode v1 manager state: %w", err)
			}
			if err := state.Validate(); err != nil {
				return fmt.Errorf("validate v1 manager state: %w", err)
			}
			legacyOnly = true
		default:
			return fmt.Errorf("manager state schema version %d is unsupported", version)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if legacyOnly {
		return errors.New("manager state schema v1 requires `portablefs-manager migrate-state -from <v1> -to <v2>`")
	}
	store.sequence, store.lastHash = sequence, checksum
	_, err = store.file.Seek(0, io.SeekEnd)
	return err
}

func readStoreChain(file *os.File, recoverTail func(int64) error, visit func(rawStoreEnvelope) error) (uint64, [32]byte, error) {
	magic := make([]byte, len(storeMagic))
	if _, err := file.ReadAt(magic, 0); err != nil || string(magic) != storeMagic {
		return 0, [32]byte{}, errors.New("manager state has an invalid format header")
	}
	offset := int64(len(storeMagic))
	var sequence uint64
	var lastHash [32]byte
	for {
		var lengthRaw [4]byte
		n, err := file.ReadAt(lengthRaw[:], offset)
		if errors.Is(err, io.EOF) && n == 0 {
			break
		}
		if err != nil || n != len(lengthRaw) {
			if recoverTail != nil {
				return sequence, lastHash, recoverTail(offset)
			}
			return 0, [32]byte{}, errors.New("manager state has a torn record tail")
		}
		length := binary.BigEndian.Uint32(lengthRaw[:])
		if length == 0 || length > maxStoreRecord {
			return 0, [32]byte{}, errors.New("manager state record length is invalid")
		}
		payload := make([]byte, length)
		if n, err := file.ReadAt(payload, offset+4); err != nil || n != len(payload) {
			if recoverTail != nil {
				return sequence, lastHash, recoverTail(offset)
			}
			return 0, [32]byte{}, errors.New("manager state has a torn record tail")
		}
		var checksum [32]byte
		if n, err := file.ReadAt(checksum[:], offset+4+int64(length)); err != nil || n != len(checksum) {
			if recoverTail != nil {
				return sequence, lastHash, recoverTail(offset)
			}
			return 0, [32]byte{}, errors.New("manager state has a torn record tail")
		}
		actual := sha256.Sum256(payload)
		if !bytes.Equal(actual[:], checksum[:]) {
			return 0, [32]byte{}, errors.New("manager state record checksum mismatch")
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		var envelope rawStoreEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			return 0, [32]byte{}, fmt.Errorf("decode manager state: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return 0, [32]byte{}, errors.New("manager state record has trailing JSON")
		}
		if envelope.Sequence != sequence+1 || envelope.PreviousHash != hex.EncodeToString(lastHash[:]) {
			return 0, [32]byte{}, errors.New("manager state hash chain is discontinuous")
		}
		if err := visit(envelope); err != nil {
			return 0, [32]byte{}, err
		}
		sequence = envelope.Sequence
		lastHash = checksum
		offset += 4 + int64(length) + int64(len(checksum))
	}
	return sequence, lastHash, nil
}

func (store *Store) recoverTail(offset int64) error {
	if err := store.file.Truncate(offset); err != nil {
		return fmt.Errorf("truncate torn manager state tail: %w", err)
	}
	if err := store.file.Sync(); err != nil {
		return fmt.Errorf("sync recovered manager state: %w", err)
	}
	_, err := store.file.Seek(0, io.SeekEnd)
	return err
}

// Transact durably records the resulting complete control state before
// publishing it in memory. An exact idempotency replay returns the original
// response bytes; reusing a key for any other operation or request is refused.
// Receipts are retained for 24 hours so the durable state has a fixed bound.
func (store *Store) Transact(requestID, operation string, request any, now int64, apply func(*State) (any, error)) (json.RawMessage, bool, error) {
	if !validIdentity(requestID) || !validIdentity(operation) || now <= 0 || apply == nil {
		return nil, false, ErrInvalid
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, false, err
	}
	requestHash := sha256.Sum256(requestBytes)
	requestHex := hex.EncodeToString(requestHash[:])
	return store.transact(requestID, operation, requestHex, now, true, func(state *State) (any, bool, error) {
		response, err := apply(state)
		return response, true, err
	})
}

// TransactNatural durably applies an operation whose exact idempotency boundary
// lives in the state it mutates. It deliberately creates no generic receipt.
// Mount refreshes use this because each enrollment retains exactly one current
// (session, sequence, request digest, response) tuple; retaining a second full
// response per sequence would make healthy periodic renewal grow state forever.
func (store *Store) TransactNatural(operation string, now int64, apply func(*State) (any, bool, error)) (json.RawMessage, error) {
	if !validIdentity(operation) || now <= 0 || apply == nil {
		return nil, ErrInvalid
	}
	raw, _, err := store.transact("", operation, "", now, false, apply)
	return raw, err
}

func (store *Store) transact(requestID, operation, requestHex string, now int64, recordReceipt bool, apply func(*State) (any, bool, error)) (json.RawMessage, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.file == nil {
		return nil, false, os.ErrClosed
	}
	if recordReceipt {
		if receipt, exists := store.state.Receipts[requestID]; exists && receipt.CreatedUnix >= now-receiptRetentionSeconds {
			if receipt.Operation != operation || receipt.RequestHash != requestHex {
				return nil, false, ErrIdempotencyReuse
			}
			return append(json.RawMessage(nil), receipt.Response...), true, nil
		}
	}
	next, err := cloneState(store.state)
	if err != nil {
		return nil, false, err
	}
	stateChanged := false
	for id, receipt := range next.Receipts {
		if receipt.CreatedUnix < now-receiptRetentionSeconds {
			delete(next.Receipts, id)
			stateChanged = true
		}
	}
	response, applied, err := apply(&next)
	if err != nil {
		return nil, false, err
	}
	stateChanged = stateChanged || applied
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, false, err
	}
	if recordReceipt {
		next.Receipts[requestID] = Receipt{Operation: operation, RequestHash: requestHex, Response: responseBytes, CreatedUnix: now}
		stateChanged = true
	}
	if !stateChanged {
		return append(json.RawMessage(nil), responseBytes...), false, nil
	}
	if err := next.Validate(); err != nil {
		return nil, false, err
	}
	envelope := storeEnvelope{Sequence: store.sequence + 1, PreviousHash: hex.EncodeToString(store.lastHash[:]), State: next}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if len(payload) > maxStoreRecord {
		return nil, false, errors.New("manager state exceeds the v2 record bound")
	}
	checksum := sha256.Sum256(payload)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, err := store.file.Write(length[:]); err != nil {
		return nil, false, err
	}
	if _, err := store.file.Write(payload); err != nil {
		return nil, false, err
	}
	if _, err := store.file.Write(checksum[:]); err != nil {
		return nil, false, err
	}
	if err := store.file.Sync(); err != nil {
		return nil, false, err
	}
	store.sequence++
	store.lastHash = checksum
	store.state = next
	if store.sequence >= compactEvery {
		if err := store.compactLocked(); err != nil {
			return nil, false, fmt.Errorf("compact manager state: %w", err)
		}
	}
	return append(json.RawMessage(nil), responseBytes...), false, nil
}

// compactLocked replaces a long hash-chain prefix with one checksummed full
// snapshot. The rename is atomic and the snapshot already includes the exact
// idempotency receipt for the transaction that triggered compaction.
func (store *Store) compactLocked() error {
	record, checksum, err := snapshotRecord(store.state)
	if err != nil {
		return err
	}
	directoryPath := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directoryPath, ".portablefs-manager-compact-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	installed := false
	cleanup := func() {
		if !installed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(record); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if _, err := temporary.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	old := store.file
	store.file = temporary
	installed = true
	store.sequence = 1
	store.lastHash = checksum
	_ = old.Close()
	if err := syncDirectory(directoryPath); err != nil {
		return err
	}
	return nil
}

func snapshotRecord(state State) ([]byte, [32]byte, error) {
	envelope := storeEnvelope{Sequence: 1, PreviousHash: hex.EncodeToString(make([]byte, sha256.Size)), State: state}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(payload) > maxStoreRecord {
		return nil, [32]byte{}, errors.New("manager state exceeds the v2 record bound")
	}
	checksum := sha256.Sum256(payload)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	record := make([]byte, 0, len(storeMagic)+len(length)+len(payload)+len(checksum))
	record = append(record, storeMagic...)
	record = append(record, length[:]...)
	record = append(record, payload...)
	record = append(record, checksum[:]...)
	return record, checksum, nil
}

func stateVersion(raw json.RawMessage) (uint32, error) {
	var header struct {
		SchemaVersion uint32 `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.SchemaVersion == 0 {
		return 0, errors.New("manager state has no valid schema_version")
	}
	return header.SchemaVersion, nil
}

// StateFileVersion validates a complete manager-state hash chain and reports
// its one schema version. Activation uses this while the Manager is stopped so
// the v1-to-v2 cutover is explicit and cannot race a writer.
func StateFileVersion(path string) (uint32, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, fmt.Errorf("%w: manager state path must be clean and absolute", ErrInvalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open manager state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, errors.New("manager state must be a regular file")
	}
	var schema uint32
	_, _, err = readStoreChain(file, nil, func(envelope rawStoreEnvelope) error {
		version, err := stateVersion(envelope.State)
		if err != nil {
			return err
		}
		if schema != 0 && schema != version {
			return errors.New("manager state hash chain mixes schema versions")
		}
		switch version {
		case 1:
			state, err := decodeStrict[stateV1](envelope.State)
			if err != nil {
				return fmt.Errorf("decode v1 manager state: %w", err)
			}
			if err := state.Validate(); err != nil {
				return fmt.Errorf("validate v1 manager state: %w", err)
			}
		case StateSchemaVersion:
			state, err := decodeStrict[State](envelope.State)
			if err != nil {
				return fmt.Errorf("decode manager state: %w", err)
			}
			if err := state.Validate(); err != nil {
				return fmt.Errorf("validate manager state: %w", err)
			}
		default:
			return fmt.Errorf("manager state schema version %d is unsupported", version)
		}
		schema = version
		return nil
	})
	if err != nil {
		return 0, err
	}
	if schema == 0 {
		return 0, errors.New("manager state contains no snapshot records")
	}
	return schema, nil
}

func decodeStrict[T any](raw []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, errors.New("trailing JSON")
	}
	return value, nil
}

// MigrateStateV1ToV2 validates the complete v1 hash chain and writes one fresh
// compacted v2 snapshot. The source is opened read-only and is never modified.
func MigrateStateV1ToV2(v1Path, v2Path string) error {
	if !filepath.IsAbs(v1Path) || filepath.Clean(v1Path) != v1Path || !filepath.IsAbs(v2Path) || filepath.Clean(v2Path) != v2Path || v1Path == v2Path {
		return fmt.Errorf("%w: migration paths must be distinct, clean, and absolute", ErrInvalid)
	}
	source, err := os.Open(v1Path)
	if err != nil {
		return fmt.Errorf("open v1 manager state: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("v1 manager state must be a regular file")
	}
	var legacy stateV1
	count := 0
	_, _, err = readStoreChain(source, nil, func(envelope rawStoreEnvelope) error {
		version, err := stateVersion(envelope.State)
		if err != nil {
			return err
		}
		if version != 1 {
			return fmt.Errorf("migration source schema is %d, want 1", version)
		}
		decoded, err := decodeStrict[stateV1](envelope.State)
		if err != nil {
			return fmt.Errorf("decode v1 manager state: %w", err)
		}
		if err := decoded.Validate(); err != nil {
			return fmt.Errorf("validate v1 manager state: %w", err)
		}
		legacy = decoded
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("v1 manager state contains no snapshot records")
	}
	state := migrateV1State(legacy)
	if err := state.Validate(); err != nil {
		return fmt.Errorf("validate migrated v2 manager state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(v2Path), 0o700); err != nil {
		return fmt.Errorf("create v2 state directory: %w", err)
	}
	if _, err := os.Lstat(v2Path); err == nil {
		return fmt.Errorf("v2 manager state already exists: %s", v2Path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	record, _, err := snapshotRecord(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(v2Path), ".portablefs-manager-migrate-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(record); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, v2Path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("v2 manager state already exists: %s", v2Path)
		}
		return fmt.Errorf("install migrated v2 manager state: %w", err)
	}
	if err := syncDirectory(filepath.Dir(v2Path)); err != nil {
		return err
	}
	return nil
}

func migrateV1State(old stateV1) State {
	state := NewState()
	state.Receipts = old.Receipts
	state.AuthorizationNonces = old.AuthorizationNonces
	state.MountEnrollments = old.MountEnrollments
	state.MountAuthorizationContexts = old.MountAuthorizationContexts
	state.RenewalFences = old.RenewalFences
	for id, oldCell := range old.Cells {
		state.Cells[id] = Cell{ID: oldCell.ID, AvailabilityZone: oldCell.AvailabilityZone, AuthorityHost: oldCell.AuthorityHost,
			AuthorityDNSZone: oldCell.AuthorityDNSZone, CapacityBytes: oldCell.CapacityBytes, CapacityInodes: oldCell.CapacityInodes, Pool: PoolProduct,
			NextProjectID: oldCell.NextProjectID, NextServiceUID: oldCell.NextServiceUID, NextPort: oldCell.NextPort,
			PlanGeneration: oldCell.PlanGeneration, PlanReleaseID: oldCell.PlanReleaseID, PlanIssuedUnix: oldCell.PlanIssuedUnix,
			PlanExpiresUnix: oldCell.PlanExpiresUnix, LastObservedUnix: oldCell.LastObservedUnix, LastManagerRelease: oldCell.LastManagerRelease,
			LastAgentRelease: oldCell.LastAgentRelease, LastHelperRelease: oldCell.LastHelperRelease, Health: oldCell.Health, QuarantineReason: oldCell.QuarantineReason}
	}
	for id, oldVolume := range old.Volumes {
		volumeState := oldVolume.State
		archiveCycleStep := ""
		deletionRequested := false
		if oldVolume.State == legacyVolumeRetired {
			// v1 RETIRED merely stopped serving and retained the placement
			// forever. v2 has one deletion path with destroy and release proofs,
			// so an old retired placement resumes directly at host-data destroy:
			// its authority was already removed by the v1 RETIRE phase.
			volumeState = VolumeDestroying
			archiveCycleStep = "destroying"
			deletionRequested = true
		}
		state.Volumes[id] = Volume{ID: oldVolume.ID, AuthorizationDomain: oldVolume.AuthorizationDomain, Owner: oldVolume.Owner,
			ProductIssuer: oldVolume.ProductIssuer, ProductPublicKeyPEM: oldVolume.ProductPublicKeyPEM, QuotaBytes: oldVolume.QuotaBytes,
			QuotaInodes: oldVolume.QuotaInodes, AuthorityEpoch: oldVolume.AuthorityGeneration, PlacementSequence: 1, State: volumeState, Pool: PoolProduct,
			Placement: &Placement{CellID: oldVolume.CellID, Sequence: 1, ProjectID: oldVolume.ProjectID, ServiceUID: oldVolume.ServiceUID,
				ServiceGID: oldVolume.ServiceGID, ListenPort: oldVolume.ListenPort, AuthorityID: oldVolume.AuthorityID,
				AuthorityServerName: oldVolume.AuthorityServerName, AuthorityCSRPEM: oldVolume.AuthorityCSRPEM,
				AuthorityCertificatePEM: oldVolume.AuthorityCertificate, AuthorityCertExpires: oldVolume.AuthorityCertExpires,
				PriorStrictFenced: oldVolume.PriorStrictFenced, StrictFenceEvidence: oldVolume.StrictFenceEvidence,
				CreatedUnix: oldVolume.CreatedUnix, LastObservedUnix: oldVolume.LastObservedUnix},
			ArchiveCycleStep: archiveCycleStep, DeletionRequested: deletionRequested,
			QuarantineReason: oldVolume.QuarantineReason, CreatedUnix: oldVolume.CreatedUnix, UpdatedUnix: oldVolume.UpdatedUnix}
		if deletionRequested {
			terminateVolumeEnrollments(&state, id, "legacy retired volume cleanup", oldVolume.UpdatedUnix)
		}
	}
	return state
}

func (store *Store) View(read func(State) error) error {
	if read == nil {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	copy, err := cloneState(store.state)
	if err != nil {
		return err
	}
	return read(copy)
}

func cloneState(state State) (State, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return State{}, err
	}
	var clone State
	if err := json.Unmarshal(raw, &clone); err != nil {
		return State{}, err
	}
	return clone, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
