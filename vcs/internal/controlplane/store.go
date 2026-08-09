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
	magic := make([]byte, len(storeMagic))
	if _, err := io.ReadFull(store.file, magic); err != nil || string(magic) != storeMagic {
		return errors.New("manager state has an invalid format header")
	}
	offset := int64(len(storeMagic))
	for {
		var lengthRaw [4]byte
		n, err := store.file.ReadAt(lengthRaw[:], offset)
		if errors.Is(err, io.EOF) && n == 0 {
			break
		}
		if err != nil || n != len(lengthRaw) {
			return store.recoverTail(offset)
		}
		length := binary.BigEndian.Uint32(lengthRaw[:])
		if length == 0 || length > maxStoreRecord {
			return errors.New("manager state record length is invalid")
		}
		payload := make([]byte, length)
		if n, err := store.file.ReadAt(payload, offset+4); err != nil || n != len(payload) {
			return store.recoverTail(offset)
		}
		var checksum [32]byte
		if n, err := store.file.ReadAt(checksum[:], offset+4+int64(length)); err != nil || n != len(checksum) {
			return store.recoverTail(offset)
		}
		actual := sha256.Sum256(payload)
		if !bytes.Equal(actual[:], checksum[:]) {
			return errors.New("manager state record checksum mismatch")
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		var envelope storeEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			return fmt.Errorf("decode manager state: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("manager state record has trailing JSON")
		}
		if envelope.Sequence != store.sequence+1 || envelope.PreviousHash != hex.EncodeToString(store.lastHash[:]) {
			return errors.New("manager state hash chain is discontinuous")
		}
		if err := envelope.State.Validate(); err != nil {
			return fmt.Errorf("validate manager state: %w", err)
		}
		store.sequence = envelope.Sequence
		store.lastHash = checksum
		store.state = envelope.State
		offset += 4 + int64(length) + int64(len(checksum))
	}
	_, err := store.file.Seek(0, io.SeekEnd)
	return err
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
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.file == nil {
		return nil, false, os.ErrClosed
	}
	if receipt, exists := store.state.Receipts[requestID]; exists && receipt.CreatedUnix >= now-receiptRetentionSeconds {
		if receipt.Operation != operation || receipt.RequestHash != requestHex {
			return nil, false, ErrIdempotencyReuse
		}
		return append(json.RawMessage(nil), receipt.Response...), true, nil
	}
	next, err := cloneState(store.state)
	if err != nil {
		return nil, false, err
	}
	for id, receipt := range next.Receipts {
		if receipt.CreatedUnix < now-receiptRetentionSeconds {
			delete(next.Receipts, id)
		}
	}
	response, err := apply(&next)
	if err != nil {
		return nil, false, err
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, false, err
	}
	next.Receipts[requestID] = Receipt{Operation: operation, RequestHash: requestHex, Response: responseBytes, CreatedUnix: now}
	if err := next.Validate(); err != nil {
		return nil, false, err
	}
	envelope := storeEnvelope{Sequence: store.sequence + 1, PreviousHash: hex.EncodeToString(store.lastHash[:]), State: next}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if len(payload) > maxStoreRecord {
		return nil, false, errors.New("manager state exceeds the v1 record bound")
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
	envelope := storeEnvelope{Sequence: 1, PreviousHash: hex.EncodeToString(make([]byte, sha256.Size)), State: store.state}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(payload) > maxStoreRecord {
		return errors.New("manager state exceeds the v1 record bound")
	}
	checksum := sha256.Sum256(payload)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
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
	for _, part := range [][]byte{[]byte(storeMagic), length[:], payload, checksum[:]} {
		if _, err := temporary.Write(part); err != nil {
			return err
		}
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
