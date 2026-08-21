package volumeserver

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const visibilityMembershipHeader = "PFS-VISIBILITY-1"

// FileVisibilityMembership is the small durable control-plane record that
// survives authority-process loss. It is bound to one volume and contains only
// strict session IDs, never filesystem metadata or contents. The manager must
// prove old hosts/mounts fenced before it asks OpenFileVisibilityMembership to
// clear old records.
type FileVisibilityMembership struct {
	mu           sync.Mutex
	path         string
	volumeID     string
	lockFile     *os.File
	active       map[SessionID]struct{}
	cleared      []SessionID
	quiesceNonce string
	quiesceProof func() error
	proofWritten bool
}

// visibilityMembershipAuditSuffix names the append-only record of operator
// assertions. -prior-strict-mounts-fenced is an unverified human claim that
// every recorded kernel mount was made unusable, and it is the one input that
// can erase this authority's memory of an unsafe mount. It stays explicit and
// human-driven, but it stops being invisible: what was cleared, for which
// volume, and when is written down before the record it clears is rewritten.
const visibilityMembershipAuditSuffix = ".audit"

// OpenFileVisibilityMembership takes an exclusive process lock and loads the
// exact active set. If priorFenced is true, the caller asserts it has already
// made every recorded old kernel mount unusable; only then are records cleared.
func OpenFileVisibilityMembership(path, volumeID string, priorFenced bool) (*FileVisibilityMembership, PriorEpochDisposition, error) {
	if !filepath.IsAbs(path) {
		return nil, PriorEpochUnproven, errors.New("volumeserver: visibility membership path must be absolute")
	}
	if volumeID == "" || len(volumeID) > 1024 {
		return nil, PriorEpochUnproven, errors.New("volumeserver: visibility membership volume ID is invalid")
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, PriorEpochUnproven, errors.New("volumeserver: visibility membership directory must exist and be private")
	}
	lockFile, err := lockVisibilityFile(path + ".lock")
	if err != nil {
		return nil, PriorEpochUnproven, err
	}
	m := &FileVisibilityMembership{path: path, volumeID: volumeID, lockFile: lockFile, active: make(map[SessionID]struct{})}
	closeOnError := func(err error) (*FileVisibilityMembership, PriorEpochDisposition, error) {
		_ = m.Close()
		return nil, PriorEpochUnproven, err
	}
	if err := m.load(); err != nil {
		return closeOnError(err)
	}
	if len(m.active) != 0 && priorFenced {
		cleared := sortedSessionIDs(m.active)
		if err := m.auditOperatorClearLocked(cleared); err != nil {
			return closeOnError(err)
		}
		m.active = make(map[SessionID]struct{})
		if err := m.persistLocked(); err != nil {
			return closeOnError(err)
		}
		m.cleared = cleared
	}
	disposition := PriorEpochStrictMountsFenced
	if len(m.active) != 0 {
		disposition = PriorEpochUnproven
	}
	return m, disposition, nil
}

// ClearedByOperatorAssertion reports the exact strict mounts this process
// forgot because an operator asserted they were fenced. It is never empty
// without a matching durable audit record.
func (m *FileVisibilityMembership) ClearedByOperatorAssertion() []SessionID {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SessionID(nil), m.cleared...)
}

// auditOperatorClearLocked appends and fsyncs the assertion record before the
// membership file is rewritten, so a crash between the two leaves evidence of
// the claim rather than a silently emptied record.
func (m *FileVisibilityMembership) auditOperatorClearLocked(cleared []SessionID) error {
	path := m.path + visibilityMembershipAuditSuffix
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open visibility membership audit: %w", err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, id := range cleared {
		if _, err := fmt.Fprintf(writer, "%s\tprior-strict-mounts-fenced\t%s\t%s\n",
			time.Now().UTC().Format(time.RFC3339Nano), hex.EncodeToString([]byte(m.volumeID)), hex.EncodeToString(id[:])); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return file.Sync()
}

func sortedSessionIDs(set map[SessionID]struct{}) []SessionID {
	ids := make([]SessionID, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	return ids
}

func (m *FileVisibilityMembership) Activate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockFile == nil {
		return errors.New("volumeserver: visibility membership is closed")
	}
	if m.quiesceNonce != "" {
		return ErrQuiescing
	}
	if _, exists := m.active[id]; exists {
		return nil
	}
	m.active[id] = struct{}{}
	if err := m.persistLocked(); err != nil {
		delete(m.active, id)
		return err
	}
	return nil
}

func (m *FileVisibilityMembership) Deactivate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockFile == nil {
		return errors.New("volumeserver: visibility membership is closed")
	}
	if _, exists := m.active[id]; !exists {
		return nil
	}
	delete(m.active, id)
	if err := m.persistLocked(); err != nil {
		m.active[id] = struct{}{}
		return err
	}
	if len(m.active) == 0 && m.quiesceNonce != "" && !m.proofWritten {
		if err := m.quiesceProof(); err != nil {
			return fmt.Errorf("write quiesce proof: %w", err)
		}
		m.proofWritten = true
	}
	return nil
}

// SetQuiescing closes strict-attach admission and, under the same mutex that
// serializes Activate and Deactivate, writes proof once the durable active set
// is empty. A new nonce replaces a stale proof obligation. An empty nonce
// reopens admission after a cancelled archive attempt.
func (m *FileVisibilityMembership) SetQuiescing(nonce string, writeProof func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockFile == nil {
		return errors.New("volumeserver: visibility membership is closed")
	}
	if nonce == "" {
		m.quiesceNonce, m.quiesceProof, m.proofWritten = "", nil, false
		return nil
	}
	if writeProof == nil {
		return errors.New("volumeserver: quiesce proof writer is required")
	}
	if nonce != m.quiesceNonce {
		m.quiesceNonce, m.quiesceProof, m.proofWritten = nonce, writeProof, false
	}
	if len(m.active) == 0 && !m.proofWritten {
		if err := m.quiesceProof(); err != nil {
			return fmt.Errorf("write quiesce proof: %w", err)
		}
		m.proofWritten = true
	}
	return nil
}

func (m *FileVisibilityMembership) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lockFile == nil {
		return nil
	}
	err := unlockVisibilityFile(m.lockFile)
	m.lockFile = nil
	return err
}

func (m *FileVisibilityMembership) load() error {
	file, err := openVisibilityMembership(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("open visibility membership: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("volumeserver: visibility membership must be a private regular file")
	}
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() || scanner.Text() != visibilityMembershipHeader {
		return errors.New("volumeserver: invalid visibility membership header")
	}
	if !scanner.Scan() || scanner.Text() != hex.EncodeToString([]byte(m.volumeID)) {
		return errors.New("volumeserver: visibility membership belongs to a different volume")
	}
	for scanner.Scan() {
		raw, err := hex.DecodeString(scanner.Text())
		if err != nil || len(raw) != len(SessionID{}) {
			return errors.New("volumeserver: invalid visibility membership record")
		}
		var id SessionID
		copy(id[:], raw)
		if id == (SessionID{}) {
			return errors.New("volumeserver: zero visibility membership record")
		}
		if _, duplicate := m.active[id]; duplicate {
			return errors.New("volumeserver: duplicate visibility membership record")
		}
		m.active[id] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (m *FileVisibilityMembership) persistLocked() error {
	ids := sortedSessionIDs(m.active)
	dir := filepath.Dir(m.path)
	temp, err := os.CreateTemp(dir, ".portablefs-visibility-*")
	if err != nil {
		return fmt.Errorf("create visibility membership temp file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := func() { _ = temp.Close(); _ = os.Remove(tempPath) }
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	writer := bufio.NewWriter(temp)
	if _, err := fmt.Fprintln(writer, visibilityMembershipHeader); err != nil {
		cleanup()
		return err
	}
	if _, err := fmt.Fprintln(writer, hex.EncodeToString([]byte(m.volumeID))); err != nil {
		cleanup()
		return err
	}
	for _, id := range ids {
		if _, err := fmt.Fprintln(writer, hex.EncodeToString(id[:])); err != nil {
			cleanup()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		cleanup()
		return err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, m.path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}
