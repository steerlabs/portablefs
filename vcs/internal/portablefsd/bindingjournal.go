package portablefsd

// The binding journal makes item-identity durability O(changes) instead of
// O(table). Every operation's binding transaction — minted items, detaches,
// reclaims, and subtree rekeys together — appends one JSON line before the
// operation replies, and the debounced
// full-state persist doubles as compaction that truncates it. The previous
// design rewrote and fsynced the ENTIRE state file (every attach's whole item
// table) synchronously inside every lookup/enumerate/create/write that touched
// an item, which grew quadratically over workloads like git clone.
//
// Appends are deliberately not fsynced: bindings must outlive the daemon
// PROCESS (the kernel and extension keep presenting old item IDs across a
// daemon crash and restart), but a machine crash takes the kernel's item cache
// down with the mount, so machine-grade durability buys nothing. An un-fsynced
// write(2) is visible to the next process after SIGKILL, which is exactly the
// required strength; a torn trailing line after a machine crash is skipped at
// load, where the state file remains authoritative.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const bindingJournalName = "items.journal"

type bindingJournalEntry struct {
	Ref             string `json:"ref"`
	Op              string `json:"op"` // bind | unbind | detach | reclaim | rekey
	Path            string `json:"path,omitempty"`
	ID              uint64 `json:"id,omitempty"`
	Gen             uint64 `json:"gen,omitempty"`
	Auth            bool   `json:"auth,omitempty"`
	AuthorityItemID uint64 `json:"authorityItemId,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Graft           bool   `json:"graft,omitempty"`
	From            string `json:"from,omitempty"` // rekey: old path prefix
	To              string `json:"to,omitempty"`   // rekey: new path prefix
}

type bindingJournalBatch struct {
	Entries []bindingJournalEntry `json:"entries"`
}

func (e bindingJournalEntry) authorityItemID() uint64 {
	if e.AuthorityItemID != 0 {
		return e.AuthorityItemID
	}
	if e.Auth {
		return e.ID
	}
	return 0
}

type bindingJournal struct {
	mu   sync.Mutex
	path string
	dir  string
	f    *os.File
	// testWrite injects short writes and terminal errors. Protected by mu.
	testWrite func([]byte) (int, error)
}

func newBindingJournal(stateDir string) *bindingJournal {
	return &bindingJournal{path: filepath.Join(stateDir, bindingJournalName), dir: stateDir}
}

// append writes complete JSON lines before an Item identity may be published
// to FSKit. The mount and its cached Items can survive a daemon restart, so a
// failed or short process-durable append is a correctness failure—not a
// best-effort diagnostic.
func (j *bindingJournal) append(entries []bindingJournalEntry) error {
	if len(entries) == 0 {
		return nil
	}
	b, err := json.Marshal(bindingJournalBatch{Entries: entries})
	if err != nil {
		return fmt.Errorf("encode binding journal transaction: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(b)
	buf.WriteByte('\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil && j.testWrite == nil {
		if err := os.MkdirAll(j.dir, 0o700); err != nil {
			return fmt.Errorf("binding journal dir: %w", err)
		}
		f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open binding journal: %w", err)
		}
		j.f = f
	}
	data := buf.Bytes()
	for len(data) > 0 {
		var n int
		var err error
		if j.testWrite != nil {
			n, err = j.testWrite(data)
		} else {
			n, err = j.f.Write(data)
		}
		if n < 0 || n > len(data) {
			return fmt.Errorf("append binding journal: invalid write count %d", n)
		}
		data = data[n:]
		if err != nil {
			return fmt.Errorf("append binding journal: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("append binding journal: %w", io.ErrShortWrite)
		}
	}
	return nil
}

// truncateLocked drops the journal after a successful full-state persist has
// captured everything it recorded. Caller holds j.mu (the persist holds it
// across snapshot+write+truncate so a racing append can never be truncated
// away while its binding missed the snapshot).
func (j *bindingJournal) truncateLocked() {
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	_ = os.Remove(j.path)
}

// loadBindingJournal reads the journal left by a previous daemon process,
// tolerating a torn trailing line.
func loadBindingJournal(stateDir string) []bindingJournalEntry {
	data, err := os.ReadFile(filepath.Join(stateDir, bindingJournalName))
	if err != nil {
		return nil
	}
	var out []bindingJournalEntry
	lines := bytes.Split(data, []byte("\n"))
	if len(data) != 0 && data[len(data)-1] != '\n' {
		// append emits one complete operation transaction per newline. A
		// trailing unterminated JSON value is a torn transaction even if the
		// JSON bytes themselves happen to be syntactically complete.
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var batch bindingJournalBatch
		if err := json.Unmarshal(line, &batch); err == nil && batch.Entries != nil {
			out = append(out, batch.Entries...)
			continue
		}
		// Legacy journals stored one entry per line. Keep accepting their
		// complete lines during the format transition.
		var e bindingJournalEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// validJournalPath rejects path shapes that could escape the volume namespace.
// Entries are daemon-written, so this only guards against corruption.
func validJournalPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return false
	}
	if p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return false
	}
	return true
}
