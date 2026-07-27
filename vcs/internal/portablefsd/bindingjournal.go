package portablefsd

// The binding journal makes item-identity durability O(changes) instead of
// O(table). Every binding change — a minted item, an unbind, a subtree rekey —
// appends one JSON line before the operation replies, and the debounced
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
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const bindingJournalName = "items.journal"

type bindingJournalEntry struct {
	Ref  string `json:"ref"`
	Op   string `json:"op"` // bind | unbind | rekey
	Path string `json:"path,omitempty"`
	ID   uint64 `json:"id,omitempty"`
	Gen  uint64 `json:"gen,omitempty"`
	Auth bool   `json:"auth,omitempty"`
	From string `json:"from,omitempty"` // rekey: old path prefix
	To   string `json:"to,omitempty"`   // rekey: new path prefix
}

type bindingJournal struct {
	mu   sync.Mutex
	path string
	dir  string
	f    *os.File
}

func newBindingJournal(stateDir string) *bindingJournal {
	return &bindingJournal{path: filepath.Join(stateDir, bindingJournalName), dir: stateDir}
}

// append writes entries as JSON lines in one write call. Failures are logged,
// never surfaced: journal I/O must not gate volume I/O, and the debounced
// full-state persist covers the same changes shortly after.
func (j *bindingJournal) append(entries []bindingJournalEntry) {
	if len(entries) == 0 {
		return
	}
	var buf bytes.Buffer
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		if err := os.MkdirAll(j.dir, 0o700); err != nil {
			log.Printf("portablefsd: binding journal dir: %v", err)
			return
		}
		f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("portablefsd: open binding journal: %v", err)
			return
		}
		j.f = f
	}
	if _, err := j.f.Write(buf.Bytes()); err != nil {
		log.Printf("portablefsd: append binding journal: %v", err)
	}
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
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
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
