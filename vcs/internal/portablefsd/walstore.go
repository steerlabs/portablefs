package portablefsd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// The write-back WAL store lives at stateDir/wal/<storageID>, where storageID
// is derived from (volumeID, branch) ONLY. Every store carries an
// identity.json naming its volume and branch, so a future re-keying (or a
// dir restored from a backup) stays adoptable by content rather than by
// directory name. Stores written by the retired (volume, branch, mountPath)
// scheme carry no identity file; an attach adopts its own legacy dir by
// recomputing the legacy hash from its current mount path, and any dir whose
// identity matches the attach's (volume, branch) is adopted regardless of
// name. Adoption renames the embedded owner prefix in each session WAL
// filename (sess-<owner>-<rootHash>.wal) to the new owner so recovery's
// owner+rootHash matching keeps working, and merges the epoch floor so
// session generations never regress across the move.

type walIdentity struct {
	VolumeID string `json:"volumeId"`
	Branch   string `json:"branch"`
}

func walIdentityPath(dir string) string { return filepath.Join(dir, "identity.json") }

func readWALIdentity(dir string) (walIdentity, bool) {
	b, err := os.ReadFile(walIdentityPath(dir))
	if err != nil {
		return walIdentity{}, false
	}
	var id walIdentity
	if json.Unmarshal(b, &id) != nil || id.VolumeID == "" {
		return walIdentity{}, false
	}
	return id, true
}

func writeWALIdentity(dir string, id walIdentity) {
	if _, ok := readWALIdentity(dir); ok {
		return
	}
	b, err := json.Marshal(id)
	if err != nil {
		return
	}
	if err := os.WriteFile(walIdentityPath(dir), b, 0o600); err != nil {
		log.Printf("portablefsd: write WAL store identity %s: %v", dir, err)
	}
}

// adoptWALStore prepares this attach's WAL store before its Volume dials:
// ensure the (volume, branch) dir with its identity file, then pull in any
// parked WALs from the legacy mount-path-keyed dir and from any other dir
// whose identity matches. Runs before the session manager exists, so no live
// handles can race the moves.
func (a *attach) adoptWALStore() {
	walRoot := filepath.Join(a.stateDir, "wal")
	dest := filepath.Join(walRoot, a.storageID)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		log.Printf("portablefsd: create WAL store %s: %v", dest, err)
		return
	}
	writeWALIdentity(dest, walIdentity{VolumeID: a.volumeID, Branch: a.branch})

	adopt := func(fromID string) {
		if fromID == a.storageID {
			return
		}
		from := filepath.Join(walRoot, fromID)
		if _, err := os.Stat(from); err != nil {
			return
		}
		if err := adoptWALDir(from, fromID, dest, a.storageID); err != nil {
			log.Printf("portablefsd: adopt WAL store %s for %s@%s: %v (dir preserved)", from, a.volumeID, a.branch, err)
		}
	}
	// This attach's own legacy (volume, branch, mountPath) dir.
	adopt(stableStorageID(attachKey(a.volumeID, a.branch, a.mountPath)))
	// Any dir that says it belongs to this (volume, branch): a prior mount
	// path's legacy dir that a later daemon stamped, or a restored backup.
	entries, err := os.ReadDir(walRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == a.storageID {
			continue
		}
		if id, ok := readWALIdentity(filepath.Join(walRoot, e.Name())); ok &&
			id.VolumeID == a.volumeID && id.Branch == a.branch {
			adopt(e.Name())
		}
	}
}

// adoptWALDir moves every WAL artifact from one store into another, rewriting
// the owner prefix embedded in session WAL filenames and merging the epoch
// floor. Existing destination files are never clobbered (log + preserve).
func adoptWALDir(from, fromID, dest, destID string) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	oldPrefix := "sess-portablefsd-" + fromID + "-"
	newPrefix := "sess-portablefsd-" + destID + "-"
	moved := 0
	for _, e := range entries {
		name := e.Name()
		switch name {
		case "identity.json":
			continue
		case ".epoch":
			mergeEpochFloor(filepath.Join(from, name), filepath.Join(dest, ".epoch"))
			_ = os.Remove(filepath.Join(from, name))
			continue
		}
		target := name
		if strings.HasPrefix(name, oldPrefix) {
			target = newPrefix + strings.TrimPrefix(name, oldPrefix)
		}
		src, dst := filepath.Join(from, name), filepath.Join(dest, target)
		if _, err := os.Lstat(dst); err == nil {
			log.Printf("portablefsd: adopt %s: destination %s already exists; source preserved", src, dst)
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("move %s: %w", src, err)
		}
		moved++
	}
	_ = os.Remove(walIdentityPath(from))
	if err := os.Remove(from); err == nil && moved > 0 {
		log.Printf("portablefsd: adopted %d WAL artifact(s) from %s into %s", moved, from, dest)
	} else if moved > 0 {
		log.Printf("portablefsd: adopted %d WAL artifact(s) from %s into %s (source dir kept: not empty)", moved, from, dest)
	}
	return nil
}

// mergeEpochFloor raises dst's persisted session-generation floor to at least
// src's, so sessions recovered under the adopted store can never mint a
// generation at or below one the old store already used.
func mergeEpochFloor(src, dst string) {
	read := func(p string) uint64 {
		b, err := os.ReadFile(p)
		if err != nil {
			return 0
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	if s := read(src); s > read(dst) {
		if err := os.WriteFile(dst, []byte(strconv.FormatUint(s, 10)), 0o600); err != nil {
			log.Printf("portablefsd: merge epoch floor into %s: %v", dst, err)
		}
	}
}

// sweepWALRoot runs once at daemon start: fully-drained session logs are
// removed (with their sidecars), WAL stores that belong to a configured
// attach are left for that attach's adoption/recovery, and anything holding
// records that can never recover here — an unknown volume — is REPORTED and
// preserved, never deleted.
func sweepWALRoot(stateDir string, attaches []persistedAttachEntry) {
	walRoot := filepath.Join(stateDir, "wal")
	entries, err := os.ReadDir(walRoot)
	if err != nil {
		return
	}
	claimed := map[string]walIdentity{}
	identities := map[walIdentity]bool{}
	for _, e := range attaches {
		id := walIdentity{VolumeID: e.VolumeID, Branch: e.Branch}
		identities[id] = true
		claimed[stableStorageID(storageKey(e.VolumeID, e.Branch))] = id
		claimed[stableStorageID(attachKey(e.VolumeID, e.Branch, e.MountPath))] = id
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(walRoot, e.Name())
		if _, ok := claimed[e.Name()]; ok {
			continue // a configured attach owns (or will adopt) this store
		}
		if id, ok := readWALIdentity(dir); ok && identities[id] {
			continue // adoptable by a configured attach's next start
		}
		sweepOrphanWALDir(dir)
	}
}

// sweepOrphanWALDir removes drained logs from a store no configured attach
// can claim, and reports (never deletes) logs still holding records.
func sweepOrphanWALDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	kept := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "sess-") || !strings.HasSuffix(name, ".wal") {
			continue
		}
		p := filepath.Join(dir, name)
		w, err := wal.Open(p)
		if err != nil {
			kept++
			log.Printf("portablefsd: orphan WAL %s is unreadable (%v); preserved", p, err)
			continue
		}
		recs, _ := w.Replay()
		_ = w.Close()
		if len(recs) > 0 {
			kept++
			log.Printf("portablefsd: orphan WAL %s holds %d unrecoverable record(s) for an unknown volume; preserved (recover by re-attaching the volume, or remove manually)", p, len(recs))
			continue
		}
		if err := wal.RemoveFiles(p); err != nil {
			kept++
			log.Printf("portablefsd: remove drained orphan WAL %s: %v", p, err)
		}
	}
	if kept == 0 {
		_ = os.Remove(walIdentityPath(dir))
		_ = os.Remove(filepath.Join(dir, ".epoch"))
		if err := os.Remove(dir); err == nil {
			log.Printf("portablefsd: removed drained orphan WAL store %s", dir)
		}
	}
}
