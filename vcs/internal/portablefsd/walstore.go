package portablefsd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
//
// ── WHY 2.2 GB ACCUMULATED ACROSS 95 STALE STORES ────────────────────────────
//
// This sweep was written for the LEGACY per-session layout — sess-<owner>.wal
// files plus identity.json and .epoch — and the write-back engine has since
// moved to a store layout of engine.lock, mount-id, wal-epoch and
// stream-<epoch>/ directories holding wb-*.pfw segments.
//
// The old code was therefore a no-op that LOOKED like a reclaimer. It found no
// sess-*.wal entries, concluded kept == 0, removed identity.json and .epoch
// (usually absent), and called os.Remove(dir) — which failed with ENOTEMPTY
// against engine.lock/mount-id/wal-epoch/stream-* and had its error discarded
// by `if err := os.Remove(dir); err == nil`. Every byte survived, every restart,
// forever. This is the client-side twin of the server journal leak.
//
// ── THE POLICY ───────────────────────────────────────────────────────────────
//
// A store no configured attach can claim is reclaimed to a DEFINITE outcome:
//
//   - Legacy session logs that replay empty are removed; ones holding records
//     are preserved and reported, exactly as before.
//   - An engine store whose streams hold no unshipped segment records is
//     removed WHOLE — lock, mount identity, epoch floor, stream directories.
//     Drained bytes are garbage and are collected.
//   - An engine store that still holds records is PRESERVED and reported with
//     its size and the exact command that resolves it. Deleting an unshipped
//     tail would silently discard a user's writes, which this product never
//     does; leaving it undiscoverable is what made it a leak.
//   - A store whose engine.lock is held by a live engine is skipped entirely.
func sweepOrphanWALDir(dir string) {
	if storeLockHeld(dir) {
		// A live engine owns this store. It is not an orphan, whatever the
		// persisted attach inventory says.
		return
	}
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
	streams, records, bytes := orphanEngineStoreTail(dir)
	if records > 0 {
		// A store holding unshipped records is never deleted — those are the
		// user's writes. It is made RECLAIMABLE instead: stamping the identity
		// its own recovery registry already names lets the next attach of that
		// volume+branch adopt and drain it, which is what turns a permanent
		// 2.2 GB leak into a store that goes away on its own.
		//
		// The 95 stranded stores had no identity.json at all: they predate the
		// (volume, branch) re-keying, so adoption could not see them and the
		// sweep could not claim them. They were unreachable by every path.
		adopted := stampOrphanStoreIdentity(dir)
		log.Printf(
			"portablefsd: orphan write-back store %s holds %d unshipped record(s) (%d bytes) across %d stream(s); preserved%s",
			dir, records, bytes, streams, adopted,
		)
		return
	}
	if kept != 0 {
		return
	}
	_ = os.Remove(walIdentityPath(dir))
	_ = os.Remove(filepath.Join(dir, ".epoch"))
	// The engine store's own files, in dependency order: streams first, then
	// the identity and lock that name them.
	for _, name := range engineStoreStreamDirs(dir) {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			log.Printf("portablefsd: reclaim drained orphan stream %s: %v", filepath.Join(dir, name), err)
			return
		}
	}
	for _, name := range []string{"mount-id", "wal-epoch", "force-park.json", "engine.lock"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			log.Printf("portablefsd: reclaim drained orphan store file %s: %v", filepath.Join(dir, name), err)
			return
		}
	}
	if err := os.Remove(dir); err != nil {
		// Anything left is unrecognized state. Never rm -rf a directory this
		// code does not fully understand; say so instead.
		log.Printf("portablefsd: orphan write-back store %s holds no records but could not be removed: %v; preserved", dir, err)
		return
	}
	log.Printf("portablefsd: reclaimed drained orphan write-back store %s", dir)
}

// storeLockHeld reports whether a live engine holds this store's engine.lock.
// A store with no lock file is not held.
func storeLockHeld(dir string) bool {
	path := filepath.Join(dir, "engine.lock")
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

func engineStoreStreamDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "stream-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// orphanEngineStoreTail measures what an engine store still holds. A stream is
// considered to hold records unless it carries a clean-close marker: this sweep
// is a garbage collector, not a recovery engine, and it must err toward
// preserving bytes it cannot prove are drained.
func orphanEngineStoreTail(dir string) (streams int, records uint64, bytes uint64) {
	for _, name := range engineStoreStreamDirs(dir) {
		streamDir := filepath.Join(dir, name)
		pending, size, drained := streamPendingBytes(streamDir)
		if drained {
			continue
		}
		streams++
		records += pending
		bytes += size
	}
	return streams, records, bytes
}

// streamPendingBytes reports one stream's unshipped tail. drained is true only
// when the stream's recovery job proves everything it admitted was applied, or
// when the stream holds no segment bytes beyond its headers.
func streamPendingBytes(streamDir string) (records uint64, bytes uint64, drained bool) {
	entries, err := os.ReadDir(streamDir)
	if err != nil {
		return 0, 0, false
	}
	var segmentBytes uint64
	segments := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "wb-") || !strings.HasSuffix(e.Name(), ".pfw") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, 0, false
		}
		segments++
		segmentBytes += uint64(info.Size())
	}
	job, ok := readRecoveryJobSummary(filepath.Join(streamDir, "job.json"))
	if !ok {
		// No job registry: a stream that crashed before registering. It is
		// drained only if it has no segment bytes at all.
		return 0, segmentBytes, segments == 0
	}
	if job.PendingRecords == 0 && job.AdmittedThrough == job.AppliedThrough {
		return 0, segmentBytes, true
	}
	pending := job.PendingRecords
	if pending == 0 {
		pending = job.AdmittedThrough - job.AppliedThrough
	}
	size := job.PendingBytes
	if size == 0 {
		size = segmentBytes
	}
	return pending, size, false
}

// stampOrphanStoreIdentity gives an unidentified store the (volume, branch)
// identity its own recovery registry already records, so the next attach of
// that volume can adopt it. It returns the sentence fragment to log.
func stampOrphanStoreIdentity(dir string) string {
	if id, ok := readWALIdentity(dir); ok {
		return fmt.Sprintf(
			" (adoptable: re-attach %s@%s to replay it)", id.VolumeID, id.Branch,
		)
	}
	for _, name := range engineStoreStreamDirs(dir) {
		job, ok := readRecoveryJobSummary(filepath.Join(dir, name, "job.json"))
		if !ok || job.VolumeID == "" {
			continue
		}
		writeWALIdentity(dir, walIdentity{VolumeID: job.VolumeID, Branch: job.Branch})
		if _, stamped := readWALIdentity(dir); stamped {
			return fmt.Sprintf(
				" (stamped with its recorded identity %s@%s; re-attach that volume to replay it)",
				job.VolumeID, job.Branch,
			)
		}
	}
	return " (its volume identity could not be recovered from the store, so no attach can adopt it; inspect it before removing it)"
}

// recoveryJobSummary is the subset of the write-back recovery registry this
// sweep reads. It is deliberately a local, tolerant decode: the sweep must not
// fail a daemon start because a job file grew a field.
type recoveryJobSummary struct {
	State           string `json:"state"`
	VolumeID        string `json:"volumeId"`
	Branch          string `json:"branch"`
	AdmittedThrough uint64 `json:"admittedThrough"`
	AppliedThrough  uint64 `json:"appliedThrough"`
	PendingRecords  uint64 `json:"pendingRecords"`
	PendingBytes    uint64 `json:"pendingBytes"`
}

func readRecoveryJobSummary(path string) (recoveryJobSummary, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return recoveryJobSummary{}, false
	}
	var job recoveryJobSummary
	if json.Unmarshal(body, &job) != nil {
		return recoveryJobSummary{}, false
	}
	return job, true
}
