package writeback

// THE RESOLUTION SURFACE THE PRODUCT ALREADY INSTRUCTED OPERATORS TO USE.
//
// validateJobIdentity refuses a force-park with
//
//	"job is terminally %s and requires explicit recovery resolution"
//
// and until this file there was no command, no daemon route, and no documented
// procedure that performed one. The live consequence was a CLOSED CYCLE:
//
//	portablefs umount               -> "run portablefs umount --force"
//	portablefs umount --force       -> "... requires explicit recovery resolution (409)"
//	portablefs umount --discard-record -> "run portablefs umount --force ... first"
//
// The only escape was to perform recoveryRunner.contain's third step BY HAND —
// `mv <store>/stream-... <store>/unreplayable/` — after which --force cleared in
// under a second. A product whose documented recovery is "move our state
// directory around" has no recovery, and one that names a resolution it does not
// ship is worse: it tells the operator the exit exists and hides it.
//
// ResolveTerminalRecoveryJobs is that resolution, with the same proof discipline
// the automatic containment uses:
//
//   - NEVER DELETE WHAT CANNOT BE PROVEN DISPOSABLE. The stream's bytes are the
//     only remaining copy of what was acknowledged, so they are MOVED, never
//     removed — into <stateDir>/unreplayable/, exactly where the automatic path
//     puts them and exactly where the by-hand escape put them.
//   - REFUSE WHAT IS NOT PROVEN TERMINAL. Only a job whose durable registry
//     records state "conflict" or "corrupt" is resolvable. An active, parked,
//     forced or replaying job has a non-destructive future (the next attach
//     replays it) and is left strictly alone, named in the result.
//   - REFUSE WHAT IS NOT PROVEN OURS. The store lock is taken non-blocking, so a
//     live engine's store is never touched; the mount identity, volume, branch
//     and WAL epoch of every stream are checked against the store before
//     anything moves.
//   - STATE THE LOSS EXACTLY. The result carries the same LostRecords/LostBytes/
//     LostScopes verdict the automatic containment publishes, computed by the
//     same function, and the same durable job.json is left behind so the loss is
//     re-reported on every later attach rather than disappearing with the
//     command's output.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ErrRecoveryResolutionRequired marks the refusal a caller can act on: a
// terminally conflict/corrupt job is blocking the operation, and
// ResolveTerminalRecoveryJobs (surfaced as `portablefs recovery resolve`) is
// what clears it.
//
// It is a typed sentinel so the daemon and the CLI can name the EXACT command
// with the EXACT arguments for the mount in hand. A message that says only "some
// resolution is required" is what created the cycle this round closes.
var ErrRecoveryResolutionRequired = errors.New("writeback: recovery job requires explicit resolution")

// ResolvedJob is one terminally-conflict/corrupt job this resolution acted on.
// It is the DEFINITE loss statement: what was quarantined, how much never
// reached the authority, and where the only remaining copy now lives.
type ResolvedJob struct {
	JobID          string   `json:"jobId"`
	WALEpoch       uint64   `json:"walEpoch"`
	State          string   `json:"state"`
	LostRecords    uint64   `json:"lostRecords"`
	LostBytes      uint64   `json:"lostBytes"`
	LostScopes     []string `json:"lostScopes,omitempty"`
	QuarantinePath string   `json:"quarantinePath"`
	Remedy         string   `json:"remedy"`
	LastError      string   `json:"lastError,omitempty"`
	// NamespaceHeld is true when the stream still holds authority delegation
	// grants that this OFFLINE resolution could not sweep. It is reported rather
	// than hidden: the next attach's recovery sweeps them, and until it runs the
	// covered scopes can still answer EAGAIN to peers.
	NamespaceHeld bool `json:"namespaceHeld,omitempty"`
}

// SkippedJob is a job the resolution deliberately did NOT touch, with the reason
// it is not this command's to resolve.
type SkippedJob struct {
	JobID    string `json:"jobId,omitempty"`
	WALEpoch uint64 `json:"walEpoch"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
}

// ResolveRecoveryResult is the whole outcome of one resolution pass.
type ResolveRecoveryResult struct {
	Resolved []ResolvedJob `json:"resolved"`
	Skipped  []SkippedJob  `json:"skipped,omitempty"`
}

// RecoveryJobReport is one durable recovery registry entry as it stands on
// disk, with the directory it was read from. It is the read-only half of the
// surface: `portablefs recovery list` needs no lock and changes nothing.
type RecoveryJobReport struct {
	StreamDir   string      `json:"streamDir"`
	Quarantined bool        `json:"quarantined"`
	Job         RecoveryJob `json:"job"`
}

// InspectStoreRecoveryJobs reads every recovery registry entry in a write-back
// store — live streams and already-quarantined ones alike — without taking the
// store lock and without changing a byte.
//
// No lock on purpose: the question "what is in this store" must be answerable
// while a daemon owns it, which is exactly when an operator is trying to find
// out why their unmount will not complete.
func InspectStoreRecoveryJobs(stateDir string) ([]RecoveryJobReport, error) {
	if stateDir == "" {
		return nil, errors.New("writeback: state directory is required")
	}
	var reports []RecoveryJobReport
	collect := func(root string, quarantined bool) error {
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "stream-") {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			job, ok := loadJob(dir)
			if !ok {
				continue
			}
			reports = append(reports, RecoveryJobReport{StreamDir: dir, Quarantined: quarantined, Job: job})
		}
		return nil
	}
	if err := collect(stateDir, false); err != nil {
		return nil, fmt.Errorf("writeback: inventory recovery registry: %w", err)
	}
	if err := collect(filepath.Join(stateDir, quarantineDirName), true); err != nil {
		return nil, fmt.Errorf("writeback: inventory quarantined recovery registry: %w", err)
	}
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Job.WALEpoch < reports[j].Job.WALEpoch
	})
	return reports, nil
}

// ResolveTerminalRecoveryJobs quarantines every terminally conflict/corrupt
// recovery job in a store, publishes the exact loss, and clears the block that
// refuses force-park and attach.
//
// jobIDs, when non-empty, restricts the pass to those job identities; an empty
// slice resolves every terminal job in the store. A job named in jobIDs that is
// not terminal is a REFUSAL, not a silent skip: an operator who named it wants
// to know why it was not resolved.
//
// It is offline by construction. It contacts no authority, so it cannot sweep
// the delegation grants a contained stream holds (the automatic path does that
// while an attach is up). Those grants are reported in ResolvedJob.NamespaceHeld
// and are swept by the next attach's recovery, which now runs at all — which is
// the point.
func ResolveTerminalRecoveryJobs(
	stateDir string,
	volumeID string,
	branch string,
	reason string,
	jobIDs []string,
) (ResolveRecoveryResult, error) {
	var result ResolveRecoveryResult
	if stateDir == "" || volumeID == "" {
		return result, errors.New("writeback: state directory and volume identity are required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "explicit operator recovery resolution"
	}
	if len(reason) > 4096 {
		return result, errors.New("writeback: recovery resolution reason is too long")
	}
	wanted := map[string]bool{}
	for _, id := range jobIDs {
		if id = strings.TrimSpace(id); id != "" {
			wanted[id] = true
		}
	}

	// NON-BLOCKING, EXCLUSIVE. Failing here is the proof that some engine still
	// owns this store, and the honest answer is to say so rather than to move
	// its bytes out from under it.
	storeDir, lock, err := lockExistingStoreDir(stateDir)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		_ = storeDir.Close()
	}()

	mountID, _, err := readExistingMountID(stateDir)
	if err != nil {
		return result, err
	}

	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return result, fmt.Errorf("writeback: inventory store: %w", err)
	}
	var streamDirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "stream-") {
			streamDirs = append(streamDirs, filepath.Join(stateDir, entry.Name()))
		}
	}
	sort.Strings(streamDirs)

	seen := map[string]bool{}
	for _, dir := range streamDirs {
		epoch, ok := streamEpochFromDir(filepath.Base(dir))
		if !ok || epoch == 0 {
			return result, fmt.Errorf("%w: malformed stream registry entry %s", ErrCorrupt, filepath.Base(dir))
		}
		job, err := loadJobStrict(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// A stream with no registry entry is not a recovery job at all.
				// force-park already has a proof for that shape; this command
				// has no business inventing one.
				result.Skipped = append(result.Skipped, SkippedJob{
					WALEpoch: epoch,
					State:    "(no registry entry)",
					Reason:   "the stream carries no recovery registry entry; `portablefs umount --force` handles a registry-less stream",
				})
				continue
			}
			return result, fmt.Errorf("writeback: read recovery registry %s: %w", filepath.Base(dir), err)
		}
		seen[job.JobID] = true
		if len(wanted) != 0 && !wanted[job.JobID] {
			continue
		}

		// PROVEN TERMINAL, OR LEFT ALONE. Everything else has a non-destructive
		// future and quarantining it would throw away a tail the next attach
		// would have replayed.
		if job.State != JobConflict && job.State != JobCorrupt {
			skip := SkippedJob{
				JobID: job.JobID, WALEpoch: epoch, State: job.State,
				Reason: "not terminal: the next attach replays this stream; nothing here needs resolving",
			}
			if wanted[job.JobID] {
				return result, fmt.Errorf(
					"writeback: recovery job %s is %s, not terminally conflict or corrupt; "+
						"resolving it would discard a tail the next attach replays",
					job.JobID, job.State,
				)
			}
			result.Skipped = append(result.Skipped, skip)
			continue
		}

		// PROVEN OURS. The registry entry must belong to this store's mount
		// identity, this volume, this branch and this stream's own epoch. A
		// foreign stream is not this command's to move.
		if job.VolumeID != volumeID || (branch != "" && job.Branch != branch) ||
			job.MountID != hex.EncodeToString(mountID[:]) || job.WALEpoch != epoch {
			result.Skipped = append(result.Skipped, SkippedJob{
				JobID: job.JobID, WALEpoch: epoch, State: job.State,
				Reason: "foreign: the registry entry does not match this store's mount/volume/branch identity, so its bytes are not this store's to move",
			})
			if wanted[job.JobID] {
				return result, fmt.Errorf(
					"%w: recovery job %s belongs to volume %q branch %q mount %s, not to this store",
					ErrCorrupt, job.JobID, job.VolumeID, job.Branch, job.MountID,
				)
			}
			continue
		}

		resolved, err := resolveTerminalStream(stateDir, dir, epoch, job, reason)
		if err != nil {
			return result, err
		}
		result.Resolved = append(result.Resolved, resolved)
	}

	for id := range wanted {
		if !seen[id] {
			return result, fmt.Errorf("writeback: no recovery job %s in this store", id)
		}
	}
	return result, nil
}

// resolveTerminalStream performs contain's steps 1, 3 and 4 offline, in the
// order every crash point survives: publish the verdict where the bytes are,
// move the bytes, then republish the location now that it is true.
func resolveTerminalStream(
	stateDir string,
	dir string,
	epoch uint64,
	job RecoveryJob,
	reason string,
) (ResolvedJob, error) {
	records, bytes, scopes, wbID := summarizeUnreplayableStream(dir, job)
	js := newJobState(dir, job)
	js.update(func(j *RecoveryJob) {
		if wbID != "" {
			j.WritebackID = wbID
		}
		j.Quarantined = true
		j.QuarantinePath = dir // true now; step 4 replaces it when the rename makes the destination true
		j.LostRecords, j.LostBytes, j.LostScopes = records, bytes, scopes
		j.PendingRecords, j.PendingBytes = records, bytes
		j.Remedy = unreplayableRemedy(j)
		if j.LastError == "" {
			j.LastError = reason
		} else {
			j.LastError = j.LastError + "; resolved by operator: " + reason
		}
		j.ResolvedAtMs = time.Now().UnixMilli()
		j.ResolvedReason = reason
	})
	if err := js.persist(); err != nil {
		return ResolvedJob{}, fmt.Errorf("writeback: publish resolution verdict for %s: %w", filepath.Base(dir), err)
	}
	moved, err := quarantineStreamDir(stateDir, dir)
	if err != nil {
		return ResolvedJob{}, fmt.Errorf("writeback: quarantine resolved stream %s: %w", filepath.Base(dir), err)
	}
	js.retarget(moved)
	js.update(func(j *RecoveryJob) {
		j.QuarantinePath = moved
		j.Remedy = unreplayableRemedy(j)
	})
	if err := js.persist(); err != nil {
		return ResolvedJob{}, fmt.Errorf("writeback: publish quarantine location for %s: %w", filepath.Base(moved), err)
	}
	final := js.snapshot()
	return ResolvedJob{
		JobID:          final.JobID,
		WALEpoch:       epoch,
		State:          final.State,
		LostRecords:    final.LostRecords,
		LostBytes:      final.LostBytes,
		LostScopes:     final.LostScopes,
		QuarantinePath: moved,
		Remedy:         final.Remedy,
		LastError:      final.LastError,
		NamespaceHeld:  len(final.LostScopes) != 0,
	}, nil
}
