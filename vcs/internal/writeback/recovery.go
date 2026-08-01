package writeback

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Recovery job states.
const (
	JobActive    = "active"    // live stream serving a mount
	JobForced    = "forced"    // forced unmount parked the stream durably
	JobReplaying = "replaying" // recovery is draining the tail
	JobParked    = "parked"    // live stream fenced/stalled terminally; recovers on next attach
	JobConflict  = "conflict"  // typed recovery conflict; operator decision required
	JobCorrupt   = "corrupt"   // WAL damage; automatic replay blocked
)

// RecoveryJob is the durable registry entry for one stream (job.json).
type RecoveryJob struct {
	Version     int    `json:"version"`
	JobID       string `json:"jobId"`
	VolumeID    string `json:"volumeId"`
	Branch      string `json:"branch"`
	MountID     string `json:"mountId"`
	WALEpoch    uint64 `json:"walEpoch"`
	WritebackID string `json:"writebackId"`

	State string `json:"state"`

	AdmittedThrough uint64 `json:"admittedThrough"`
	AppliedThrough  uint64 `json:"appliedThrough"`
	PendingRecords  uint64 `json:"pendingRecords"`
	PendingBytes    uint64 `json:"pendingBytes"`

	CreatedAtMs      int64 `json:"createdAtMs"`
	UpdatedAtMs      int64 `json:"updatedAtMs"`
	LastProgressAtMs int64 `json:"lastProgressAtMs,omitempty"`

	LastError string           `json:"lastError,omitempty"`
	Conflicts []ConflictDetail `json:"conflicts,omitempty"`
}

// jobState is the atomic on-disk registry for one stream directory.
type jobState struct {
	mu          sync.Mutex
	path        string
	job         RecoveryJob
	lastPersist time.Time
}

func newJobState(streamDir string, job RecoveryJob) *jobState {
	return &jobState{path: filepath.Join(streamDir, "job.json"), job: job}
}

func (js *jobState) snapshot() RecoveryJob {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.job
}

func (js *jobState) update(fn func(*RecoveryJob)) {
	js.mu.Lock()
	fn(&js.job)
	js.job.UpdatedAtMs = time.Now().UnixMilli()
	js.mu.Unlock()
}

// updateDebounced folds progress counters in and persists at most once per
// second. The WAL remains the mutation record, while registry persistence
// errors are returned rather than hidden.
func (js *jobState) updateDebounced(fn func(*RecoveryJob)) error {
	js.mu.Lock()
	fn(&js.job)
	js.job.UpdatedAtMs = time.Now().UnixMilli()
	js.job.LastProgressAtMs = js.job.UpdatedAtMs
	due := time.Since(js.lastPersist) >= time.Second
	if due {
		js.lastPersist = time.Now()
	}
	js.mu.Unlock()
	if due {
		return js.persist()
	}
	return nil
}

// persist writes job.json through the package's file-sync, atomic-replace,
// directory-sync primitive.
func (js *jobState) persist() error {
	js.mu.Lock()
	body, err := json.MarshalIndent(js.job, "", "  ")
	js.mu.Unlock()
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeFileAtomicDurable(js.path, body, 0o600)
}

func loadJob(streamDir string) (RecoveryJob, bool) {
	var job RecoveryJob
	b, err := os.ReadFile(filepath.Join(streamDir, "job.json"))
	if err != nil {
		return job, false
	}
	if err := json.Unmarshal(b, &job); err != nil {
		return job, false
	}
	return job, true
}

// errRetryable marks a transient recovery failure (authority unreachable/
// slow). Recovery is an ATTACH-READINESS GATE: a transient failure fails the
// attach — the mount never serves with parked streams in limbo.
var errRetryable = errors.New("writeback: recovery attempt failed")

// recoveryRunner reconciles every parked stream of this store at engine
// open, BEFORE the mount serves. A stream either drains fully, or parks in
// an explicit terminal state (conflict/corrupt/foreign — surfaced, never
// blocking peers silently); a transient failure fails the attach.
type recoveryRunner struct {
	e *Engine

	mu     sync.Mutex
	parked map[string]*jobState // stream dir -> registry (terminal only, post-open)
}

func newRecoveryRunner(e *Engine) *recoveryRunner {
	return &recoveryRunner{e: e, parked: map[string]*jobState{}}
}

// discover registers every parked stream directory and returns the highest
// epoch seen (the live stream picks the next one).
func (r *recoveryRunner) discover() uint64 {
	entries, err := os.ReadDir(r.e.cfg.StateDir)
	if err != nil {
		return 0
	}
	var maxEpoch uint64
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		epoch, ok := streamEpochFromDir(ent.Name())
		if !ok {
			continue
		}
		maxEpoch = max(maxEpoch, epoch)
		dir := filepath.Join(r.e.cfg.StateDir, ent.Name())
		job, _ := loadJob(dir)
		js := newJobState(dir, job)
		r.parked[dir] = js
	}
	return maxEpoch
}

// reconcileAll drains every parked stream, epoch ascending, BEFORE the mount
// serves. It returns nil when every stream either drained (removed) or
// parked in an explicit TERMINAL state (conflict/corrupt/foreign — kept
// registered and surfaced). Any transient failure returns an error: the
// attach fails rather than serving with recovery in limbo.
func (r *recoveryRunner) reconcileAll(ctx context.Context) error {
	r.mu.Lock()
	dirs := make([]string, 0, len(r.parked))
	for dir := range r.parked {
		dirs = append(dirs, dir)
	}
	r.mu.Unlock()
	sort.Strings(dirs)
	for _, dir := range dirs {
		if err := r.attempt(ctx, dir); err != nil {
			return err
		}
	}
	return nil
}

// attempt reconciles one stream. nil means resolved-or-terminal; an error is
// a transient failure the caller must surface (attach-readiness gate).
func (r *recoveryRunner) attempt(ctx context.Context, dir string) error {
	r.mu.Lock()
	js := r.parked[dir]
	r.mu.Unlock()
	if js == nil {
		return nil
	}
	err := r.recoverStream(ctx, dir, js)
	switch {
	case err == nil:
		r.mu.Lock()
		delete(r.parked, dir)
		r.mu.Unlock()
		return nil
	case errors.Is(err, errRetryable):
		js.update(func(j *RecoveryJob) {
			if j.State == "" || j.State == JobActive || j.State == JobForced || j.State == JobParked {
				j.State = JobReplaying
			}
		})
		if persistErr := js.persist(); persistErr != nil {
			return fmt.Errorf("writeback: persist retryable recovery state for %s: %w", filepath.Base(dir), persistErr)
		}
		return fmt.Errorf("writeback: parked stream %s not drained: %w", filepath.Base(dir), err)
	default:
		// Terminal (conflict/corrupt/foreign): stays registered for
		// surfacing; the mount serves — the scopes stay fenced server-side
		// and typed locally, nothing is silently merged.
		if persistErr := js.persist(); persistErr != nil {
			return fmt.Errorf("writeback: persist terminal recovery state for %s: %w", filepath.Base(dir), persistErr)
		}
		return nil
	}
}

func (r *recoveryRunner) jobs() []RecoveryJob {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecoveryJob, 0, len(r.parked))
	for _, js := range r.parked {
		out = append(out, js.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WALEpoch < out[j].WALEpoch })
	return out
}

// recoverStream reconciles one parked stream: scan, verify against the
// authority's durable stream state, rebind the recovery scopes, drain the
// tail, release, and remove. nil means resolved (dir removed); errRetryable
// means try again; anything else parked terminally with a typed job state.
func (r *recoveryRunner) recoverStream(ctx context.Context, dir string, js *jobState) error {
	e := r.e
	scan, err := scanStream(dir)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = err.Error()
			})
			return fmt.Errorf("corrupt stream: %w", err)
		}
		return fmt.Errorf("%w: %v", errRetryable, err)
	}
	if scan.header.VolumeID != e.cfg.VolumeID || scan.header.Branch != e.cfg.Branch {
		// A job for another volume/branch is reported but never adopted.
		js.update(func(j *RecoveryJob) {
			j.State = JobConflict
			j.LastError = fmt.Sprintf("stream belongs to %s@%s, not %s@%s",
				scan.header.VolumeID, scan.header.Branch, e.cfg.VolumeID, e.cfg.Branch)
		})
		return errors.New("foreign stream")
	}

	live, mutations, marks, closed, err := decodeStreamFrames(scan.frames)
	if err != nil {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	wbID := streamID(scan.header.MountID, scan.header.WALEpoch)
	if closed {
		return removeStreamDir(dir)
	}
	if len(mutations) == 0 && len(live) == 0 {
		// A validly EMPTY stream (header, no frames): the holder crashed
		// between the authority journaling a grant and the client appending
		// its DELEGATION frame. Nothing was ever acknowledged (frames
		// precede every ack), so sweeping every grant still bound to this
		// stream is lossless — and required: an orphaned grant would block
		// the subtree for every peer forever.
		if err := e.remote.Discard(ctx, wbID, nil); err != nil {
			return fmt.Errorf("%w: discard empty stream: %v", errRetryable, err)
		}
		return removeStreamDir(dir)
	}
	jobID := js.snapshot().JobID
	if jobID == "" {
		jobID, err = newPublicJobID()
		if err != nil {
			return fmt.Errorf("%w: generate recovery job id: %v", errRetryable, err)
		}
	}
	js.update(func(j *RecoveryJob) {
		j.State = JobReplaying
		j.WritebackID = wbID
		j.MountID = hex.EncodeToString(scan.header.MountID[:])
		j.WALEpoch = scan.header.WALEpoch
		j.VolumeID = scan.header.VolumeID
		j.Branch = scan.header.Branch
		j.JobID = jobID
		j.AdmittedThrough = scan.lastSeq
	})
	if err := js.persist(); err != nil {
		return fmt.Errorf("%w: persist recovery registry: %v", errRetryable, err)
	}

	certThrough, certDigest, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	ss, err := e.remote.StreamState(ctx, wbID)
	if err != nil {
		return fmt.Errorf("%w: stream state: %v", errRetryable, err)
	}
	through := certThrough
	if ss.Exists {
		through = ss.Through
	}
	if through > scan.lastSeq {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = fmt.Sprintf("authority watermark %d is past the local tail %d", through, scan.lastSeq)
		})
		return errors.New("watermark past local tail")
	}
	localDigest, err := digestAt(scan, marks, through)
	if err != nil {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	if !ss.Exists && localDigest != certDigest {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = "local applied certificate does not match the retained stream"
		})
		return errors.New("local applied certificate mismatch")
	}
	if ss.Exists && localDigest != ss.Digest {
		js.update(func(j *RecoveryJob) {
			j.State = JobConflict
			j.LastError = "stream digest diverged from the authority's durable state"
			j.Conflicts = []ConflictDetail{{Kind: "DIGEST_MISMATCH"}}
		})
		return errors.New("digest mismatch")
	}

	var tail []frame
	for _, m := range mutations {
		if m.seq > through {
			tail = append(tail, m)
		}
	}
	if len(tail) == 0 && len(live) == 0 {
		if err := e.remote.Discard(ctx, wbID, nil); err != nil {
			return fmt.Errorf("%w: discard drained stream: %v", errRetryable, err)
		}
		return removeStreamDir(dir)
	}

	scopes := make([]RebindScope, 0, len(live))
	for s, ep := range live {
		scopes = append(scopes, RebindScope{Scope: s, Epoch: ep})
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Scope < scopes[j].Scope })
	if len(tail) > 0 && len(live) == 0 {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = "unshipped tail without a recorded delegation"
		})
		return errors.New("tail without delegation")
	}
	// A previous attach may have been terminalized while one resolved
	// recovery flush was already executing at the authority. If that flush
	// commits between our StreamState read and Rebind, the authority correctly
	// rejects the stale digest. Re-read and accept only a strict forward
	// watermark whose digest is provable from this WAL, then retry Rebind with
	// a fresh exact identity. A stationary/missing/divergent state remains a
	// real typed conflict.
	for {
		reply, err := e.remote.Rebind(ctx, wbID, scopes, through, localDigest)
		if err != nil {
			return fmt.Errorf("%w: rebind: %v", errRetryable, err)
		}
		if len(reply.Conflicts) == 0 {
			break
		}
		digestOnly := true
		for _, conflict := range reply.Conflicts {
			if conflict.Kind != "DIGEST_MISMATCH" {
				digestOnly = false
				break
			}
		}
		if digestOnly {
			next, stateErr := e.remote.StreamState(ctx, wbID)
			if stateErr != nil {
				return fmt.Errorf("%w: refresh stream state after rebind race: %v", errRetryable, stateErr)
			}
			if next.Exists && next.Through > through && next.Through <= scan.lastSeq {
				nextDigest, digestErr := digestAt(scan, marks, next.Through)
				if digestErr != nil {
					js.update(func(j *RecoveryJob) {
						j.State = JobCorrupt
						j.LastError = digestErr.Error()
					})
					return digestErr
				}
				if nextDigest == next.Digest {
					through = next.Through
					localDigest = nextDigest
					continue
				}
			}
		}
		js.update(func(j *RecoveryJob) {
			j.State = JobConflict
			j.LastError = "recovery scopes moved on the authority"
			j.Conflicts = reply.Conflicts
		})
		return errors.New("rebind conflict")
	}

	// Drain the dense tail as mixed-scope batches, chaining the digest
	// forward. Every run names the exact rebound grant authorizing it.
	tail = tail[:0]
	for _, m := range mutations {
		if m.seq > through {
			tail = append(tail, m)
		}
	}
	prev := localDigest
	finalThrough := through
	i := 0
	for i < len(tail) {
		var records []wal.Record
		var scopeRuns []FlushScope
		var bytes int64
		end := prev
		j := i
		for ; j < len(tail) && len(records) < flushMaxRecords && bytes < flushMaxBytes; j++ {
			scope := coveringScope(live, decodePathOf(tail[j]))
			if scope == "" {
				missingSeq := tail[j].seq
				js.update(func(job *RecoveryJob) {
					job.State = JobCorrupt
					job.LastError = fmt.Sprintf("record %d has no covering delegation", missingSeq)
				})
				return errors.New("record without covering delegation")
			}
			rec, err := wal.DecodePFR1(tail[j].payload)
			if err != nil {
				js.update(func(jb *RecoveryJob) {
					jb.State = JobCorrupt
					jb.LastError = err.Error()
				})
				return err
			}
			rec.Seq = tail[j].seq
			end = digestNext(end, tail[j].seq, tail[j].payload)
			records = append(records, rec)
			bytes += int64(len(tail[j].payload))
			if len(scopeRuns) != 0 && scopeRuns[len(scopeRuns)-1].Scope == scope {
				scopeRuns[len(scopeRuns)-1].Through = tail[j].seq
			} else {
				scopeRuns = append(scopeRuns, FlushScope{
					Scope: scope, Epoch: live[scope], Through: tail[j].seq,
				})
			}
		}
		reply, err := e.remote.FlushResolved(ctx, FlushRequest{
			WritebackID: wbID, PrevDigest: prev, EndDigest: end,
			Records: records, ScopeRuns: scopeRuns,
		})
		if err != nil {
			return fmt.Errorf("%w: recovery flush: %v", errRetryable, err)
		}
		if reply.Status != 0 {
			js.update(func(jb *RecoveryJob) {
				jb.State = JobConflict
				jb.LastError = fmt.Sprintf("recovery flush rejected with status %d", reply.Status)
			})
			return errors.New("recovery flush rejected")
		}
		// A success must name this batch's exact end. A short watermark would
		// drop unshipped records; a watermark past the sent end claims bytes
		// this request never supplied.
		if batchEnd := tail[j-1].seq; reply.Through != batchEnd {
			js.update(func(jb *RecoveryJob) {
				jb.State = JobConflict
				jb.LastError = fmt.Sprintf("recovery flush succeeded with authority watermark %d, want exact batch end %d", reply.Through, batchEnd)
			})
			return errors.New("recovery flush watermark short of batch end")
		}
		prev = end
		finalThrough = reply.Through
		i = j
		if err := js.updateDebounced(func(jb *RecoveryJob) {
			jb.AppliedThrough = reply.Through
			jb.PendingRecords = uint64(len(tail) - i)
		}); err != nil {
			return fmt.Errorf("%w: persist recovery progress: %v", errRetryable, err)
		}
	}
	if finalThrough != scan.lastSeq {
		err := fmt.Errorf("%w: recovery drain ended at %d before WAL tail %d", ErrCorrupt, finalThrough, scan.lastSeq)
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	// Resolve and durably publish every frontend identity before recording
	// any local RELEASE. If the process crashes after a RELEASE certificate,
	// the next recovery deliberately treats that scope as locally final and
	// may sweep its remaining authority grant without rebinding it; therefore
	// the identity boundary must already be complete at that point.
	preparedEnds := make([]func(bool), len(scopes))
	cleanupPreparedFrom := func(start int) {
		for i := start; i < len(preparedEnds); i++ {
			if preparedEnds[i] != nil {
				preparedEnds[i](false)
				preparedEnds[i] = nil
			}
		}
	}
	for i, sc := range scopes {
		if e.cfg.Events.OnHandoffPrepared != nil {
			var err error
			preparedEnds[i], err = e.cfg.Events.OnHandoffPrepared(
				ctx, sc.Scope, sc.Epoch,
			)
			if err != nil {
				cleanupPreparedFrom(0)
				return fmt.Errorf(
					"%w: prepare recovered frontend identities %q: %v",
					errRetryable, sc.Scope, err,
				)
			}
		}
	}
	// Make every rebound scope locally final in ONE durable append before
	// sending the first Checkin. A crash or failure after any subset of the
	// sequential authority releases then recovers from an empty local live
	// projection and the exact applied certificate, sweeping whichever
	// recovery grants remain instead of trying to rebind already-released
	// scopes.
	if err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, prev, scopes, e.cfg.BudgetBytes); err != nil {
		cleanupPreparedFrom(0)
		if errors.Is(err, errCloseOutUnbounded) {
			// Definite and terminal: no retry can create budget, and none can
			// create free space on a full device either — both arrive here as
			// this one typed answer. The tail is already applied at the
			// authority and the grants stay checked out to this stream until an
			// operator raises the cap or frees the device, at which point the
			// next attach finishes the close-out unchanged.
			js.update(func(j *RecoveryJob) {
				j.State = JobConflict
				j.LastError = err.Error()
				j.Conflicts = []ConflictDetail{{Kind: "CLOSE_OUT_UNBOUNDED"}}
			})
			return err
		}
		return fmt.Errorf("%w: persist recovery release certificate: %v", errRetryable, err)
	}
	for i, sc := range scopes {
		if err := e.remote.ReleaseDelegation(ctx, sc.Scope, sc.Epoch); err != nil {
			cleanupPreparedFrom(i)
			return fmt.Errorf("%w: release %q: %v", errRetryable, sc.Scope, err)
		}
		if preparedEnds[i] != nil {
			preparedEnds[i](true)
			preparedEnds[i] = nil
		}
	}
	// Sweep any grant still bound to this stream but absent from the local
	// live projection. This covers both an acquire that crashed before its
	// DELEGATION frame and a fully-drained release whose local RELEASE frame
	// was synced before Checkin. Neither shape can carry an unshipped tail,
	// so discarding the authority remainder is lossless and idempotent.
	if err := e.remote.Discard(ctx, wbID, nil); err != nil {
		return fmt.Errorf("%w: discard stream remainder: %v", errRetryable, err)
	}
	e.logf("writeback: recovered stream %s: %d records drained, %d scopes released", wbID, len(tail), len(scopes))
	return removeStreamDir(dir)
}

// decodeStreamFrames interprets a scanned stream's control records. A control
// payload that fails to decode is CORRUPTION (the frame CRC proved the bytes
// are what was written, so the writer wrote garbage): fail closed instead of
// silently dropping a grant, release, or checkpoint from the recovered state.
func decodeStreamFrames(frames []frame) (live map[string]string, mutations []frame, marks []appliedFrame, closed bool, err error) {
	live = map[string]string{}
	for _, fr := range frames {
		switch fr.typ {
		case frameMutation:
			mutations = append(mutations, fr)
		case frameDelegation:
			var df delegationFrame
			if uerr := json.Unmarshal(fr.payload, &df); uerr != nil || df.Scope == "" || df.Epoch == "" {
				return nil, nil, nil, false, fmt.Errorf("%w: malformed DELEGATION frame %d", ErrCorrupt, fr.frameNo)
			}
			live[df.Scope] = df.Epoch
		case frameRelease:
			var df delegationFrame
			if uerr := json.Unmarshal(fr.payload, &df); uerr != nil || df.Scope == "" {
				return nil, nil, nil, false, fmt.Errorf("%w: malformed RELEASE frame %d", ErrCorrupt, fr.frameNo)
			}
			delete(live, df.Scope)
		case frameApplied:
			var af appliedFrame
			if uerr := json.Unmarshal(fr.payload, &af); uerr != nil {
				return nil, nil, nil, false, fmt.Errorf("%w: malformed APPLIED frame %d", ErrCorrupt, fr.frameNo)
			}
			if raw, derr := hex.DecodeString(af.Digest); derr != nil || len(raw) != 32 {
				return nil, nil, nil, false, fmt.Errorf("%w: APPLIED frame %d carries a malformed digest", ErrCorrupt, fr.frameNo)
			}
			marks = append(marks, af)
		case frameClose, frameForcedClose:
			var cf closeFrame
			if uerr := json.Unmarshal(fr.payload, &cf); uerr != nil {
				return nil, nil, nil, false, fmt.Errorf("%w: malformed CLOSE frame %d", ErrCorrupt, fr.frameNo)
			}
			if fr.typ == frameClose {
				closed = true
			}
		}
	}
	return live, mutations, marks, closed, nil
}

func removeStreamDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(dir))
}

// errCloseOutUnbounded is the DEFINITE terminal outcome of a close-out that
// cannot be made to fit: the stream parks in a typed conflict an operator
// resolves, by raising BudgetBytes or by freeing space on the device. It is
// deliberately NOT errRetryable — an attach must never be failed forever by a
// condition no amount of retrying can change.
//
// It covers both ways a close-out fails to fit. When the arithmetic gate refuses
// it, nothing at all was written. When a physical ENOSPC produces it (see
// closeOutWrite), a partial barrier may be on disk — which the three-barrier
// ordering already makes safe, and which the next attach re-derives from scratch.
var errCloseOutUnbounded = errors.New("writeback: recovery close-out does not fit the configured WAL budget")

// appendRecoveryReleaseCertificate makes every rebound scope locally final:
// APPLIED at the drained tail followed by one RELEASE per scope, appended to
// the scanned stream's last segment. The store lock guarantees no concurrent
// writer. It is the close-out half of the legacy-stream recovery contract
// stated in wal.go, and it is budget-aware for the reason stated there: a
// pre-upgrade WAL carries NO control reserve, so the room this append needs
// cannot be assumed to exist.
//
// The cost is EXACT, never a maximum: the RELEASE payloads are the actual
// encoded bytes of the actual scopes, produced by the DURABLE encoder because
// every one of them was already read back out of this stream's own DELEGATION
// frames.
//
// When the certificate does not fit, recovery reclaims the fully-applied
// segment prefix. It is entitled to: this function is only reached once the
// whole tail is authority-applied (finalThrough == scan.lastSeq), so every
// mutation frame in the stream is dead. The ordering is what makes that
// crash-safe, in three barriers:
//
//	A. APPLIED(lastSeq, digest) alone, synced. The mark is what authorizes the
//	   reclaim: after it, digestAt can still rebuild the digest at the tail from
//	   a stream whose earlier segments are gone. Skipped entirely when the
//	   scanned marks already carry it, so a crash loop cannot accumulate marks.
//	   Like CheckpointAndReclaim's checkpoint, it is charged to the space its own
//	   reclamation frees and is only written when that space dominates it.
//	B. Delete the fully-applied segments in ASCENDING ordinal order, then fsync
//	   the directory. A crash mid-delete always leaves a contiguous ordinal
//	   suffix — the shape scanStream requires — with the barrier-A mark inside it.
//	C. The RELEASE frames, one WriteAt, truncated back to the tail on a short
//	   write, then synced. A crash here leaves a prefix of released scopes; the
//	   next recovery sees them as already-final and sweeps their authority
//	   remainder with Discard, which is exactly the documented shape.
//
// A-before-B is NOT an efficiency choice and must never be inverted to make the
// arithmetic easier. digestAt refuses to rebuild a digest when the retained
// frames start past baseSeq+1, so deleting the earlier segments before a durable
// mark exists in the RETAINED one leaves a stream that fails closed as ErrCorrupt
// across a crash — an unrecoverable outcome traded for a transient byte saving.
// The mark's cost is paid up front, in full, and the budget must accommodate it
// in that order rather than the order that happens to be cheapest.
//
// Because the mark lands while everything it authorizes deleting is still on
// disk, the protocol's PEAK occupancy is not its final footprint. BudgetBytes
// bounds occupancy — a WAL that momentarily exceeds the cap has exceeded it, and
// on a store sized to the cap that moment IS the ENOSPC. So every bound is
// checked before the first byte is written:
//
//	PEAK-A: used + appliedBytes         <= budget   (occupancy at barrier A)
//	FINAL:  used - reclaimable + appliedBytes + releaseBytes <= budget
//
// plus reclaimable >= appliedBytes, without which the mark costs more than the
// reclaim it authorizes ever returns. Barrier C needs no bound of its own: the
// reclaim of barrier B has already happened by then, so C's peak IS the final
// footprint that FINAL bounds. The fast path needs none either, for the mirror
// reason — it reclaims nothing, so its peak is likewise its final footprint,
// which its own single condition bounds.
//
// If any bound fails, NOTHING is written and errCloseOutUnbounded is returned.
// That is a definite terminal answer, not a retry and not a mid-append ENOSPC.
// A physical ENOSPC from one of the close-out's own appends asserts the same
// fact about a device the budget cannot see, so closeOutWrite converts it into
// the same typed answer: see the comment there for why anything else strands the
// grant forever.
func appendRecoveryReleaseCertificate(
	dir string,
	scan *streamScan,
	through uint64,
	digest [32]byte,
	scopes []RebindScope,
	budget int64,
) error {
	if scan == nil || through != scan.lastSeq || len(scopes) == 0 {
		return errors.New("writeback: invalid recovery release certificate")
	}
	hexDigest := fmt.Sprintf("%x", digest)
	// The APPLIED watermark and digest are values recovery computed just now,
	// so they go through the ADMISSION encoder: nothing about them is legacy.
	appliedPayload, err := encodeControlPayload(appliedFrame{Through: through, Digest: hexDigest})
	if err != nil {
		return err
	}
	releasePayloads := make([][]byte, len(scopes))
	var releaseBytes int64
	for i, scope := range scopes {
		if scope.Scope == "" || scope.Epoch == "" {
			return errors.New("writeback: invalid recovery release scope")
		}
		// Already durable in this stream: the frozen frame bound is the only
		// bound that may apply.
		payload, err := encodeDurableControlPayload(delegationFrame{Scope: scope.Scope, Epoch: scope.Epoch})
		if err != nil {
			return err
		}
		releasePayloads[i] = payload
		releaseBytes += frameLen(len(payload))
	}

	segments, err := streamSegmentSizes(dir)
	if err != nil {
		return err
	}
	path, frameNo, end, err := abandonedStreamTail(&abandonedStream{dir: dir, scan: scan})
	if err != nil {
		return err
	}
	var used int64
	for _, seg := range segments {
		used += seg.size
	}
	// An identical mark may already be durable from an interrupted earlier
	// close-out; re-emitting it would grow the log for nothing, and across a
	// crash loop grow it without bound. It only counts when it sits in the
	// segment the reclaim RETAINS — a mark inside a segment about to be deleted
	// authorizes nothing.
	appliedBytes := frameLen(len(appliedPayload))
	if n := len(scan.frames); n > 0 {
		tailOrdinal := scan.frames[n-1].ordinal
		for _, fr := range scan.frames {
			if fr.typ == frameApplied && fr.ordinal == tailOrdinal &&
				bytes.Equal(fr.payload, appliedPayload) {
				appliedBytes = 0
				break
			}
		}
	}

	if budget <= 0 || used+appliedBytes+releaseBytes <= budget {
		var body []byte
		if appliedBytes > 0 {
			body = encodeFrame(body, frameApplied, frameNo+1, 0, appliedPayload)
			frameNo++
		}
		for _, payload := range releasePayloads {
			body = encodeFrame(body, frameRelease, frameNo+1, 0, payload)
			frameNo++
		}
		return closeOutWrite(path, end, body)
	}

	// Legacy accommodation. Every segment but the last is fully applied and
	// unreferenced (offline recovery holds the store lock and has no readers).
	var reclaimable int64
	for _, seg := range segments[:len(segments)-1] {
		reclaimable += seg.size
	}
	// Every bound, decided here, before anything is written. A gate that admits
	// the protocol and then discovers at barrier B that it cannot finish has
	// already overshot the cap and already lost the choice of writing nothing.
	switch {
	case reclaimable < appliedBytes:
		return fmt.Errorf(
			"%w: the %d-byte applied mark authorizing the reclaim costs more than the %d bytes that reclaim returns (%d live segment bytes, %d-byte budget)",
			errCloseOutUnbounded, appliedBytes, reclaimable, used, budget,
		)
	case used+appliedBytes > budget:
		// PEAK-A. The mark must be durable BEFORE the segments it authorizes
		// deleting go away (inverting that order trades a recoverable stream for
		// an ErrCorrupt one), so this sum is genuinely occupied at once. An
		// at-cap pre-upgrade stream simply has nowhere to put it.
		return fmt.Errorf(
			"%w: the close-out's transient peak of %d bytes (%d live segment bytes plus the %d-byte applied mark, which must be durable before the %d reclaimable bytes may be freed) exceeds the %d-byte budget",
			errCloseOutUnbounded, used+appliedBytes, used, appliedBytes, reclaimable, budget,
		)
	case used-reclaimable+appliedBytes+releaseBytes > budget:
		return fmt.Errorf(
			"%w: %d live segment bytes plus a %d-byte close-out for %d scopes exceed the %d-byte budget (%d reclaimable)",
			errCloseOutUnbounded, used, appliedBytes+releaseBytes, len(scopes), budget, reclaimable,
		)
	}

	// Barrier A: the mark that authorizes the reclaim.
	if appliedBytes > 0 {
		body := encodeFrame(nil, frameApplied, frameNo+1, 0, appliedPayload)
		if err := closeOutWrite(path, end, body); err != nil {
			return err
		}
		frameNo++
		end += int64(len(body))
	}
	// Barrier B: reclaim, ascending, so every crash point leaves a contiguous
	// ordinal suffix.
	for _, seg := range segments[:len(segments)-1] {
		if err := os.Remove(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reclaim applied segment %s: %w", filepath.Base(seg.path), err)
		}
	}
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("sync WAL directory after recovery reclaim: %w", err)
	}
	// Barrier C: the releases, now inside the budget.
	var body []byte
	for _, payload := range releasePayloads {
		body = encodeFrame(body, frameRelease, frameNo+1, 0, payload)
		frameNo++
	}
	return closeOutWrite(path, end, body)
}

// writeStreamTailFrames is the indirection every close-out append goes through.
// It exists so a test can observe the stream's occupancy at the exact instant
// each barrier lands — the peak the budget arithmetic must bound — and so a
// physical ENOSPC can be injected at a named barrier without a full disk. In
// production it is appendStreamTailFrames and nothing else.
var writeStreamTailFrames = appendStreamTailFrames

// closeOutWrite performs one of the close-out's own appends and classifies its
// failure.
//
// The budget arithmetic bounds this stream's share of the device; it cannot
// bound the device. A close-out that is arithmetically admissible can still hit
// a physically full filesystem, and the two say the same thing: this close-out
// does not fit. They must therefore reach the caller as the same DEFINITE
// answer. If a raw ENOSPC escapes here, recoverStream's default branch wraps it
// in errRetryable, and because this function is only reached once the whole tail
// is already applied at the authority, the result is an attach that fails
// forever on a condition retrying cannot change, with the delegation grants
// checked out to a stream that can never resolve. errCloseOutUnbounded is the
// answer an operator can actually act on — raise BudgetBytes, or free space —
// so the underlying errno stays wrapped and visible in the message rather than
// being flattened into the typed sentinel.
func closeOutWrite(path string, off int64, body []byte) error {
	err := writeStreamTailFrames(path, off, body)
	if err != nil && errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("%w: the device is physically full: %w", errCloseOutUnbounded, err)
	}
	return err
}

// segmentFile is one retained segment of an offline stream.
type segmentFile struct {
	path string
	size int64
}

// streamSegmentSizes lists a stream's segments in ordinal order with their
// on-disk sizes. Ordinals are zero-padded in the filename, so lexical order is
// ordinal order — the same ordering scanStream and abandonedStreamTail use.
func streamSegmentSizes(dir string) ([]segmentFile, error) {
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: stream %s has no segments", ErrCorrupt, dir)
	}
	sort.Strings(names)
	out := make([]segmentFile, 0, len(names))
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		out = append(out, segmentFile{path: name, size: info.Size()})
	}
	return out, nil
}

// appendStreamTailFrames writes body at off in an offline stream's last segment
// and makes it durable. A short write truncates back to off, so recovery never
// leaves a half frame behind; an empty body is a no-op that still syncs nothing.
func appendStreamTailFrames(path string, off int64, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	active, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	n, writeErr := active.WriteAt(body, off)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		if n > 0 {
			_ = active.Truncate(off)
		}
		_ = active.Close()
		return fmt.Errorf("append recovery release certificate: %w", writeErr)
	}
	if err := active.Sync(); err != nil {
		_ = active.Close()
		return fmt.Errorf("sync recovery release certificate: %w", err)
	}
	if err := active.Close(); err != nil {
		return fmt.Errorf("close recovery release certificate: %w", err)
	}
	return nil
}

// highestAppliedCertificate selects the newest durable local authority
// acknowledgement. Concurrent release workers may append an older snapshot
// after a newer checkpoint, so physical frame order does not imply watermark
// order. Two different digests for the same watermark remain corruption.
func highestAppliedCertificate(marks []appliedFrame, lastSeq uint64) (uint64, [32]byte, error) {
	through := uint64(0)
	digest := digestZero()
	seen := map[uint64][32]byte{0: digest}
	for _, mark := range marks {
		raw, err := hex.DecodeString(mark.Digest)
		if err != nil || len(raw) != len(digest) {
			return 0, digestZero(), fmt.Errorf("%w: applied checkpoint digest malformed", ErrCorrupt)
		}
		var next [32]byte
		copy(next[:], raw)
		if mark.Through > lastSeq {
			return 0, digestZero(), fmt.Errorf(
				"%w: applied checkpoint %d is past local tail %d",
				ErrCorrupt, mark.Through, lastSeq,
			)
		}
		if prior, ok := seen[mark.Through]; ok {
			if next != prior {
				return 0, digestZero(), fmt.Errorf(
					"%w: conflicting applied digests at watermark %d",
					ErrCorrupt, mark.Through,
				)
			}
			continue
		}
		seen[mark.Through] = next
		if mark.Through > through {
			through = mark.Through
			digest = next
		}
	}
	return through, digest, nil
}

// digestAt reconstructs the stream digest at seq from the retained frames
// and the latest APPLIED checkpoint at or below it.
func digestAt(scan *streamScan, marks []appliedFrame, seq uint64) ([32]byte, error) {
	base := digestZero()
	var baseSeq uint64
	for _, m := range marks {
		if m.Through <= seq && m.Through > baseSeq {
			raw, err := hex.DecodeString(m.Digest)
			if err != nil || len(raw) != 32 {
				return base, fmt.Errorf("%w: applied checkpoint digest malformed", ErrCorrupt)
			}
			copy(base[:], raw)
			baseSeq = m.Through
		}
	}
	if scan.firstSeq != 0 && baseSeq+1 < scan.firstSeq && seq > baseSeq {
		return base, fmt.Errorf("%w: retained frames start at %d, cannot rebuild digest from %d", ErrCorrupt, scan.firstSeq, baseSeq)
	}
	for _, fr := range scan.frames {
		if fr.typ != frameMutation || fr.seq <= baseSeq {
			continue
		}
		if fr.seq > seq {
			break
		}
		base = digestNext(base, fr.seq, fr.payload)
	}
	return base, nil
}

// coveringScope resolves the delegation covering p among the recovered
// grants ("" = none).
func coveringScope(live map[string]string, p string) string {
	for s := p; ; {
		if _, ok := live[s]; ok {
			return s
		}
		if s == "" {
			return ""
		}
		s = parentDir(s)
	}
}

// decodePathOf extracts the primary path of a mutation frame without a full
// decode (falls back to the decoder).
func decodePathOf(fr frame) string {
	rec, err := wal.DecodePFR1(fr.payload)
	if err != nil {
		return ""
	}
	if rec.Path != "" {
		return rec.Path
	}
	return strings.TrimSpace(rec.NewPath)
}
