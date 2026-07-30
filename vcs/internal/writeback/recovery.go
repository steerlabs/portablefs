package writeback

import (
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
		var bytes int
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
			bytes += len(tail[j].payload)
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
	// Make every rebound scope locally final in ONE durable append before
	// sending the first Checkin. A crash or failure after any subset of the
	// sequential authority releases then recovers from an empty local live
	// projection and the exact applied certificate, sweeping whichever
	// recovery grants remain instead of trying to rebind already-released
	// scopes.
	if err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, prev, scopes); err != nil {
		return fmt.Errorf("%w: persist recovery release certificate: %v", errRetryable, err)
	}
	for _, sc := range scopes {
		if err := e.remote.ReleaseDelegation(ctx, sc.Scope, sc.Epoch); err != nil {
			return fmt.Errorf("%w: release %q: %v", errRetryable, sc.Scope, err)
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

// appendRecoveryReleaseCertificate appends APPLIED followed by every RELEASE
// to the already-scanned final segment with one physical WriteAt and one sync.
// The store lock guarantees the scanned tail has no concurrent writer.
func appendRecoveryReleaseCertificate(
	dir string,
	scan *streamScan,
	through uint64,
	digest [32]byte,
	scopes []RebindScope,
) error {
	if scan == nil || through != scan.lastSeq || len(scopes) == 0 {
		return errors.New("writeback: invalid recovery release certificate")
	}
	path, frameNo, end, err := abandonedStreamTail(&abandonedStream{dir: dir, scan: scan})
	if err != nil {
		return err
	}
	appliedPayload, err := json.Marshal(appliedFrame{
		Through: through,
		Digest:  fmt.Sprintf("%x", digest),
	})
	if err != nil {
		return err
	}
	body := encodeFrame(nil, frameApplied, frameNo+1, 0, appliedPayload)
	frameNo++
	for _, scope := range scopes {
		if scope.Scope == "" || scope.Epoch == "" {
			return errors.New("writeback: invalid recovery release scope")
		}
		payload, err := json.Marshal(delegationFrame{Scope: scope.Scope, Epoch: scope.Epoch})
		if err != nil {
			return err
		}
		body = encodeFrame(body, frameRelease, frameNo+1, 0, payload)
		frameNo++
	}
	active, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	n, writeErr := active.WriteAt(body, end)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		if n > 0 {
			_ = active.Truncate(end)
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
