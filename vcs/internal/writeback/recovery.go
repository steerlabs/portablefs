package writeback

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// second: the WAL is the durability record; job.json is advisory surfacing.
func (js *jobState) updateDebounced(fn func(*RecoveryJob)) {
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
		_ = js.persist()
	}
}

// persist writes job.json by atomic temporary-file replacement followed by a
// parent-directory fsync.
func (js *jobState) persist() error {
	js.mu.Lock()
	body, err := json.MarshalIndent(js.job, "", "  ")
	js.mu.Unlock()
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp := js.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	if err := os.Rename(tmp, js.path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(js.path))
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
		_ = js.persist()
		return fmt.Errorf("writeback: parked stream %s not drained: %w", filepath.Base(dir), err)
	default:
		// Terminal (conflict/corrupt/foreign): stays registered for
		// surfacing; the mount serves — the scopes stay fenced server-side
		// and typed locally, nothing is silently merged.
		_ = js.persist()
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
	_ = js.persist()

	ss, err := e.remote.StreamState(ctx, wbID)
	if err != nil {
		return fmt.Errorf("%w: stream state: %v", errRetryable, err)
	}
	through := uint64(0)
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
	reply, err := e.remote.Rebind(ctx, wbID, scopes, through, localDigest)
	if err != nil {
		return fmt.Errorf("%w: rebind: %v", errRetryable, err)
	}
	if len(reply.Conflicts) > 0 {
		js.update(func(j *RecoveryJob) {
			j.State = JobConflict
			j.LastError = "recovery scopes moved on the authority"
			j.Conflicts = reply.Conflicts
		})
		return errors.New("rebind conflict")
	}

	// Drain the dense tail as same-scope runs, chaining the digest forward.
	prev := localDigest
	i := 0
	for i < len(tail) {
		scope := coveringScope(live, decodePathOf(tail[i]))
		if scope == "" {
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = fmt.Sprintf("record %d has no covering delegation", tail[i].seq)
			})
			return errors.New("record without covering delegation")
		}
		var records []wal.Record
		var bytes int
		end := prev
		j := i
		for ; j < len(tail) && len(records) < flushMaxRecords && bytes < flushMaxBytes; j++ {
			if coveringScope(live, decodePathOf(tail[j])) != scope {
				break
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
		}
		reply, err := e.remote.Flush(ctx, FlushRequest{
			WritebackID: wbID, Scope: scope, Epoch: live[scope],
			PrevDigest: prev, EndDigest: end, Records: records,
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
		i = j
		js.updateDebounced(func(jb *RecoveryJob) {
			jb.AppliedThrough = reply.Through
			jb.PendingRecords = uint64(len(tail) - i)
		})
	}
	for _, sc := range scopes {
		if err := e.remote.ReleaseDelegation(ctx, sc.Scope, sc.Epoch); err != nil {
			return fmt.Errorf("%w: release %q: %v", errRetryable, sc.Scope, err)
		}
	}
	// Sweep any grant still bound to this stream that never reached a local
	// DELEGATION frame (a crash between the authority's journal row and the
	// client's append): it admitted nothing, so discarding it is lossless.
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
