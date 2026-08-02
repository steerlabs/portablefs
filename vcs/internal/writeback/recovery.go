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

	// PendingBasis names the rule PendingRecords/PendingBytes were counted
	// under. It exists because the two numbers are a PROMISE the next attach
	// reconciles its replay against, and a promise counted under a different
	// rule than the one that checks it is not checkable at all.
	//
	// pendingBasisLane is the only rule a writer of this build uses: a record is
	// pending when its OWN LANE's applied watermark does not cover it — exactly
	// the set laneTailFrames selects and exactly the set replay drains. The
	// field is empty on a job written before this round, whose counters used the
	// GLOBAL applied prefix instead. That basis over-counts by construction (a
	// wedged lane pins the global prefix while another lane's applied records sit
	// above it), so an empty basis is reported as-is and never reconciled — an
	// over-count is not evidence of loss.
	PendingBasis string `json:"pendingBasis,omitempty"`

	LastError string           `json:"lastError,omitempty"`
	Conflicts []ConflictDetail `json:"conflicts,omitempty"`

	// ── THE UNREPLAYABLE VERDICT ─────────────────────────────────────────────
	//
	// Set only when a parked job was PROVEN unreplayable and contained (see
	// recoveryRunner.contain). Until then every field here is zero, so a job
	// that is merely retrying is never mistaken for a job that lost data.
	//
	// Quarantined says the stream's bytes were moved aside and its authority
	// grants swept, so the namespace it covered is usable again. The Lost*
	// fields are the DEFINITE loss statement an operator acts on: how much
	// acknowledged data never reached the authority and which scopes it was
	// written under. Remedy names what to do about it.
	Quarantined    bool     `json:"quarantined,omitempty"`
	QuarantinePath string   `json:"quarantinePath,omitempty"`
	LostRecords    uint64   `json:"lostRecords,omitempty"`
	LostBytes      uint64   `json:"lostBytes,omitempty"`
	LostScopes     []string `json:"lostScopes,omitempty"`
	Remedy         string   `json:"remedy,omitempty"`
}

// Unrecovered reports the acknowledged bytes this job still holds that the
// authority has never made durable. It is nonzero for a parked job that has not
// drained AND for a contained one whose bytes are unrecoverable — in both cases
// the data is locally durable and not at the authority, which is the only thing
// a drain-completeness check may conclude from.
func (j RecoveryJob) Unrecovered() (records uint64, bytes uint64) {
	if j.Quarantined {
		return j.LostRecords, j.LostBytes
	}
	return j.PendingRecords, j.PendingBytes
}

// pendingBasisLane is the one accounting rule this build's park paths use for
// PendingRecords/PendingBytes: per LANE, not per global prefix. See
// RecoveryJob.PendingBasis.
const pendingBasisLane = "lane"

// laneTailStats counts the mutation frames each lane has NOT applied at mark,
// with their exact payload bytes.
//
// It is the ONE definition of "what this stream still owes the authority", and
// both halves of the parked-tail contract are stated in it: the park records it
// as its promise, and the replay reconciles against it before it applies a
// single record. Counting the two ends differently is what let a park promise 34
// records, a replay drain 2, and the difference be reported as nothing at all.
func laneTailStats(mutations []frame, mark streamMark) (records, bytes uint64) {
	for _, fr := range mutations {
		if fr.laneSeq > mark.lanes[fr.lane].through {
			records++
			bytes += uint64(len(fr.payload))
		}
	}
	return records, bytes
}

// verifyTailPrefixConsistent proves the tail about to be replayed is, in every
// lane, a DENSE run from the verified base to the retained tail.
//
// ── WHY THIS IS THE PROPERTY, NOT AN EXTRA CHECK ─────────────────────────────
//
// A lane is a chain, and a chain has exactly one meaning: record N+1 is defined
// on the state record N produced. So a replay that cannot apply record N may not
// apply record N+1 either — not "should not", CANNOT, because what it would be
// applying N+1 to is not the state N+1 was written against. When it does anyway,
// the loss stops being a truncated tail and becomes a HOLE: a 0.94 MiB run of
// zeros in the middle of a 1 GiB file, with correct data on both sides of it and
// nothing anywhere saying so. Zeros where acknowledged bytes belong are worse
// than a short file, because a short file is visibly short.
//
// Nothing else in the replay path establishes this. scanStream proves the
// RETAINED frames are dense in global sequence, and the lane sequence is derived
// by counting them — so within the retained set a gap cannot exist. What it
// cannot prove is the join: the retained set begins wherever a reclaimed prefix
// left it, the base is whatever the authority (or the local certificate) names,
// and the two are separate facts. If the first retained record of a lane sits
// above base+1, every record between them is simply absent from the replay, and
// every later record is applied on top of the gap. The per-lane completeness
// check at the END of the drain does not see it either: it compares the position
// reached against the retained tail, and both sides of that comparison come from
// the same retained set the missing records are already absent from.
func verifyTailPrefixConsistent(tail []frame, pos streamMark, tails [streamLaneCount]uint64) error {
	for lane := range pos.lanes {
		l := StreamLane(lane)
		want := pos.lanes[lane].through
		for _, fr := range tail {
			if fr.lane != l {
				continue
			}
			want++
			if fr.laneSeq != want {
				return fmt.Errorf(
					"%w: %s-lane replay would apply record %d over a missing record %d; "+
						"a chain cannot be continued across a gap, and applying the later record would write a hole",
					ErrCorrupt, l, fr.laneSeq, want,
				)
			}
		}
		if want != tails[lane] {
			return fmt.Errorf(
				"%w: %s-lane replay covers through %d but the retained WAL tail is %d",
				ErrCorrupt, l, want, tails[lane],
			)
		}
	}
	return nil
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

// retarget repoints the registry at the stream's new directory after a
// containment rename, so later persists land beside the bytes they describe.
func (js *jobState) retarget(streamDir string) {
	js.mu.Lock()
	js.path = filepath.Join(streamDir, "job.json")
	js.mu.Unlock()
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

// errForeignStream marks a parked stream that belongs to another volume or
// branch. It is reported and never adopted — and, unlike every other terminal
// verdict, never contained: its grants and its bytes are not this engine's to
// sweep or move.
var errForeignStream = errors.New("writeback: parked stream belongs to another volume or branch")

// recoveryRunner reconciles every parked stream of this store at engine
// open, BEFORE the mount serves. A stream either drains fully, or parks in
// an explicit terminal state (conflict/corrupt/foreign — surfaced, never
// blocking peers silently); a transient failure fails the attach.
type recoveryRunner struct {
	e *Engine

	mu     sync.Mutex
	parked map[string]*jobState // stream dir -> registry (terminal only, post-open)
	// contained holds the CONTAINED jobs: proven unreplayable, their namespace
	// already released, their bytes moved aside. They are never attempted
	// again — retrying a proof does not change it — but they stay surfaced on
	// every attach, forever, so the loss cannot become invisible.
	contained map[string]*jobState
}

func newRecoveryRunner(e *Engine) *recoveryRunner {
	return &recoveryRunner{
		e:         e,
		parked:    map[string]*jobState{},
		contained: map[string]*jobState{},
	}
}

// quarantineDirName holds streams whose replay was proven impossible. It is
// deliberately NOT a "stream-" directory: the recovery scan, the force-park
// inventory and the epoch allocator all key off that prefix, and a contained
// stream must never again be mistaken for a replay candidate.
const quarantineDirName = "unreplayable"

// discover registers every parked stream directory and returns the highest
// epoch seen (the live stream picks the next one).
func (r *recoveryRunner) discover() uint64 {
	var maxEpoch uint64
	entries, err := os.ReadDir(r.e.cfg.StateDir)
	if err != nil {
		return 0
	}
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
	return max(maxEpoch, r.discoverContained())
}

// discoverContained re-registers every previously contained stream so its
// verdict is reported on this attach too. A contained stream's epoch still
// counts toward the high-water mark: its writeback identity is durable at the
// authority's ledger and must never be minted twice.
func (r *recoveryRunner) discoverContained() uint64 {
	root := filepath.Join(r.e.cfg.StateDir, quarantineDirName)
	entries, err := os.ReadDir(root)
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
		dir := filepath.Join(root, ent.Name())
		job, ok := loadJob(dir)
		if !ok {
			// The bytes are there but the verdict is not readable. Report the
			// containment anyway — an unreadable verdict is still a loss, and
			// silence is the one answer that is never allowed here.
			job = RecoveryJob{
				State:     JobCorrupt,
				WALEpoch:  epoch,
				LastError: "contained stream has no readable recovery verdict",
			}
		}
		job.Quarantined = true
		job.QuarantinePath = dir
		r.contained[dir] = newJobState(dir, job)
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
	case isUnreplayable(err):
		// PROVEN unreplayable. Leaving it parked is what turned a lost tail
		// into a lost NAMESPACE: the stream's grants stay checked out to a
		// dead writeback identity, so every enumeration of the covered subtree
		// fails with EAGAIN on every future attach, including clean ones. The
		// tail is gone either way — no retry, no setting, and no later attach
		// changes a proof — so the only question left is whether the loss also
		// takes the directory with it. Contain it: sweep the grants, move the
		// bytes aside, and publish a definite verdict.
		if containErr := r.contain(ctx, dir, js, err); containErr != nil {
			return containErr
		}
		return nil
	default:
		// Terminal but NOT proven unreplayable — a foreign stream, or a
		// close-out an operator can still make fit. It stays registered for
		// surfacing and keeps its grants; the mount serves.
		if persistErr := js.persist(); persistErr != nil {
			return fmt.Errorf("writeback: persist terminal recovery state for %s: %w", filepath.Base(dir), persistErr)
		}
		return nil
	}
}

// contain makes a proven-unreplayable stream harmless to everything except
// itself, in an order every crash point survives:
//
//  1. Publish the verdict INTO the stream directory and sync it. Everything
//     after this point is idempotent, so a crash simply repeats it.
//  2. Sweep the authority grants bound to this stream. This is the step that
//     gives the namespace back: until it runs, the covered subtree answers
//     EAGAIN for every peer and every future attach. A transport failure here
//     fails the attach — loudly and retryably — rather than serving a mount
//     whose namespace is still hostage.
//  3. Rename the stream out of the scan path, atomically, and sync both
//     parents. A crash before the rename leaves a stream that is re-proven
//     unreplayable and re-contained; a crash after it leaves a contained
//     stream carrying its verdict.
//
// The bytes are KEPT. They are unrecoverable through this protocol, not
// worthless: they are the only remaining copy of what was acknowledged, and an
// operator (or a forensic tool) may still extract from them. Deleting them
// would turn a reported loss into an unexaminable one.
func (r *recoveryRunner) contain(ctx context.Context, dir string, js *jobState, cause error) error {
	records, bytes, scopes, wbID := summarizeUnreplayableStream(dir, js.snapshot())
	js.update(func(j *RecoveryJob) {
		if j.State != JobConflict {
			j.State = JobCorrupt
		}
		if j.LastError == "" {
			j.LastError = cause.Error()
		}
		if wbID != "" {
			j.WritebackID = wbID
		}
		j.Quarantined = true
		j.QuarantinePath = filepath.Join(r.e.cfg.StateDir, quarantineDirName, filepath.Base(dir))
		j.LostRecords, j.LostBytes, j.LostScopes = records, bytes, scopes
		j.PendingRecords, j.PendingBytes = records, bytes
		j.Remedy = unreplayableRemedy(j)
	})
	if err := js.persist(); err != nil {
		return fmt.Errorf("writeback: publish unreplayable verdict for %s: %w", filepath.Base(dir), err)
	}
	if wbID != "" {
		if err := r.e.remote.Discard(ctx, wbID, nil); err != nil {
			return fmt.Errorf(
				"writeback: release the namespace held by unreplayable stream %s: %w",
				filepath.Base(dir), err,
			)
		}
	}
	moved, err := quarantineStreamDir(r.e.cfg.StateDir, dir)
	if err != nil {
		return fmt.Errorf("writeback: contain unreplayable stream %s: %w", filepath.Base(dir), err)
	}
	js.retarget(moved)
	r.mu.Lock()
	delete(r.parked, dir)
	r.contained[moved] = js
	r.mu.Unlock()
	job := js.snapshot()
	r.e.logf(
		"writeback: parked stream %s CANNOT be replayed (%v); %d acknowledged record(s) / %d byte(s) under %v are unrecoverable; the bytes are kept at %s and the namespace has been released",
		job.WritebackID, cause, job.LostRecords, job.LostBytes, job.LostScopes, moved,
	)
	return nil
}

// isUnreplayable reports a terminal verdict that no retry, no operator setting
// and no later attach can change.
//
// The two exclusions are the whole content of the predicate. A FOREIGN stream
// belongs to another volume or branch: this engine has no standing to sweep its
// grants or move its bytes, and its replayability is not this engine's finding.
// An UNBOUNDED CLOSE-OUT is definite but not final: its tail is already applied
// at the authority and only the local close-out does not fit, which an operator
// resolves by raising the budget or freeing the device — containing it would
// throw away a stream that is one setting away from finishing.
func isUnreplayable(err error) bool {
	switch {
	case err == nil, errors.Is(err, errRetryable):
		return false
	case errors.Is(err, errForeignStream), errors.Is(err, errCloseOutUnbounded):
		return false
	default:
		return true
	}
}

func unreplayableRemedy(j *RecoveryJob) string {
	if j.LostRecords == 0 {
		return "No acknowledged record was lost: the stream held nothing the authority had not already made durable. " +
			"The retained bytes may be deleted once the verdict has been noted."
	}
	return fmt.Sprintf(
		"%d acknowledged record(s) (%d byte(s)) written under %v never reached the authority and cannot be replayed. "+
			"Treat every path under those scopes as having lost its most recent writes, re-copy them from the source if one exists, "+
			"and keep %s until you have done so — it holds the only remaining copy.",
		j.LostRecords, j.LostBytes, j.LostScopes, j.QuarantinePath,
	)
}

// summarizeUnreplayableStream states the loss as exactly as the stream still
// allows. It is deliberately best-effort in that order: the exact frame-level
// count when the stream still decodes, the parked job's own durable counters
// when it does not. A stream too damaged to enumerate is exactly the one whose
// loss must still be reported rather than reported as zero.
func summarizeUnreplayableStream(dir string, job RecoveryJob) (records, bytes uint64, scopes []string, wbID string) {
	records, bytes, wbID = job.PendingRecords, job.PendingBytes, job.WritebackID
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		return records, bytes, nil, wbID
	}
	if wbID == "" {
		wbID = streamID(scan.header.MountID, scan.header.WALEpoch)
	}
	live, mutations, marks, _, decodeErr := decodeStreamFrames(scan.frames)
	applied := job.AppliedThrough
	if decodeErr == nil {
		if cert, certErr := highestAppliedCertificate(marks, scan.lastSeq); certErr == nil {
			applied = max(applied, cert.global)
		}
	}
	if decodeErr == nil {
		// The frame-level count is per LANE, matching the basis both park paths
		// record and the basis replay reconciles against — but only when the
		// certificates FOLD. A stream whose certificates contradict each other is
		// one of the two shapes that reach containment at all, and it has no lane
		// position: reading its lanes as zero would count every retained record
		// as lost, including the ones the authority demonstrably applied. That
		// stream's only surviving position is the job's own global watermark, so
		// it is counted against that, exactly as before.
		var scanRecords, scanBytes uint64
		if cert, certErr := highestAppliedCertificate(marks, scan.lastSeq); certErr == nil {
			scanRecords, scanBytes = laneTailStats(mutations, streamMark{global: applied, lanes: cert.lanes})
		} else {
			for _, fr := range mutations {
				if fr.seq > applied {
					scanRecords++
					scanBytes += uint64(len(fr.payload))
				}
			}
		}
		// The LARGER of the two, never the frame count alone. The job's durable
		// counters are what the park PROMISED was still owed to the authority;
		// the frame count is what the stream can still produce. When they differ
		// the difference is precisely the loss this verdict exists to state, and
		// overwriting the promise with the remainder would report the vanished
		// records as never having existed.
		records, bytes = max(records, scanRecords), max(bytes, scanBytes)
		for scope := range live {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
	}
	return records, bytes, scopes, wbID
}

// quarantineStreamDir moves a stream out of the scan path with one atomic
// rename and makes both directory changes durable.
func quarantineStreamDir(stateDir, dir string) (string, error) {
	root := filepath.Join(stateDir, quarantineDirName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	if err := fsyncDir(stateDir); err != nil {
		return "", err
	}
	target := filepath.Join(root, filepath.Base(dir))
	if _, err := os.Lstat(target); err == nil {
		// Epochs are allocated from a durable monotone high-water mark, so a
		// collision here means the store's identity has been reused. Refuse
		// rather than overwrite the earlier verdict and its bytes.
		return "", fmt.Errorf("writeback: quarantine slot %s already exists", target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(dir, target); err != nil {
		return "", err
	}
	if err := fsyncDir(stateDir); err != nil {
		return "", err
	}
	if err := fsyncDir(root); err != nil {
		return "", err
	}
	return target, nil
}

func (r *recoveryRunner) jobs() []RecoveryJob {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecoveryJob, 0, len(r.parked)+len(r.contained))
	for _, js := range r.parked {
		out = append(out, js.snapshot())
	}
	for _, js := range r.contained {
		out = append(out, js.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WALEpoch < out[j].WALEpoch })
	return out
}

// unrecovered is the store's whole durable-but-unapplied debt outside the live
// stream: every parked job that has not drained plus every contained one whose
// bytes are unrecoverable. It is what makes a drain-completeness answer honest —
// see Engine.Pending.
func (r *recoveryRunner) unrecovered() (records uint64, bytes uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, js := range r.parked {
		jr, jb := js.snapshot().Unrecovered()
		records, bytes = records+jr, bytes+jb
	}
	for _, js := range r.contained {
		jr, jb := js.snapshot().Unrecovered()
		records, bytes = records+jr, bytes+jb
	}
	return records, bytes
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
		return errForeignStream
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

	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	// ── RECONCILE THE PARK'S OWN PROMISE, BEFORE ANYTHING IS SENT ────────────
	//
	// The park published a DEFINITE count of the acknowledged records it was
	// holding. This is the only moment that count can still be checked against
	// the bytes it was a count OF, and it has to be checked before the first
	// record is shipped: once a suffix has been applied, "the stream is shorter
	// than it promised" is no longer a recoverable situation, it is a hole.
	//
	// Only a SHORTFALL is a finding. The claim may legitimately sit BELOW the
	// retained tail — a re-entered replay records its own dwindling remainder as
	// it goes, and the authority may already hold records whose acknowledgement
	// was lost — so the one direction that means anything is `claim > have`:
	// records the park promised are no longer in the stream at all.
	// That is unreplayable, and it must reach a reported verdict rather than a
	// success that drains what is left and calls the difference zero.
	claim := js.snapshot()
	promisedRecords, promisedBytes := claim.PendingRecords, claim.PendingBytes
	if claim.PendingBasis == pendingBasisLane {
		haveRecords, haveBytes := laneTailStats(mutations, cert)
		if claim.PendingRecords > haveRecords || claim.PendingBytes > haveBytes {
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = fmt.Sprintf(
					"the parked snapshot promised %d acknowledged record(s) / %d byte(s) but the stream retains only %d / %d",
					claim.PendingRecords, claim.PendingBytes, haveRecords, haveBytes)
			})
			return fmt.Errorf(
				"%w: parked stream lost %d of %d acknowledged record(s) before replay",
				ErrCorrupt, claim.PendingRecords-min(claim.PendingRecords, haveRecords), claim.PendingRecords,
			)
		}
	}
	ss, err := e.remote.StreamState(ctx, wbID)
	if err != nil {
		return fmt.Errorf("%w: stream state: %v", errRetryable, err)
	}
	// ── THE PER-LANE RECOVERY POSITION ───────────────────────────────────────
	//
	// A lane is an independently-applicable chain, so "where is this stream"
	// is one question PER LANE, and the answers can legitimately disagree: the
	// namespace lane is normally ahead of the data lane, which is the whole
	// point of splitting them. The authority's ledger is the truth when it has
	// one; the local APPLIED certificate is the truth when it does not (the
	// stream was fully drained and its ledger retired).
	tails := laneTails(scan, cert)
	var pos streamMark
	for lane := range pos.lanes {
		l := StreamLane(lane)
		want := cert.lanes[lane]
		if ss.Exists {
			want = laneMark{through: ss.LaneThrough(l), digest: ss.LaneDigest(l)}
		}
		if want.through > tails[lane] {
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = fmt.Sprintf("authority %s-lane watermark %d is past the local tail %d", l, want.through, tails[lane])
			})
			return errors.New("watermark past local tail")
		}
		local, derr := laneDigestAt(scan, marks, l, want.through)
		if derr != nil {
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = derr.Error()
			})
			return derr
		}
		if want.through == 0 {
			// A lane with nothing applied has no digest to agree about: the
			// chain base is the same constant on both sides by construction.
			want.digest = local
		}
		if local != want.digest {
			if ss.Exists {
				js.update(func(j *RecoveryJob) {
					j.State = JobConflict
					j.LastError = fmt.Sprintf("%s-lane digest diverged from the authority's durable state", l)
					j.Conflicts = []ConflictDetail{{Kind: "DIGEST_MISMATCH"}}
				})
				return errors.New("digest mismatch")
			}
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = "local applied certificate does not match the retained stream"
			})
			return errors.New("local applied certificate mismatch")
		}
		pos.lanes[lane] = laneMark{through: want.through, digest: local}
	}
	tail := laneTailFrames(mutations, pos)
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
		reply, err := e.remote.Rebind(ctx, wbID, scopes, markState(pos))
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
			// Accept only a STRICTLY FORWARD move in at least one lane, with
			// every lane still provable from this WAL. Nothing else is a race;
			// everything else is a real conflict.
			if next.Exists {
				forward, ok := true, false
				var advanced streamMark
				for lane := range advanced.lanes {
					l := StreamLane(lane)
					want := laneMark{through: next.LaneThrough(l), digest: next.LaneDigest(l)}
					if want.through < pos.lanes[lane].through || want.through > tails[lane] {
						forward = false
						break
					}
					if want.through > pos.lanes[lane].through {
						ok = true
					}
					local, digestErr := laneDigestAt(scan, marks, l, want.through)
					if digestErr != nil {
						js.update(func(j *RecoveryJob) {
							j.State = JobCorrupt
							j.LastError = digestErr.Error()
						})
						return digestErr
					}
					if want.through == 0 {
						want.digest = local
					}
					if local != want.digest {
						forward = false
						break
					}
					advanced.lanes[lane] = laneMark{through: want.through, digest: local}
				}
				if forward && ok {
					pos = advanced
					tail = laneTailFrames(mutations, pos)
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

	// ── DRAIN THE TAIL, LANE BY LANE ─────────────────────────────────────────
	//
	// The order is legacy, then namespace, then data, and it is the order that
	// makes the replay sound rather than a convenience:
	//
	//   - LEGACY first because it is a strict prefix of the stream: the lane
	//     boundary is only crossed once every unlaned record is applied, so a
	//     WAL that holds laned frames holds NO unapplied legacy ones. This arm
	//     is empty in every laned stream and carries the whole tail in every
	//     pre-upgrade one.
	//   - NAMESPACE next, in full. Nothing in the namespace lane depends on
	//     anything outside it (the lane router guarantees it), so it can always
	//     be replayed first.
	//   - DATA last. Every data record's namespace dependency is ≤ the namespace
	//     lane's total, which is now applied, so no batch can be held.
	//
	// Each lane chains from its own verified base and names its own watermark.
	tail = laneTailFrames(mutations, pos)
	// PREFIX CONSISTENCY, proved before the first record is shipped. See
	// verifyTailPrefixConsistent: a lane whose tail does not begin exactly at
	// its verified base+1 has records missing UNDER the ones about to be
	// applied, and applying them anyway is how a lost tail becomes a mid-file
	// hole. There is nothing to salvage record-by-record here — the lane is a
	// chain — so the answer is one terminal verdict for the stream.
	if err := verifyTailPrefixConsistent(tail, pos, tails); err != nil {
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	drained := 0
	// The BYTE half of the replay's own progress, tracked beside the record
	// half. It used to be absent, and the absence was a silent dishonesty of its
	// own: a replay that shipped every record left PendingRecords at 0 and
	// PendingBytes at whatever the park had written, so a job mid-replay — and
	// any job that was re-attempted from a persisted snapshot — carried a byte
	// count that no longer described anything. Two counters that are supposed to
	// be two views of one set must move together or neither can be trusted.
	var tailBytes, drainedBytes uint64
	for _, fr := range tail {
		tailBytes += uint64(len(fr.payload))
	}
	for _, lane := range [...]StreamLane{StreamLaneLegacy, StreamLaneNamespace, StreamLaneData} {
		laneFrames := make([]frame, 0, len(tail))
		for _, fr := range tail {
			if fr.lane == lane {
				laneFrames = append(laneFrames, fr)
			}
		}
		if len(laneFrames) == 0 {
			continue
		}
		prev := pos.lanes[lane].digest
		i := 0
		for i < len(laneFrames) {
			var records []wal.Record
			var scopeRuns []FlushScope
			var bytes int64
			var nsRequired uint64
			end := prev
			j := i
			for ; j < len(laneFrames) && len(records) < flushMaxRecords && bytes < laneMaxBytes(lane); j++ {
				scope := coveringScope(live, decodePathOf(laneFrames[j]))
				if scope == "" {
					missingSeq := laneFrames[j].seq
					js.update(func(job *RecoveryJob) {
						job.State = JobCorrupt
						job.LastError = fmt.Sprintf("record %d has no covering delegation", missingSeq)
					})
					return errors.New("record without covering delegation")
				}
				rec, err := wal.DecodePFR1(laneFrames[j].payload)
				if err != nil {
					js.update(func(jb *RecoveryJob) {
						jb.State = JobCorrupt
						jb.LastError = err.Error()
					})
					return err
				}
				rec.Seq = laneFrames[j].laneSeq
				end = digestNext(end, laneFrames[j].laneSeq, laneFrames[j].payload)
				nsRequired = max(nsRequired, laneFrames[j].nsRequired)
				records = append(records, rec)
				bytes += int64(len(laneFrames[j].payload))
				if len(scopeRuns) != 0 && scopeRuns[len(scopeRuns)-1].Scope == scope {
					scopeRuns[len(scopeRuns)-1].Through = laneFrames[j].laneSeq
				} else {
					scopeRuns = append(scopeRuns, FlushScope{
						Scope: scope, Epoch: live[scope], Through: laneFrames[j].laneSeq,
					})
				}
			}
			if lane != StreamLaneData {
				nsRequired = 0
			}
			reply, err := e.remote.FlushResolved(ctx, FlushRequest{
				WritebackID: wbID, Lane: lane, NSRequired: nsRequired,
				PrevDigest: prev, EndDigest: end,
				Records: records, ScopeRuns: scopeRuns,
			})
			if err != nil {
				return fmt.Errorf("%w: recovery flush: %v", errRetryable, err)
			}
			if reply.Status != 0 {
				js.update(func(jb *RecoveryJob) {
					jb.State = JobConflict
					jb.LastError = fmt.Sprintf("recovery %s-lane flush rejected with status %d", lane, reply.Status)
				})
				return errors.New("recovery flush rejected")
			}
			// A success must name this batch's exact end. A short watermark would
			// drop unshipped records; a watermark past the sent end claims bytes
			// this request never supplied.
			if batchEnd := laneFrames[j-1].laneSeq; reply.Through != batchEnd {
				js.update(func(jb *RecoveryJob) {
					jb.State = JobConflict
					jb.LastError = fmt.Sprintf("recovery %s-lane flush succeeded with authority watermark %d, want exact batch end %d", lane, reply.Through, batchEnd)
				})
				return errors.New("recovery flush watermark short of batch end")
			}
			prev = end
			pos.lanes[lane] = laneMark{through: reply.Through, digest: end}
			drained += j - i
			drainedBytes += uint64(bytes)
			i = j
			remaining := len(tail) - drained
			remainingBytes := tailBytes - min(tailBytes, drainedBytes)
			// The registry's AppliedThrough is a GLOBAL-sequence progress
			// figure, and a per-lane replay does not produce one directly: the
			// lanes are drained one after another, so no single lane watermark
			// is a prefix of the stream mid-replay. What IS exact at every step
			// is how many records are still outstanding, so the global figure
			// is derived from the tail rather than from a lane.
			applied := scan.lastSeq
			if uint64(remaining) < applied {
				applied -= uint64(remaining)
			} else {
				applied = 0
			}
			if err := js.updateDebounced(func(jb *RecoveryJob) {
				jb.AppliedThrough = applied
				jb.PendingRecords = uint64(remaining)
				jb.PendingBytes = remainingBytes
				jb.PendingBasis = pendingBasisLane
			}); err != nil {
				return fmt.Errorf("%w: persist recovery progress: %v", errRetryable, err)
			}
		}
		if pos.lanes[lane].through != tails[lane] {
			err := fmt.Errorf("%w: recovery %s-lane drain ended at %d before WAL tail %d",
				ErrCorrupt, lane, pos.lanes[lane].through, tails[lane])
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = err.Error()
			})
			return err
		}
	}
	for lane := range pos.lanes {
		if pos.lanes[lane].through != tails[lane] {
			err := fmt.Errorf("%w: recovery %s-lane drain ended at %d before WAL tail %d",
				ErrCorrupt, StreamLane(lane), pos.lanes[lane].through, tails[lane])
			js.update(func(j *RecoveryJob) {
				j.State = JobCorrupt
				j.LastError = err.Error()
			})
			return err
		}
	}
	// Every selected record was shipped. This is a statement about the drain
	// loop itself, not about the stream, and it is asserted rather than assumed
	// because everything downstream — the removal of the stream directory, the
	// job leaving the parked set, Pending() returning to zero — is authorized by
	// it. A success that shipped fewer records than it selected is the exact
	// shape this round exists to make impossible.
	if drained != len(tail) {
		err := fmt.Errorf("%w: recovery drained %d of the %d selected record(s)",
			ErrCorrupt, drained, len(tail))
		js.update(func(j *RecoveryJob) {
			j.State = JobCorrupt
			j.LastError = err.Error()
		})
		return err
	}
	pos.global = scan.lastSeq
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
	if err := appendRecoveryReleaseCertificate(dir, scan, pos, scopes, e.cfg.BudgetBytes); err != nil {
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
	// The count is what was actually SHIPPED, and the promise it satisfied is
	// named beside it. Reporting the size of the selection instead made the one
	// number an operator reads to check a replay against the park a restatement
	// of the replay's own opinion of itself.
	e.logf("writeback: recovered stream %s: %d record(s) drained, satisfying the parked promise of %d record(s) / %d byte(s); %d scope(s) released",
		wbID, drained, promisedRecords, promisedBytes, len(scopes))
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
	mark streamMark,
	scopes []RebindScope,
	budget int64,
) error {
	if scan == nil || mark.global != scan.lastSeq || len(scopes) == 0 {
		return errors.New("writeback: invalid recovery release certificate")
	}
	// The APPLIED watermark and every lane digest are values recovery computed
	// just now, so they go through the ADMISSION encoder: nothing about them is
	// legacy.
	appliedPayload, err := encodeControlPayload(mark.appliedFrame())
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
	//
	// The test is SEMANTIC, not byte equality. What authorizes the reclaim is
	// the POSITION the durable certificate decodes to, and the same position has
	// more than one valid encoding — a pre-round-7 stream spells its legacy
	// watermark as Through alone, where this close-out spells it with the
	// self-describing legacy field as well. Comparing bytes would call those two
	// different marks and charge for a duplicate that adds nothing, which on an
	// at-cap pre-upgrade stream is the difference between a close-out that fits
	// and one that parks the grant in a typed conflict forever.
	appliedBytes := frameLen(len(appliedPayload))
	if n := len(scan.frames); n > 0 {
		tailOrdinal := scan.frames[n-1].ordinal
		for _, fr := range scan.frames {
			if fr.typ != frameApplied || fr.ordinal != tailOrdinal {
				continue
			}
			if bytes.Equal(fr.payload, appliedPayload) {
				appliedBytes = 0
				break
			}
			var durable appliedFrame
			if json.Unmarshal(fr.payload, &durable) != nil {
				continue
			}
			position, derr := durable.mark()
			if derr == nil && sameAppliedPosition(position, mark) {
				appliedBytes = 0
				break
			}
		}
	}

	if budget <= 0 || used+appliedBytes+releaseBytes <= budget {
		var body []byte
		if appliedBytes > 0 {
			body = encodeFrame(body, frameApplied, StreamLaneLegacy, frameNo+1, 0, appliedPayload)
			frameNo++
		}
		for _, payload := range releasePayloads {
			body = encodeFrame(body, frameRelease, StreamLaneLegacy, frameNo+1, 0, payload)
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
		body := encodeFrame(nil, frameApplied, StreamLaneLegacy, frameNo+1, 0, appliedPayload)
		if err := closeOutWrite(path, end, body); err != nil {
			return err
		}
		frameNo++
		end += int64(len(body))
	}
	// Barrier B: reclaim, ascending, EACH UNLINK MADE DURABLE BEFORE THE NEXT IS
	// ISSUED, so that every crash point leaves a contiguous ordinal suffix.
	//
	// Ascending issue order alone does not buy that. Persistence order is not
	// syscall order: two unlinks with no directory barrier between them may
	// reach media in either order, or one and not the other. A single trailing
	// fsyncDir therefore leaves the whole batch unordered against a crash, and
	// the crash that persists the unlink of ordinal 2 but not ordinal 1 leaves
	// the HOLE {0,2,3}. That is not a survivable state: scanStreamWithTailRepair
	// rejects a gap in the ordinal chain as ErrCorrupt, recoverStream maps
	// ErrCorrupt to JobCorrupt, and attempt() treats JobCorrupt as terminal — so
	// the stream parks forever with its delegation grants still checked out.
	//
	// One fsyncDir per unlink makes each removal a barrier of its own, which is
	// what reduces the reachable crash states to prefixes of this loop, which is
	// exactly the contiguous-suffix retained set the reader accepts. Close-out
	// runs once per abandoned stream, so paying N directory syncs here is free
	// next to the alternative of an unrecoverable stream.
	for _, seg := range segments[:len(segments)-1] {
		if err := reclaimUnlinkSegment(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reclaim applied segment %s: %w", filepath.Base(seg.path), err)
		}
		if err := reclaimSyncDir(dir); err != nil {
			return fmt.Errorf("sync WAL directory after reclaiming %s: %w", filepath.Base(seg.path), err)
		}
	}
	// Barrier C: the releases, now inside the budget.
	var body []byte
	for _, payload := range releasePayloads {
		body = encodeFrame(body, frameRelease, StreamLaneLegacy, frameNo+1, 0, payload)
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

// sameAppliedPosition reports whether two marks name the same durable position.
// A lane with nothing applied has no digest to agree about: the chain base is
// the same constant on both sides by construction, and callers legitimately
// spell it either as that constant or as the zero value.
func sameAppliedPosition(a, b streamMark) bool {
	if a.global != b.global {
		return false
	}
	for lane := range a.lanes {
		if a.lanes[lane].through != b.lanes[lane].through {
			return false
		}
		if a.lanes[lane].through != 0 && a.lanes[lane].digest != b.lanes[lane].digest {
			return false
		}
	}
	return true
}

// highestAppliedCertificate folds every durable local authority
// acknowledgement into one position. Concurrent release workers may append an
// older snapshot after a newer checkpoint, so physical frame order does not
// imply watermark order.
//
// ── WHY THE AGREEMENT TEST IS PER LANE, NOT PER GLOBAL WATERMARK ─────────────
//
// The exactly-once proof is "one lane watermark names exactly one chain
// digest". It is a statement about a LANE, because a chain is a lane. Two
// certificates that name the same GLOBAL watermark and different lane marks are
// not a contradiction about anything — they are the ORDINARY steady state of a
// laned stream, and the reason is structural:
//
//   - The global prefix is the lowest still-unshipped global sequence minus one
//     over ALL lanes (see flusher.recomputeStreamLocked). One stuck record pins
//     it, however far the other lanes run.
//   - Each lane's watermark advances on its own. That independence is the whole
//     point of splitting the lanes.
//
// So a wedged data lane pins the global watermark while the namespace lane
// keeps applying, and every certificate written in that window — one per drained
// scope release, one per reclaiming checkpoint — carries the same Through and a
// different namespace mark. Reading that as WAL corruption condemned a stream
// that was in perfect health: the parked tail became unreplayable, its bytes
// unrecoverable, and its delegation grants stayed checked out to a dead stream
// forever. That is the defect this function exists in its present form to close.
//
// What IS corruption is two different digests for the SAME lane at the SAME lane
// watermark: one chain cannot have two values at one position.
//
// The result is the per-lane MAXIMUM rather than one certificate's snapshot.
// Each certificate is an independent durable statement about each lane, and
// authority lane watermarks only advance, so the highest watermark seen for a
// lane is proven durable for that lane regardless of which frame carried it.
// Taking one frame's whole array instead could adopt an OLDER position for a
// lane that a different frame had already proven further along.
func highestAppliedCertificate(marks []appliedFrame, lastSeq uint64) (streamMark, error) {
	best := streamMark{}
	for lane := range best.lanes {
		best.lanes[lane].digest = digestZero()
	}
	zero := digestZero()
	// lane watermark -> chain digest at it. Seeded with the chain base, which is
	// the same constant on both sides by construction.
	seen := make([]map[uint64][32]byte, streamLaneCount)
	for lane := range seen {
		seen[lane] = map[uint64][32]byte{0: zero}
	}
	for _, mark := range marks {
		decoded, err := mark.mark()
		if err != nil {
			return streamMark{}, err
		}
		if mark.Through > lastSeq {
			return streamMark{}, fmt.Errorf(
				"%w: applied checkpoint %d is past local tail %d",
				ErrCorrupt, mark.Through, lastSeq,
			)
		}
		for lane := range decoded.lanes {
			lm := decoded.lanes[lane]
			if lm.through == 0 {
				// A lane with nothing applied has no digest to agree about.
				lm.digest = zero
			}
			if prior, ok := seen[lane][lm.through]; ok && prior != lm.digest {
				return streamMark{}, fmt.Errorf(
					"%w: conflicting %s-lane applied digests at lane watermark %d",
					ErrCorrupt, StreamLane(lane), lm.through,
				)
			}
			seen[lane][lm.through] = lm.digest
			if lm.through > best.lanes[lane].through {
				best.lanes[lane] = lm
			}
		}
		best.global = max(best.global, mark.Through)
	}
	return best, nil
}

// digestAt reconstructs the LEGACY-lane digest at global sequence seq from the
// retained frames and the latest APPLIED checkpoint at or below it.
//
// In the legacy era the lane sequence IS the global sequence, so this is the
// same function it has always been. Past the boundary the legacy chain is
// frozen and every laned frame is skipped, which is exactly right: the legacy
// digest at any point after the boundary is the digest at the boundary.
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
		if fr.typ != frameMutation || fr.lane != StreamLaneLegacy || fr.seq <= baseSeq {
			continue
		}
		if fr.seq > seq {
			break
		}
		base = digestNext(base, fr.laneSeq, fr.payload)
	}
	return base, nil
}

// laneDigestAt reconstructs LANE's chain digest at laneSeq from the retained
// frames and the newest APPLIED checkpoint at or below it in that lane.
//
// It is the per-lane form of digestAt and works for the same reason: a
// certificate carries every lane's (watermark, digest) at one applied prefix,
// so the newest certificate not past laneSeq is a valid base for that lane, and
// the retained frames of that lane chain forward from it.
func laneDigestAt(scan *streamScan, marks []appliedFrame, lane StreamLane, laneSeq uint64) ([32]byte, error) {
	base := digestZero()
	var baseSeq uint64
	for _, m := range marks {
		decoded, err := m.mark()
		if err != nil {
			return base, err
		}
		lm := decoded.lanes[lane]
		if lm.through <= laneSeq && lm.through > baseSeq {
			base, baseSeq = lm.digest, lm.through
		}
	}
	if first := scan.laneFirst[lane]; first != 0 && baseSeq+1 < first && laneSeq > baseSeq {
		return base, fmt.Errorf("%w: retained %s-lane frames start at %d, cannot rebuild digest from %d",
			ErrCorrupt, lane, first, baseSeq)
	}
	for _, fr := range scan.frames {
		if fr.typ != frameMutation || fr.lane != lane || fr.laneSeq <= baseSeq {
			continue
		}
		if fr.laneSeq > laneSeq {
			break
		}
		base = digestNext(base, fr.laneSeq, fr.payload)
	}
	return base, nil
}

// laneTailFrames selects the mutation frames each lane has NOT applied, in
// physical order. A frame belongs to the tail when its own lane's watermark
// does not cover it — never when some other lane's does.
func laneTailFrames(mutations []frame, pos streamMark) []frame {
	var tail []frame
	for _, fr := range mutations {
		if fr.laneSeq > pos.lanes[fr.lane].through {
			tail = append(tail, fr)
		}
	}
	return tail
}

// markState renders a recovery position as the wire-facing stream view the
// rebind claims.
func markState(pos streamMark) StreamState {
	return StreamState{
		Exists:  true,
		Through: pos.lanes[StreamLaneLegacy].through, Digest: pos.lanes[StreamLaneLegacy].digest,
		NSThrough: pos.lanes[StreamLaneNamespace].through, NSDigest: pos.lanes[StreamLaneNamespace].digest,
		DataThrough: pos.lanes[StreamLaneData].through, DataDigest: pos.lanes[StreamLaneData].digest,
	}
}

// laneTails is the highest retained LANE sequence per lane, falling back to the
// certificate's watermark for a lane whose whole prefix was reclaimed.
func laneTails(scan *streamScan, cert streamMark) [streamLaneCount]uint64 {
	var tails [streamLaneCount]uint64
	for lane := range tails {
		tails[lane] = cert.lanes[lane].through
	}
	for _, fr := range scan.frames {
		if fr.typ == frameMutation && fr.laneSeq > tails[fr.lane] {
			tails[fr.lane] = fr.laneSeq
		}
	}
	return tails
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
