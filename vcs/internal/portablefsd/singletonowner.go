package portablefsd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// THE SINGLETON LOCK MUST NOT OUTLIVE A PROCESS THAT WILL NEVER RUN AGAIN.
//
// flock(2) is a DESCRIPTOR lock. The kernel releases it when the last
// descriptor referring to the open file is closed — which for a process means
// during exit. A process that entered exit1() but cannot finish it (see
// kerneldetach.go) therefore holds the state-directory lock forever, and every
// later portablefsd fails to start. On the live incident that is exactly what
// happened, and the only recovery available to the operator was a reboot.
//
// The primary fix is kerneldetach.go: no portablefsd thread may enter an
// uninterruptible kernel wait, so the process can always be killed and the lock
// always released. This file is the second line: a takeover policy that PROVES
// the recorded holder can no longer act, rather than guessing from a timeout.
//
// ── WHAT COUNTS AS PROOF ─────────────────────────────────────────────────────
//
// The holder writes its identity into the lock file while it owns the lock. A
// contender that is refused reads that record and asks the kernel about that
// exact process. Exactly three answers are proof, and none of them is a clock:
//
//   1. NO SUCH PROCESS. The pid is gone.
//   2. DIFFERENT PROCESS. The pid was recycled: its start identity does not
//      match the recorded one, so the recorded holder is gone.
//   3. IN EXIT. The process exists but the kernel has entered process teardown
//      for it (macOS P_WEXIT / a zombie, Linux state Z or X). exit1() has run;
//      the process will never execute another instruction of portablefsd. It
//      cannot open, write, rename or unlink anything in the state directory
//      ever again, so it can no longer be a writer this daemon must exclude.
//
// Case 3 is the incident's case, and it is the one a liveness probe gets wrong:
// the process is still listed, still has the lock, still answers kill(pid, 0) —
// and is nevertheless finished. Note that "unresponsive" is NOT on this list. A
// live daemon that is merely slow keeps its lock.
//
// ── WHY TAKEOVER IS SAFE ─────────────────────────────────────────────────────
//
// The contender cannot take the lock the dead holder still owns, so it REPLACES
// the lock inode: it creates a fresh lock file and renames it over the canonical
// name. The stuck holder keeps an exclusive lock on an unlinked inode nothing
// will ever open again. Two properties make that sound:
//
//   - No OTHER live daemon can be holding the old inode, because the stuck
//     holder holds it exclusively; any competing acquirer is blocked exactly
//     like this one.
//   - Takeovers are serialized through their own lock file, which the stuck
//     holder has never opened, so two contenders cannot both install a new
//     inode.

// singletonOwnerRecord is written into the lock file body by its owner.
type singletonOwnerRecord struct {
	SchemaVersion int    `json:"schemaVersion"`
	PID           int    `json:"pid"`
	StartIdentity string `json:"startIdentity"`
	Version       string `json:"version"`
	Owner         string `json:"owner"`
}

const singletonOwnerSchemaVersion = 1

// holderVerdict is the classification of a recorded lock holder.
type holderVerdict int

const (
	// holderLive means the recorded holder exists and can still act.
	holderLive holderVerdict = iota
	// holderGone means the recorded holder is proven unable to act again.
	holderGone
	// holderUnprovable means the platform could not answer decisively. It is
	// never a takeover: an unprovable holder is treated as live.
	holderUnprovable
)

func (v holderVerdict) String() string {
	switch v {
	case holderLive:
		return "live"
	case holderGone:
		return "gone"
	default:
		return "unprovable"
	}
}

// publishSingletonOwner records this process's identity in the lock file it
// owns. The caller must hold the flock.
func publishSingletonOwner(lock *singletonLock, version, owner string) error {
	if lock == nil || lock.file == nil {
		return errors.New("portablefsd singleton is not open")
	}
	identity, err := processStartIdentity(os.Getpid())
	if errors.Is(err, errProcessStateUnsupported) {
		// No record is written where no record could ever be verified. An
		// unverifiable record would make a recycled pid look like the original
		// holder, and takeover would become the guess this policy refuses to be.
		return nil
	}
	if err != nil {
		return fmt.Errorf("record portablefsd singleton owner identity: %w", err)
	}
	body, err := json.Marshal(singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion,
		PID:           os.Getpid(),
		StartIdentity: identity,
		Version:       version,
		Owner:         owner,
	})
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := lock.file.Truncate(0); err != nil {
		return fmt.Errorf("reset portablefsd singleton owner record: %w", err)
	}
	if _, err := lock.file.WriteAt(body, 0); err != nil {
		return fmt.Errorf("write portablefsd singleton owner record: %w", err)
	}
	if err := lock.file.Sync(); err != nil {
		return fmt.Errorf("sync portablefsd singleton owner record: %w", err)
	}
	return nil
}

// readSingletonOwner reads the owner record from an already-open lock file.
// A missing, empty or unreadable record is (nil, nil): no record is not
// evidence of death, and the caller must treat it as a live holder.
func readSingletonOwner(file *os.File) (*singletonOwnerRecord, error) {
	if file == nil {
		return nil, nil
	}
	body := make([]byte, 4096)
	n, err := file.ReadAt(body, 0)
	if n == 0 {
		return nil, nil
	}
	if err != nil && n == 0 {
		return nil, err
	}
	text := strings.TrimSpace(string(body[:n]))
	if text == "" {
		return nil, nil
	}
	var record singletonOwnerRecord
	if err := json.Unmarshal([]byte(text), &record); err != nil {
		return nil, nil
	}
	if record.SchemaVersion != singletonOwnerSchemaVersion || record.PID <= 0 || record.StartIdentity == "" {
		return nil, nil
	}
	return &record, nil
}

// classifySingletonHolder answers whether the recorded holder can still act.
func classifySingletonHolder(record *singletonOwnerRecord) (holderVerdict, string) {
	if record == nil {
		return holderUnprovable, "the lock carries no owner record"
	}
	state, err := inspectProcessState(record.PID)
	if err != nil {
		if errors.Is(err, errNoSuchProcess) {
			return holderGone, fmt.Sprintf("pid %d does not exist", record.PID)
		}
		if errors.Is(err, errProcessStateUnsupported) {
			return holderUnprovable, fmt.Sprintf("this platform cannot classify pid %d", record.PID)
		}
		return holderUnprovable, fmt.Sprintf("pid %d could not be inspected: %v", record.PID, err)
	}
	if state.startIdentity != record.StartIdentity {
		return holderGone, fmt.Sprintf(
			"pid %d is a different process (start identity %s, recorded %s)",
			record.PID, state.startIdentity, record.StartIdentity,
		)
	}
	if state.exiting {
		return holderGone, fmt.Sprintf(
			"pid %d has entered process exit and will never execute portablefsd code again", record.PID,
		)
	}
	return holderLive, fmt.Sprintf("pid %d is live", record.PID)
}

// errNoSuchProcess and errProcessStateUnsupported are the two decisive shapes
// inspectProcessState can report besides a real state.
var (
	errNoSuchProcess           = errors.New("no such process")
	errProcessStateUnsupported = errors.New("process state classification is unsupported on this platform")
)

// processState is the minimum the takeover policy needs: is this the same
// process that took the lock, and has the kernel already begun tearing it down?
type processState struct {
	startIdentity string
	exiting       bool
}
