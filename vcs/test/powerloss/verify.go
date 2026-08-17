package powerloss

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Requirement is what the harness asserts about one checkpoint at one cut. The
// three values are the whole contract, and nothing outside them is claimed.
type Requirement string

const (
	// RequirePresent: an fsync through the mount returned success before the
	// cut, so unix.Fdatasync had returned on the target descriptor in the
	// authority. The file must exist after recovery with exactly the bytes the
	// workload wrote. A missing or different file here is a durability defect.
	RequirePresent Requirement = "present"
	// RequirePermitted: the write was acknowledged but never fsynced, or it
	// was fsynced only after this cut. The authority acknowledges a write
	// transaction once sendfile has applied the staged bytes to the XFS inode,
	// which puts them in the page cache and nowhere else, so a power cut may
	// legitimately discard them. Absent, empty, partial and complete are all
	// conforming outcomes.
	//
	// One thing is still asserted: whatever bytes ARE there must be bytes this
	// workload wrote, or zeros. Checkpoint files are write-once, so any other
	// byte would be stale data XFS exposed from a previously freed extent,
	// which is a defect at any cut.
	RequirePermitted Requirement = "permitted"
	// RequireAbsentOrPermitted is the same permission with an additional note
	// that the checkpoint's own mark had not yet been reached, so the file's
	// absence is the expected outcome rather than merely a tolerated one.
	RequireAbsentOrPermitted Requirement = "absent-or-permitted"
)

// Expectation binds one checkpoint to one requirement at one cut.
type Expectation struct {
	Checkpoint  Checkpoint
	Requirement Requirement
	// Why states, in the report, the reason this requirement and not a
	// stronger one applies.
	Why string
}

// Expectations derives what must hold at a cut that replayed every log entry
// up to and including endEntry.
//
// This function is the entire durability contract, and it is deliberately
// stingy. It demands presence only where an fsync had already returned
// success, and it demands nothing at all about content that was merely
// acknowledged. Widening any rule here would make the harness assert a promise
// the authority does not make; narrowing one would make a green run
// meaningless.
func Expectations(log *Log, ledger *Ledger, endEntry int) ([]Expectation, error) {
	if log == nil || ledger == nil {
		return nil, errors.New("powerloss: Expectations needs both a log and a ledger")
	}
	expectations := make([]Expectation, 0, len(ledger.Checkpoints))
	for _, checkpoint := range ledger.Checkpoints {
		reached := false
		if checkpoint.Mark != "" {
			index, found := log.MarkEntry(checkpoint.Mark)
			if !found {
				return nil, fmt.Errorf("powerloss: checkpoint %d claims mark %q but the log does not carry it", checkpoint.Index, checkpoint.Mark)
			}
			reached = index <= endEntry
		}
		switch {
		case checkpoint.Durability == Fsynced && reached:
			expectations = append(expectations, Expectation{
				Checkpoint:  checkpoint,
				Requirement: RequirePresent,
				Why:         "fsync through the mount returned success before this cut",
			})
		case checkpoint.Durability == Fsynced:
			expectations = append(expectations, Expectation{
				Checkpoint:  checkpoint,
				Requirement: RequireAbsentOrPermitted,
				Why:         "the cut precedes this checkpoint's fsync",
			})
		default:
			expectations = append(expectations, Expectation{
				Checkpoint:  checkpoint,
				Requirement: RequirePermitted,
				Why:         "the write was acknowledged but never fsynced, so it lived only in the page cache a power cut discards",
			})
		}
	}
	return expectations, nil
}

// ExpectationsAfterRestart derives what must hold after the authority process
// was SIGKILLed and restarted, with no power cut and therefore no device log.
//
// The requirements are deliberately identical in shape to the device
// instrument's, and deliberately no stronger. A SIGKILL leaves the kernel's
// dirty page cache intact, so in practice an acknowledged-but-un-fsynced write
// will usually still be readable afterwards - but "usually" is not a contract,
// and asserting it would encode the current implementation instead of the
// promise. The only thing demanded is that every write whose fsync returned
// success is intact.
func ExpectationsAfterRestart(ledger *Ledger) ([]Expectation, error) {
	if ledger == nil {
		return nil, errors.New("powerloss: ExpectationsAfterRestart needs a ledger")
	}
	if ledger.Instrument != InstrumentProcess {
		return nil, fmt.Errorf("powerloss: ExpectationsAfterRestart needs a %s ledger, got %q", InstrumentProcess, ledger.Instrument)
	}
	expectations := make([]Expectation, 0, len(ledger.Checkpoints))
	for _, checkpoint := range ledger.Checkpoints {
		expectation := Expectation{
			Checkpoint:  checkpoint,
			Requirement: RequirePermitted,
			Why:         "the write was acknowledged but never fsynced; a restart owes it nothing",
		}
		if checkpoint.Durability == Fsynced {
			expectation.Requirement = RequirePresent
			expectation.Why = "fsync through the mount returned success before the authority was killed"
		}
		expectations = append(expectations, expectation)
	}
	return expectations, nil
}

// Finding is one conforming or non-conforming observation.
type Finding struct {
	Checkpoint  Checkpoint
	Requirement Requirement
	// Observed describes what recovery actually left, in every case including
	// the conforming ones, so a green report shows how much survived rather
	// than only that nothing broke.
	Observed string
	Err      error
}

// Report is the outcome of verifying one cut.
type Report struct {
	EndEntry int
	Findings []Finding
	// Durable counts checkpoints that were required to be present and were.
	Durable int
	// Surviving counts checkpoints that were permitted to vanish and did not.
	Surviving int
}

// Failures returns the non-conforming findings.
func (r Report) Failures() []Finding {
	failures := make([]Finding, 0, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.Err != nil {
			failures = append(failures, finding)
		}
	}
	return failures
}

// Err joins every failure into one error, or returns nil.
func (r Report) Err() error {
	failures := r.Failures()
	if len(failures) == 0 {
		return nil
	}
	messages := make([]string, 0, len(failures))
	for _, failure := range failures {
		messages = append(messages, fmt.Sprintf("checkpoint %d (%s, %s, requirement %s): %v",
			failure.Checkpoint.Index, failure.Checkpoint.Path, failure.Checkpoint.Durability, failure.Requirement, failure.Err))
	}
	sort.Strings(messages)
	where := fmt.Sprintf("at the cut ending at log entry %d", r.EndEntry)
	if r.EndEntry < 0 {
		// The process instrument has no device log and therefore no entry to
		// name; saying "entry -1" would read as a harness bug.
		where = "after the restart"
	}
	return fmt.Errorf("powerloss: %d of %d checkpoints did not honour the durability contract %s:\n- %s",
		len(failures), len(r.Findings), where, strings.Join(messages, "\n- "))
}

// Verify inspects a recovered volume root against a set of expectations.
//
// root is the volume directory inside a mounted, already-recovered filesystem
// - the caller mounts the replayed image, which is what runs XFS log recovery,
// and passes <mountpoint>/<ledger.Volume>.
func Verify(root string, expectations []Expectation, endEntry int) Report {
	report := Report{EndEntry: endEntry, Findings: make([]Finding, 0, len(expectations))}
	for _, expectation := range expectations {
		finding := verifyOne(root, expectation)
		switch {
		case finding.Err != nil:
		case expectation.Requirement == RequirePresent:
			report.Durable++
		case strings.HasPrefix(finding.Observed, "present"):
			report.Surviving++
		}
		report.Findings = append(report.Findings, finding)
	}
	return report
}

func verifyOne(root string, expectation Expectation) Finding {
	checkpoint := expectation.Checkpoint
	finding := Finding{Checkpoint: checkpoint, Requirement: expectation.Requirement}
	name := filepath.Join(root, filepath.FromSlash(checkpoint.Path))
	content, err := os.ReadFile(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if expectation.Requirement == RequirePresent {
			finding.Observed = "absent"
			finding.Err = fmt.Errorf("fsync had returned success before this cut, so the file must exist after recovery; it does not")
			return finding
		}
		finding.Observed = "absent"
		return finding
	case err != nil:
		finding.Observed = "unreadable"
		finding.Err = fmt.Errorf("reading the recovered file failed: %w", err)
		return finding
	}
	digest := Digest(content)
	if digest == checkpoint.SHA256 && int64(len(content)) == checkpoint.Size {
		finding.Observed = fmt.Sprintf("present, complete (%d bytes)", len(content))
		return finding
	}
	if expectation.Requirement == RequirePresent {
		finding.Observed = fmt.Sprintf("present, %d bytes, digest %s", len(content), digest)
		finding.Err = fmt.Errorf("fsync had returned success before this cut, so the content must be exactly the %d bytes digesting to %s", checkpoint.Size, checkpoint.SHA256)
		return finding
	}
	// A partially-applied write is conforming, but only if every byte present
	// is a byte this workload wrote. Anything else is stale data from a
	// previously freed extent, and no cut permits that.
	if int64(len(content)) > checkpoint.Size {
		finding.Observed = fmt.Sprintf("present, %d bytes", len(content))
		finding.Err = fmt.Errorf("recovery left more bytes than the workload ever wrote (%d)", checkpoint.Size)
		return finding
	}
	written, err := torn(name, checkpoint, content)
	if err != nil {
		finding.Observed = fmt.Sprintf("present, %d bytes", len(content))
		finding.Err = err
		return finding
	}
	finding.Observed = fmt.Sprintf("present, partial (%d of %d bytes carry written content)", written, checkpoint.Size)
	return finding
}

// torn checks the one property a partial file must still honour: every
// non-zero byte equals the byte the workload wrote at that offset. That needs
// the original payload, which the ledger deliberately does not carry - a
// ledger with every byte in it would be the size of the workload. Checkpoint
// content is generated deterministically from the checkpoint index instead, by
// the same GenerateContent the driver used, so the verifier can reconstruct it
// and the ledger stays small.
func torn(name string, checkpoint Checkpoint, content []byte) (int64, error) {
	expected := GenerateContent(checkpoint.Index, checkpoint.Size)
	if Digest(expected) != checkpoint.SHA256 {
		// The ledger was not produced by GenerateContent, so this harness
		// cannot tell a torn write from stale data. Fail rather than skip:
		// silently dropping the stale-data check would make a green run claim
		// more than it verified.
		return 0, fmt.Errorf("checkpoint content is not reproducible, so the stale-data check on %s cannot run", name)
	}
	var written int64
	for offset, actual := range content {
		if actual == 0 {
			continue
		}
		if actual != expected[offset] {
			return 0, fmt.Errorf("recovery exposed a byte at offset %d that this workload never wrote (%#x, expected %#x or zero): stale data from a freed extent", offset, actual, expected[offset])
		}
		written++
	}
	return written, nil
}

// GenerateContent produces the deterministic payload for a checkpoint. It is
// shared by the workload driver and the verifier so that a partially applied
// write can still be distinguished from stale data without the ledger having
// to carry every byte.
//
// The stream must contain no zero bytes: a zero is how the verifier recognises
// a byte that never landed, and a payload that legitimately contained zeros
// would make a lost byte indistinguishable from a written one.
func GenerateContent(index int, size int64) []byte {
	if size <= 0 {
		return nil
	}
	content := make([]byte, size)
	state := uint64(index)*0x9e3779b97f4a7c15 + 0x243f6a8885a308d3
	for offset := range content {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		value := byte(state)
		if value == 0 {
			value = 0xff
		}
		content[offset] = value
	}
	return content
}
