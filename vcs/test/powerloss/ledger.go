package powerloss

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Durability is what the workload driver claims about one checkpoint at the
// moment it recorded it. The whole harness turns on this distinction, so the
// two values are named for the promise rather than for the syscall.
type Durability string

const (
	// Fsynced means fsync or fdatasync through the mount returned success
	// before the mark was taken. This is the only value the harness asserts
	// presence for.
	Fsynced Durability = "fsynced"
	// Acknowledged means the write was acknowledged by the authority and
	// nothing was fsynced. The authority applies such a write to the served
	// XFS through sendfile before it acks, so the bytes are in the page cache
	// - but page cache is exactly what a power cut discards. Presence after a
	// cut is therefore permitted, not required.
	Acknowledged Durability = "acknowledged"
)

// Instrument names which harness produced a ledger. The two instruments prove
// different things and are verified differently, so the ledger says which one
// it came from rather than letting the verifier guess from whether marks
// happen to be present.
type Instrument string

const (
	// InstrumentDevice is the dm-log-writes power-cut simulation. Every
	// fsynced checkpoint must carry a mark, because a checkpoint with no mark
	// has no cut to be asserted at and would silently drop out of the run.
	InstrumentDevice Instrument = "device"
	// InstrumentProcess is the authority-SIGKILL restart test. There is no
	// device log and therefore no marks; it is weaker than a power cut because
	// the kernel's dirty page cache survives the kill, and it says so in every
	// report.
	InstrumentProcess Instrument = "process"
)

// markPattern is deliberately narrow. A mark travels through `dmsetup message`
// as an argv word and comes back out of a fixed-size inline log payload, so
// anything a shell could reinterpret, or that could be truncated, must never
// become one.
var markPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Checkpoint is one recorded expectation: a file the workload wrote, the exact
// content it had, and the log mark taken immediately after the durability
// claim was established.
type Checkpoint struct {
	Index      int        `json:"index"`
	Path       string     `json:"path"`
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256"`
	Mark       string     `json:"mark"`
	Durability Durability `json:"durability"`
}

// Ledger is the workload's record of what must be true after a cut. It is
// written by the driver process that ran on the mount and read by the verifier
// that inspects a replayed image, so it is the only channel between them and
// is deliberately plain JSON.
type Ledger struct {
	// Volume is the volume directory name inside the XFS cell. A replayed
	// image is mounted at an arbitrary path, so the verifier joins its own
	// root with this rather than trusting an absolute path from the driver.
	Volume string `json:"volume"`
	// Instrument is which harness produced this ledger, and decides whether
	// marks are mandatory.
	Instrument Instrument `json:"instrument"`
	// Label describes the run in prose and appears in every report.
	Label       string       `json:"label"`
	Checkpoints []Checkpoint `json:"checkpoints"`
}

// Digest is the content hash the ledger records. SHA-256 mirrors the digest
// the rest of the repository content-addresses with; the harness does not
// introduce a second one.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Add appends a checkpoint and returns it. It is the only way to build a
// ledger, so every checkpoint goes through Validate's rules at Save time.
func (l *Ledger) Add(relative string, content []byte, mark string, durability Durability) Checkpoint {
	checkpoint := Checkpoint{
		Index:      len(l.Checkpoints),
		Path:       relative,
		Size:       int64(len(content)),
		SHA256:     Digest(content),
		Mark:       mark,
		Durability: durability,
	}
	l.Checkpoints = append(l.Checkpoints, checkpoint)
	return checkpoint
}

// Marks returns every mark the ledger refers to, in checkpoint order.
func (l *Ledger) Marks() []string {
	marks := make([]string, 0, len(l.Checkpoints))
	for _, checkpoint := range l.Checkpoints {
		if checkpoint.Mark != "" {
			marks = append(marks, checkpoint.Mark)
		}
	}
	return marks
}

// Validate rejects a ledger the verifier could misread. Every rule here exists
// because breaking it would let the harness report a pass it did not earn: a
// duplicate mark would resolve to the wrong cut, a relative path that escapes
// the volume would verify a file outside it, and an empty ledger would let a
// driver that did nothing look like a driver that proved everything.
func (l *Ledger) Validate() error {
	if l.Volume == "" {
		return errors.New("powerloss: ledger has no volume name")
	}
	if strings.Contains(l.Volume, "/") || l.Volume == "." || l.Volume == ".." {
		return fmt.Errorf("powerloss: ledger volume %q is not a single directory name", l.Volume)
	}
	switch l.Instrument {
	case InstrumentDevice, InstrumentProcess:
	default:
		return fmt.Errorf("powerloss: ledger names no known instrument (got %q)", l.Instrument)
	}
	if len(l.Checkpoints) == 0 {
		return errors.New("powerloss: ledger records no checkpoints; a run that asserted nothing must fail, not pass")
	}
	seenMarks := make(map[string]int, len(l.Checkpoints))
	seenPaths := make(map[string]int, len(l.Checkpoints))
	for position, checkpoint := range l.Checkpoints {
		if checkpoint.Index != position {
			return fmt.Errorf("powerloss: checkpoint at position %d declares index %d", position, checkpoint.Index)
		}
		switch checkpoint.Durability {
		case Fsynced, Acknowledged:
		default:
			return fmt.Errorf("powerloss: checkpoint %d has unknown durability %q", position, checkpoint.Durability)
		}
		if err := validateRelative(checkpoint.Path); err != nil {
			return fmt.Errorf("powerloss: checkpoint %d: %w", position, err)
		}
		if previous, exists := seenPaths[checkpoint.Path]; exists {
			// Every checkpoint file is written once and never rewritten. That
			// is what makes the torn-write rule in Verify sound: the only
			// bytes a crash can leave in one of these files are bytes this
			// workload wrote, or zeros.
			return fmt.Errorf("powerloss: checkpoints %d and %d both write %q; checkpoint files must be write-once", previous, position, checkpoint.Path)
		}
		seenPaths[checkpoint.Path] = position
		if len(checkpoint.SHA256) != 2*sha256.Size {
			return fmt.Errorf("powerloss: checkpoint %d has a malformed digest %q", position, checkpoint.SHA256)
		}
		if _, err := hex.DecodeString(checkpoint.SHA256); err != nil {
			return fmt.Errorf("powerloss: checkpoint %d has a non-hex digest %q", position, checkpoint.SHA256)
		}
		if checkpoint.Size < 0 {
			return fmt.Errorf("powerloss: checkpoint %d has a negative size", position)
		}
		if checkpoint.Mark == "" {
			if l.Instrument == InstrumentDevice && checkpoint.Durability == Fsynced {
				return fmt.Errorf("powerloss: fsynced checkpoint %d has no mark; there would be no cut to assert it at", position)
			}
			continue
		}
		if l.Instrument == InstrumentProcess {
			return fmt.Errorf("powerloss: checkpoint %d carries mark %q, but the process instrument has no device log to resolve it against", position, checkpoint.Mark)
		}
		if !markPattern.MatchString(checkpoint.Mark) {
			return fmt.Errorf("powerloss: checkpoint %d mark %q is not a safe mark name", position, checkpoint.Mark)
		}
		if previous, exists := seenMarks[checkpoint.Mark]; exists {
			return fmt.Errorf("powerloss: checkpoints %d and %d share mark %q", previous, position, checkpoint.Mark)
		}
		seenMarks[checkpoint.Mark] = position
	}
	return nil
}

func validateRelative(relative string) error {
	if relative == "" {
		return errors.New("checkpoint path is empty")
	}
	if path.IsAbs(relative) {
		return fmt.Errorf("checkpoint path %q is absolute", relative)
	}
	if path.Clean(relative) != relative {
		return fmt.Errorf("checkpoint path %q is not in clean form", relative)
	}
	for _, element := range strings.Split(relative, "/") {
		if element == ".." || element == "." || element == "" {
			return fmt.Errorf("checkpoint path %q escapes the volume", relative)
		}
	}
	return nil
}

// Save writes the ledger durably. The driver is killed on purpose while this
// harness runs, so the ledger is written to a temporary name, fsynced, renamed
// and the directory fsynced - a truncated ledger would make the verifier
// report a product failure that is really a harness failure.
func (l *Ledger) Save(pathname string) error {
	if err := l.Validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("powerloss: encode ledger: %w", err)
	}
	encoded = append(encoded, '\n')
	pending := pathname + ".pending"
	file, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("powerloss: create ledger: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("powerloss: write ledger: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("powerloss: sync ledger: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("powerloss: close ledger: %w", err)
	}
	if err := os.Rename(pending, pathname); err != nil {
		return fmt.Errorf("powerloss: publish ledger: %w", err)
	}
	directory, err := os.Open(dirOf(pathname))
	if err != nil {
		return fmt.Errorf("powerloss: open ledger directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("powerloss: sync ledger directory: %w", err)
	}
	return nil
}

func dirOf(pathname string) string {
	if index := strings.LastIndex(pathname, "/"); index > 0 {
		return pathname[:index]
	}
	return "."
}

// LoadLedger reads and validates a ledger. A ledger that does not validate is
// a hard error rather than an empty result: the verifier must never proceed
// with fewer expectations than the driver recorded.
func LoadLedger(pathname string) (*Ledger, error) {
	raw, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("powerloss: read ledger: %w", err)
	}
	ledger := &Ledger{}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(ledger); err != nil {
		return nil, fmt.Errorf("powerloss: decode ledger: %w", err)
	}
	if err := ledger.Validate(); err != nil {
		return nil, err
	}
	sort.SliceStable(ledger.Checkpoints, func(i, j int) bool {
		return ledger.Checkpoints[i].Index < ledger.Checkpoints[j].Index
	})
	return ledger, nil
}
