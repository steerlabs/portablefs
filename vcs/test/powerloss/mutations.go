package powerloss

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// The acknowledged-mutation ledger: the record the FSKit instrument keeps.
//
// The fsync ledger in ledger.go records write-once files and claims durability
// only where an fsync returned. That shape cannot express the FSKit contract,
// which is stronger and wider: the authority makes every successful FSKit
// mutation reply durable before it is sent, so every acknowledged namespace,
// attribute and data change must survive any later cut. Expressing that needs
// the complete expected namespace after every step, not a list of files, so
// this ledger records one snapshot of the workload subtree per acknowledged
// mutation. The workload is a few dozen steps over a handful of small objects,
// which keeps full snapshots small and lets the verifier compare against them
// directly instead of replaying a change log it would also have to trust.

// MutationKind names one authority mutation the FSKit workload performs. The
// verifier relies on the kind only to know which mutations rewrite file bytes;
// everything else it needs is in the recorded states.
type MutationKind string

const (
	MutationMkdir          MutationKind = "mkdir"
	MutationCreate         MutationKind = "create"
	MutationWrite          MutationKind = "write"
	MutationTruncateHandle MutationKind = "truncate-handle"
	MutationTruncateItem   MutationKind = "truncate-item"
	MutationChmod          MutationKind = "chmod"
	MutationSetTimes       MutationKind = "set-times"
	MutationLink           MutationKind = "link"
	MutationSymlink        MutationKind = "symlink"
	MutationRename         MutationKind = "rename"
	MutationUnlink         MutationKind = "unlink"
	MutationRmdir          MutationKind = "rmdir"
)

func (k MutationKind) known() bool {
	switch k {
	case MutationMkdir, MutationCreate, MutationWrite, MutationTruncateHandle, MutationTruncateItem,
		MutationChmod, MutationSetTimes, MutationLink, MutationSymlink, MutationRename, MutationUnlink, MutationRmdir:
		return true
	default:
		return false
	}
}

// changesData reports whether the mutation rewrites file bytes or size. Those
// are the one kind of change XFS does not apply as a single logged
// transaction: data pages, the on-disk size and a truncated tail reach the
// device separately, so an unacknowledged one may be found partly applied.
func (k MutationKind) changesData() bool {
	return k == MutationWrite || k == MutationTruncateHandle || k == MutationTruncateItem
}

// ObjectKind is the file type of one object in a recorded state.
type ObjectKind string

const (
	ObjectFile      ObjectKind = "file"
	ObjectDirectory ObjectKind = "directory"
	ObjectSymlink   ObjectKind = "symlink"
)

// ContentSpan is one write's bytes inside a file: GenerateContent(Seed,
// Length) placed at Offset. Recording the recipe instead of the bytes keeps
// the ledger small and still lets the verifier rebuild every byte, which the
// stale-data rule needs for a file an unacknowledged write may have torn.
type ContentSpan struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
	Seed   int   `json:"seed"`
}

// ObjectState is the exact expected state of one object.
type ObjectState struct {
	Kind ObjectKind `json:"kind"`
	// Mode is the permission and set-id bits (07777). Symlinks carry none.
	Mode uint32 `json:"mode,omitempty"`
	// Size and Spans describe file content: Size bytes of zeros overlaid, in
	// order, by every span clipped to Size. Later spans win where they overlap.
	Size  int64         `json:"size,omitempty"`
	Spans []ContentSpan `json:"spans,omitempty"`
	// SHA256 is the digest of the content Size and Spans describe. It is
	// redundant on purpose: Validate recomputes it, so a ledger whose recipe
	// and digest disagree is refused before any cut is judged by it.
	SHA256 string `json:"sha256,omitempty"`
	// Links is a file's hard-link count, which must equal the number of names
	// the state gives it.
	Links uint32 `json:"links,omitempty"`
	// Target is a symlink's target.
	Target string `json:"target,omitempty"`
	// AtimeNs and MtimeNs are set only while an explicit SETATTR timestamp is
	// the last change that touched them. A data mutation clears them, because
	// it moves mtime to a time the workload does not choose.
	AtimeNs *int64 `json:"atimeNs,omitempty"`
	MtimeNs *int64 `json:"mtimeNs,omitempty"`
}

// Content rebuilds the bytes the state describes.
func (o ObjectState) Content() []byte {
	if o.Size <= 0 {
		return nil
	}
	content := make([]byte, o.Size)
	for _, span := range o.Spans {
		if span.Offset < 0 || span.Length <= 0 || span.Offset >= o.Size {
			continue
		}
		end := min(span.Offset+span.Length, o.Size)
		copy(content[span.Offset:end], GenerateContent(span.Seed, end-span.Offset))
	}
	return content
}

// TreeState is the complete expected workload subtree after one step. Entries
// maps every volume-relative path to the label of the object it names, so two
// names with one label are hard links of one inode; Objects holds each
// labelled object's state.
type TreeState struct {
	Entries map[string]string      `json:"entries"`
	Objects map[string]ObjectState `json:"objects"`
}

// Clone returns a deep copy, so a recorded snapshot can never change when the
// workload's live model moves on.
func (t TreeState) Clone() TreeState {
	clone := TreeState{Entries: make(map[string]string, len(t.Entries)), Objects: make(map[string]ObjectState, len(t.Objects))}
	for name, label := range t.Entries {
		clone.Entries[name] = label
	}
	for label, object := range t.Objects {
		object.Spans = append([]ContentSpan(nil), object.Spans...)
		if object.AtimeNs != nil {
			value := *object.AtimeNs
			object.AtimeNs = &value
		}
		if object.MtimeNs != nil {
			value := *object.MtimeNs
			object.MtimeNs = &value
		}
		clone.Objects[label] = object
	}
	return clone
}

// MutationStep is one acknowledged authority mutation: what it was, the mark
// taken after its success reply arrived, and the whole subtree state that
// reply made durable.
type MutationStep struct {
	Index       int          `json:"index"`
	Kind        MutationKind `json:"kind"`
	Description string       `json:"description"`
	Mark        string       `json:"mark"`
	State       TreeState    `json:"state"`
}

// MutationLedger is the FSKit workload driver's record of every acknowledged
// mutation, in acknowledgement order.
type MutationLedger struct {
	// Volume is the volume directory name inside the XFS cell, joined by the
	// verifier to wherever it mounted a replayed image.
	Volume string `json:"volume"`
	// Prefix is the single directory the workload owns inside the volume. The
	// first step creates it, so the state before any step is its absence.
	Prefix string `json:"prefix"`
	// Label describes the run in prose and appears in every report.
	Label string         `json:"label"`
	Steps []MutationStep `json:"steps"`
}

// Record appends one acknowledged step with a private copy of its state.
func (l *MutationLedger) Record(kind MutationKind, description, mark string, state TreeState) MutationStep {
	step := MutationStep{Index: len(l.Steps), Kind: kind, Description: description, Mark: mark, State: state.Clone()}
	l.Steps = append(l.Steps, step)
	return step
}

func (l *MutationLedger) markedPoints() []markedPoint {
	if l == nil {
		return nil
	}
	points := make([]markedPoint, 0, len(l.Steps))
	for _, step := range l.Steps {
		points = append(points, markedPoint{
			mark:   step.Mark,
			owner:  fmt.Sprintf("step %d", step.Index),
			reason: fmt.Sprintf("cut at the mark taken immediately after step %d (%s) was acknowledged", step.Index, step.Description),
		})
	}
	return points
}

// Validate rejects a ledger the verifier could misread. Each rule closes a way
// to report a pass that was not earned: a duplicate mark would resolve to the
// wrong cut, a path outside the prefix would let the verifier judge files the
// workload does not own, an unreachable or miscounted object would make the
// link-count and membership checks vacuous, and a recipe that disagrees with
// its digest would make the stale-data rule rebuild the wrong bytes.
func (l *MutationLedger) Validate() error {
	if l.Volume == "" || strings.Contains(l.Volume, "/") || l.Volume == "." || l.Volume == ".." {
		return fmt.Errorf("powerloss: mutation ledger volume %q is not a single directory name", l.Volume)
	}
	if !markPattern.MatchString(l.Prefix) {
		return fmt.Errorf("powerloss: mutation ledger prefix %q is not a single safe path element", l.Prefix)
	}
	if len(l.Steps) == 0 {
		return errors.New("powerloss: mutation ledger records no steps; a run that asserted nothing must fail, not pass")
	}
	marks := make(map[string]int, len(l.Steps))
	for position, step := range l.Steps {
		if step.Index != position {
			return fmt.Errorf("powerloss: step at position %d declares index %d", position, step.Index)
		}
		if !step.Kind.known() {
			return fmt.Errorf("powerloss: step %d has unknown kind %q", position, step.Kind)
		}
		if step.Description == "" {
			return fmt.Errorf("powerloss: step %d carries no description", position)
		}
		if !markPattern.MatchString(step.Mark) {
			return fmt.Errorf("powerloss: step %d mark %q is not a safe mark name", position, step.Mark)
		}
		if previous, exists := marks[step.Mark]; exists {
			return fmt.Errorf("powerloss: steps %d and %d share mark %q", previous, position, step.Mark)
		}
		marks[step.Mark] = position
		if err := step.State.validate(l.Prefix); err != nil {
			return fmt.Errorf("powerloss: step %d state: %w", position, err)
		}
	}
	return nil
}

func (t TreeState) validate(prefix string) error {
	names := make([]string, 0, len(t.Entries))
	for name := range t.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	references := make(map[string]int, len(t.Objects))
	for _, name := range names {
		label := t.Entries[name]
		if err := validateRelative(name); err != nil {
			return err
		}
		if name != prefix && !strings.HasPrefix(name, prefix+"/") {
			return fmt.Errorf("path %q is outside the workload prefix %q", name, prefix)
		}
		if name != prefix {
			parent, exists := t.Entries[path.Dir(name)]
			if !exists || t.Objects[parent].Kind != ObjectDirectory {
				return fmt.Errorf("path %q has no directory entry for its parent", name)
			}
		}
		if _, exists := t.Objects[label]; !exists {
			return fmt.Errorf("path %q names object %q, which the state does not describe", name, label)
		}
		references[label]++
	}
	for label, object := range t.Objects {
		count := references[label]
		if label == "" || count == 0 {
			return fmt.Errorf("object %q is not reachable from any path", label)
		}
		if object.Mode > 0o7777 {
			return fmt.Errorf("object %q has mode %#o outside the permission bits", label, object.Mode)
		}
		hasFileFields := object.Size != 0 || len(object.Spans) != 0 || object.SHA256 != "" || object.Links != 0
		switch object.Kind {
		case ObjectDirectory:
			if count != 1 || hasFileFields || object.Target != "" {
				return fmt.Errorf("directory %q must have exactly one name and no file or symlink state", label)
			}
		case ObjectSymlink:
			if count != 1 || object.Target == "" || strings.ContainsRune(object.Target, 0) ||
				object.Mode != 0 || hasFileFields {
				return fmt.Errorf("symlink %q must have exactly one name, a target, and no mode or file state", label)
			}
		case ObjectFile:
			if object.Target != "" {
				return fmt.Errorf("file %q carries a symlink target", label)
			}
			if object.Links != uint32(count) {
				return fmt.Errorf("file %q records %d links but has %d names", label, object.Links, count)
			}
			if object.Size < 0 {
				return fmt.Errorf("file %q has a negative size", label)
			}
			for _, span := range object.Spans {
				if span.Offset < 0 || span.Length <= 0 || span.Length > object.Size-span.Offset || span.Seed < 0 {
					return fmt.Errorf("file %q has a content span %+v outside its %d bytes", label, span, object.Size)
				}
			}
			if len(object.SHA256) != 2*sha256.Size {
				return fmt.Errorf("file %q has a malformed digest %q", label, object.SHA256)
			}
			if _, err := hex.DecodeString(object.SHA256); err != nil {
				return fmt.Errorf("file %q has a non-hex digest %q", label, object.SHA256)
			}
			if Digest(object.Content()) != object.SHA256 {
				return fmt.Errorf("file %q digest does not match the content its spans describe", label)
			}
		default:
			return fmt.Errorf("object %q has unknown kind %q", label, object.Kind)
		}
	}
	return nil
}

// Save writes the ledger durably; see saveJSON.
func (l *MutationLedger) Save(pathname string) error {
	if err := l.Validate(); err != nil {
		return err
	}
	return saveJSON(pathname, l, "mutation ledger")
}

// LoadMutationLedger reads and validates a mutation ledger. Like LoadLedger,
// an invalid ledger is a hard error: the verifier must never proceed with
// fewer expectations than the driver recorded.
func LoadMutationLedger(pathname string) (*MutationLedger, error) {
	ledger := &MutationLedger{}
	if err := loadJSON(pathname, ledger, "mutation ledger"); err != nil {
		return nil, err
	}
	if err := ledger.Validate(); err != nil {
		return nil, err
	}
	return ledger, nil
}
