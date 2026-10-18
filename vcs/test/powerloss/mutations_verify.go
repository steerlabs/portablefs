package powerloss

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// The FSKit durability contract, expressed per cut.
//
// FSKit has no fsync callback, so the authority makes every successful FSKit
// mutation reply durable before it is sent or retained for replay: a mutation
// on an open description fsyncs that description, and a handleless namespace
// or attribute mutation runs syncfs on the authority's retained XFS-root
// description. The driver takes a mark only after the success reply arrived.
// So, unlike the Linux workload, every acknowledged mutation must survive
// every cut taken at or after its mark, exactly:
//
//   - every acknowledged name exists and names an object of the recorded kind;
//     every name an acknowledged unlink or rename removed is gone, and every
//     directory lists exactly its recorded names;
//   - every file has exactly its recorded bytes, size, mode and hard-link
//     count, names sharing a label are one inode, and an explicitly set
//     timestamp is exactly what was set;
//   - every symlink has its recorded target, every directory its mode.
//
// Between two marks the driver may have sent exactly one more mutation. It may
// have reached storage not at all, wholly, or - for the parts XFS does not
// apply in one logged transaction - partly. The cut must then match the
// acknowledged state or the in-flight step's state as a whole, with two stated
// allowances that are properties of an unacknowledged change, not of any
// acknowledged one:
//
//   - file bytes and size the in-flight step rewrites follow the stale-data
//     rule: each byte is the acknowledged byte, the in-flight byte, or a zero
//     where one of the two states has no byte. Data pages, the on-disk size
//     and a truncated tail are separate device writes, and a write is never
//     promised to be atomic, so a page-granular mix is conforming; any other
//     byte is stale data or a lost acknowledged byte and fails every cut. The
//     in-flight step's own mtime is unchecked, since a write moves it.
//   - an object the in-flight step creates may carry a mode other than the
//     requested one: the authority creates it and then applies the exact mode
//     in a second transaction.
//
// Namespace changes are not relaxed. Each one is a single XFS transaction, so
// a half-applied rename or link is a defect even though no reply was sent.

// MutationCut is the contract at one cut of an acknowledged-mutation run.
type MutationCut struct {
	EndEntry int
	// Acknowledged counts the steps whose mark the cut reached; every one of
	// them must be present exactly.
	Acknowledged int
	// Durable is the state the last acknowledged step left, or the empty state
	// (prefix absent) before the first.
	Durable TreeState
	// InFlight is the step after the last reached mark, which may have reached
	// storage before the cut. Nil when the cut follows the final mark.
	InFlight *MutationStep
}

// MutationCutAt derives the contract at a cut that replayed every log entry up
// to and including endEntry. Every step's mark must be in the log, in
// acknowledgement order: a missing or reordered mark means the mark channel
// broke, and every cut would then be judged against the wrong state.
func MutationCutAt(log *Log, ledger *MutationLedger, endEntry int) (MutationCut, error) {
	if log == nil || ledger == nil {
		return MutationCut{}, errors.New("powerloss: MutationCutAt needs both a log and a ledger")
	}
	previous := -1
	acknowledged := 0
	for position, step := range ledger.Steps {
		entry, found := log.MarkEntry(step.Mark)
		if !found {
			return MutationCut{}, fmt.Errorf("powerloss: step %d claims mark %q but the log does not carry it; the mark channel was broken and no cut can be trusted", step.Index, step.Mark)
		}
		if entry <= previous {
			return MutationCut{}, fmt.Errorf("powerloss: step %d's mark %q is not after the previous step's in the log; marks were not taken in acknowledgement order", step.Index, step.Mark)
		}
		previous = entry
		if entry <= endEntry {
			acknowledged = position + 1
		}
	}
	cut := MutationCut{EndEntry: endEntry, Acknowledged: acknowledged}
	if acknowledged > 0 {
		cut.Durable = ledger.Steps[acknowledged-1].State
	}
	if acknowledged < len(ledger.Steps) {
		cut.InFlight = &ledger.Steps[acknowledged]
	}
	return cut, nil
}

// MutationReport is the outcome of verifying one cut.
type MutationReport struct {
	EndEntry     int
	Acknowledged int
	Steps        int
	// InFlight names the step that may have been in flight, if any.
	InFlight string
	// Outcome says, for a conforming cut, what recovery left of the in-flight
	// step, so a green report shows which side of each boundary was observed.
	Outcome    string
	Mismatches []string
}

// Err joins every mismatch into one error, or returns nil.
func (r MutationReport) Err() error {
	if len(r.Mismatches) == 0 {
		return nil
	}
	inFlight := ""
	if r.InFlight != "" {
		inFlight = "; " + r.InFlight + " may have been in flight"
	}
	return fmt.Errorf("powerloss: at the cut ending at log entry %d, %d of %d FSKit mutations were acknowledged and must be present exactly%s:\n- %s",
		r.EndEntry, r.Acknowledged, r.Steps, inFlight, strings.Join(r.Mismatches, "\n- "))
}

// VerifyMutationCut inspects a recovered volume against one cut. volumeRoot is
// <replay mountpoint>/<ledger.Volume> inside an already-recovered filesystem.
func VerifyMutationCut(volumeRoot string, ledger *MutationLedger, cut MutationCut) MutationReport {
	report := MutationReport{EndEntry: cut.EndEntry, Acknowledged: cut.Acknowledged, Steps: len(ledger.Steps)}
	if cut.InFlight == nil {
		report.Mismatches = compareTree(volumeRoot, ledger.Prefix, cut.Durable, relaxation{})
		report.Outcome = "every step acknowledged and present; nothing was in flight"
		return report
	}
	step := cut.InFlight
	report.InFlight = fmt.Sprintf("step %d (%s)", step.Index, step.Description)
	relaxed := inFlightRelaxation(step, cut.Durable)
	before := compareTree(volumeRoot, ledger.Prefix, cut.Durable, relaxed)
	if len(before) == 0 {
		report.Outcome = "the in-flight step had not reached storage"
		if step.Kind.changesData() {
			report.Outcome = "the in-flight data step left only acknowledged, in-flight or never-written bytes"
		}
		return report
	}
	after := compareTree(volumeRoot, ledger.Prefix, step.State, relaxed)
	if len(after) == 0 {
		report.Outcome = "the in-flight step had fully reached storage"
		return report
	}
	for _, mismatch := range before {
		report.Mismatches = append(report.Mismatches, "against the acknowledged state: "+mismatch)
	}
	for _, mismatch := range after {
		report.Mismatches = append(report.Mismatches, "against the in-flight step's state: "+mismatch)
	}
	return report
}

// relaxation is what the one in-flight step may have left half-done.
// Everything outside it is compared exactly in both interpretations.
type relaxation struct {
	// data maps a file whose bytes or size the in-flight step rewrites to its
	// acknowledged and in-flight states.
	data map[string][2]ObjectState
	// created holds objects the in-flight step creates.
	created map[string]bool
}

func inFlightRelaxation(step *MutationStep, durable TreeState) relaxation {
	relaxed := relaxation{data: make(map[string][2]ObjectState), created: make(map[string]bool)}
	for label, after := range step.State.Objects {
		before, existed := durable.Objects[label]
		if !existed {
			relaxed.created[label] = true
			continue
		}
		if step.Kind.changesData() && before.Kind == ObjectFile && after.Kind == ObjectFile &&
			(before.Size != after.Size || before.SHA256 != after.SHA256) {
			relaxed.data[label] = [2]ObjectState{before, after}
		}
	}
	return relaxed
}

// rawAttributes are the stat fields os.FileInfo does not expose portably.
type rawAttributes struct {
	mode    uint32
	links   uint64
	atimeNs int64
}

func kindOf(info fs.FileInfo) ObjectKind {
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return ObjectSymlink
	case info.IsDir():
		return ObjectDirectory
	case info.Mode().IsRegular():
		return ObjectFile
	default:
		return ObjectKind(fmt.Sprintf("special file (%s)", info.Mode().Type()))
	}
}

// compareTree reports every way the recovered subtree differs from tree.
// Attributes are read before any content, so a read can never move an atime
// before it is compared.
func compareTree(root, prefix string, tree TreeState, relaxed relaxation) []string {
	var mismatches []string
	report := func(format string, arguments ...any) {
		mismatches = append(mismatches, fmt.Sprintf(format, arguments...))
	}
	local := func(name string) string { return filepath.Join(root, filepath.FromSlash(name)) }
	if _, present := tree.Entries[prefix]; !present {
		if _, err := os.Lstat(local(prefix)); err == nil {
			report("%s exists, but no acknowledged step had created it", prefix)
		} else if !errors.Is(err, fs.ErrNotExist) {
			report("%s cannot be inspected: %v", prefix, err)
		}
		return mismatches
	}
	names := make([]string, 0, len(tree.Entries))
	children := make(map[string]map[string]bool)
	for name := range tree.Entries {
		names = append(names, name)
		if name != prefix {
			parent := path.Dir(name)
			if children[parent] == nil {
				children[parent] = make(map[string]bool)
			}
			children[parent][path.Base(name)] = true
		}
	}
	sort.Strings(names)
	present := make(map[string]fs.FileInfo, len(names))
	for _, name := range names {
		label := tree.Entries[name]
		object := tree.Objects[label]
		info, err := os.Lstat(local(name))
		if errors.Is(err, fs.ErrNotExist) {
			report("%s is missing; the expected state has %s %q there", name, object.Kind, label)
			continue
		}
		if err != nil {
			report("%s cannot be inspected: %v", name, err)
			continue
		}
		if kind := kindOf(info); kind != object.Kind {
			report("%s is a %s; the expected state has %s %q there", name, kind, object.Kind, label)
			continue
		}
		present[name] = info
		for _, mismatch := range compareObject(local(name), label, object, info, relaxed) {
			report("%s: %s", name, mismatch)
		}
	}
	for _, name := range names {
		info := present[name]
		if info == nil || !info.IsDir() {
			continue
		}
		listed, err := os.ReadDir(local(name))
		if err != nil {
			report("%s cannot be listed: %v", name, err)
			continue
		}
		var unexpected []string
		for _, entry := range listed {
			if !children[name][entry.Name()] {
				unexpected = append(unexpected, entry.Name())
			}
		}
		if len(unexpected) != 0 {
			report("%s lists %q, which the expected state does not have: a removed name survived or an unrecorded one appeared", name, unexpected)
		}
	}
	// Hard links: names sharing a label must be one inode, and names with
	// different labels must not be.
	for i, first := range names {
		for _, second := range names[i+1:] {
			left, right := present[first], present[second]
			if left == nil || right == nil || kindOf(left) != ObjectFile || kindOf(right) != ObjectFile {
				continue
			}
			same := os.SameFile(left, right)
			sameLabel := tree.Entries[first] == tree.Entries[second]
			if sameLabel && !same {
				report("%s and %s must be hard links of one inode (%q) but are not", first, second, tree.Entries[first])
			}
			if !sameLabel && same {
				report("%s and %s are one inode, but the expected state has distinct objects %q and %q", first, second, tree.Entries[first], tree.Entries[second])
			}
		}
	}
	return mismatches
}

func compareObject(name, label string, object ObjectState, info fs.FileInfo, relaxed relaxation) []string {
	var mismatches []string
	report := func(format string, arguments ...any) {
		mismatches = append(mismatches, fmt.Sprintf(format, arguments...))
	}
	if object.Kind == ObjectSymlink {
		target, err := os.Readlink(name)
		if err != nil {
			report("readlink failed: %v", err)
		} else if target != object.Target {
			report("symlink target is %q; the expected state has %q", target, object.Target)
		}
		return mismatches
	}
	raw, ok := rawStatOf(info)
	if !ok {
		return append(mismatches, "this platform exposes no mode, link count or atime to verify against")
	}
	if !relaxed.created[label] && raw.mode != object.Mode {
		report("mode is %#o; the expected state has %#o", raw.mode, object.Mode)
	}
	if object.Kind == ObjectDirectory {
		return mismatches
	}
	if raw.links != uint64(object.Links) {
		report("hard-link count is %d; the expected state has %d", raw.links, object.Links)
	}
	states, loose := relaxed.data[label]
	if !loose && object.MtimeNs != nil && info.ModTime().UnixNano() != *object.MtimeNs {
		report("mtime is %d ns; the explicitly set value was %d ns", info.ModTime().UnixNano(), *object.MtimeNs)
	}
	if !loose && object.AtimeNs != nil && raw.atimeNs != *object.AtimeNs {
		report("atime is %d ns; the explicitly set value was %d ns", raw.atimeNs, *object.AtimeNs)
	}
	content, err := readNoAtime(name)
	if err != nil {
		return append(mismatches, fmt.Sprintf("reading the recovered file failed: %v", err))
	}
	if loose {
		if err := permittedInFlightContent(content, states[0], states[1]); err != nil {
			report("%v", err)
		}
		return mismatches
	}
	if int64(len(content)) != object.Size || Digest(content) != object.SHA256 {
		report("holds %d bytes digesting to %s; the expected state is %d bytes digesting to %s%s",
			len(content), Digest(content), object.Size, object.SHA256, firstDifference(content, object.Content()))
	}
	return mismatches
}

func readNoAtime(name string) ([]byte, error) {
	file, err := openNoAtime(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(file)
}

// permittedInFlightContent is the stale-data rule for a file an
// unacknowledged write or truncate may have torn: the size lies between the
// two states' sizes, and every byte is the acknowledged byte, the in-flight
// byte, or a zero at an offset where one of the two states has no byte.
// Workload bytes are never zero (GenerateContent), so a zero cannot hide a
// lost byte, and a byte from neither state is stale data from a freed extent
// or a lost acknowledged byte.
func permittedInFlightContent(actual []byte, before, after ObjectState) error {
	low, high := min(before.Size, after.Size), max(before.Size, after.Size)
	if size := int64(len(actual)); size < low || size > high {
		return fmt.Errorf("size is %d, outside the acknowledged size and the in-flight step's size [%d, %d]", size, low, high)
	}
	acknowledged, inFlight := before.Content(), after.Content()
	for offset, value := range actual {
		inAcknowledged, inInFlight := offset < len(acknowledged), offset < len(inFlight)
		if inAcknowledged && value == acknowledged[offset] || inInFlight && value == inFlight[offset] {
			continue
		}
		if value == 0 && (!inAcknowledged || !inInFlight) {
			continue
		}
		return fmt.Errorf("byte %d is %#x, which is neither the acknowledged byte, the in-flight step's byte, nor a never-written zero: stale data or a lost acknowledged byte", offset, value)
	}
	return nil
}

func firstDifference(actual, expected []byte) string {
	for offset := range min(len(actual), len(expected)) {
		if actual[offset] != expected[offset] {
			return fmt.Sprintf(" (first difference at byte %d: %#x, expected %#x)", offset, actual[offset], expected[offset])
		}
	}
	if len(actual) != len(expected) {
		return fmt.Sprintf(" (identical through byte %d, then the lengths differ)", min(len(actual), len(expected)))
	}
	return ""
}
