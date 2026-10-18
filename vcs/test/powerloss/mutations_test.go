package powerloss

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fileState builds a file object whose digest matches its spans.
func fileState(mode uint32, links uint32, size int64, spans ...ContentSpan) ObjectState {
	object := ObjectState{Kind: ObjectFile, Mode: mode, Size: size, Spans: spans, Links: links}
	object.SHA256 = Digest(object.Content())
	return object
}

func directoryState(mode uint32) ObjectState { return ObjectState{Kind: ObjectDirectory, Mode: mode} }

func int64Pointer(value int64) *int64 { return &value }

const (
	sampleAtime = int64(1700000000123456789)
	sampleMtime = int64(1600000000987654321)
)

// sampleMutationLedger is a hand-written ledger covering every relation the
// verifier checks: directories, a file written, hard linked, renamed through
// its alias, overwritten and extended, timestamped, a symlink, and an unlink
// of one of two names.
func sampleMutationLedger(t *testing.T) *MutationLedger {
	t.Helper()
	ledger := &MutationLedger{Volume: "powerloss-volume", Prefix: "fskit", Label: "unit"}
	state := TreeState{Entries: map[string]string{}, Objects: map[string]ObjectState{}}
	record := func(kind MutationKind, description string, change func()) {
		change()
		ledger.Record(kind, description, "step-"+string(rune('a'+len(ledger.Steps))), state)
	}
	record(MutationMkdir, "mkdir fskit", func() {
		state.Entries["fskit"] = "top"
		state.Objects["top"] = directoryState(0o755)
	})
	record(MutationCreate, "create fskit/a", func() {
		state.Entries["fskit/a"] = "a"
		state.Objects["a"] = fileState(0o644, 1, 0)
	})
	record(MutationWrite, "write fskit/a [0, 8192)", func() {
		state.Objects["a"] = fileState(0o644, 1, 8192, ContentSpan{0, 8192, 1})
	})
	record(MutationLink, "link fskit/a to fskit/b", func() {
		state.Entries["fskit/b"] = "a"
		state.Objects["a"] = fileState(0o644, 2, 8192, ContentSpan{0, 8192, 1})
	})
	record(MutationRename, "rename fskit/b to fskit/c", func() {
		delete(state.Entries, "fskit/b")
		state.Entries["fskit/c"] = "a"
	})
	record(MutationWrite, "write fskit/a [4096, 12288)", func() {
		state.Objects["a"] = fileState(0o644, 2, 12288, ContentSpan{0, 8192, 1}, ContentSpan{4096, 8192, 2})
	})
	record(MutationSetTimes, "set times on fskit/a", func() {
		object := state.Objects["a"]
		object.AtimeNs, object.MtimeNs = int64Pointer(sampleAtime), int64Pointer(sampleMtime)
		state.Objects["a"] = object
	})
	record(MutationSymlink, "symlink fskit/s to a", func() {
		state.Entries["fskit/s"] = "s"
		state.Objects["s"] = ObjectState{Kind: ObjectSymlink, Target: "a"}
	})
	record(MutationMkdir, "mkdir fskit/d", func() {
		state.Entries["fskit/d"] = "d"
		state.Objects["d"] = directoryState(0o750)
	})
	record(MutationUnlink, "unlink fskit/a", func() {
		delete(state.Entries, "fskit/a")
		object := state.Objects["a"]
		object.Links = 1
		state.Objects["a"] = object
	})
	if err := ledger.Validate(); err != nil {
		t.Fatalf("the sample ledger is invalid: %v", err)
	}
	return ledger
}

// materialize lays a recorded state out on disk under a fresh volume root,
// which is what a conforming recovery would leave.
func materialize(t *testing.T, state TreeState) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "powerloss-volume")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(state.Entries))
	for name := range state.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	first := map[string]string{}
	for _, name := range names {
		label := state.Entries[name]
		object := state.Objects[label]
		local := filepath.Join(root, filepath.FromSlash(name))
		switch object.Kind {
		case ObjectDirectory:
			if err := os.Mkdir(local, 0o700); err != nil {
				t.Fatal(err)
			}
		case ObjectSymlink:
			if err := os.Symlink(object.Target, local); err != nil {
				t.Fatal(err)
			}
		case ObjectFile:
			if existing, linked := first[label]; linked {
				if err := os.Link(existing, local); err != nil {
					t.Fatal(err)
				}
				continue
			}
			first[label] = local
			if err := os.WriteFile(local, object.Content(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Modes and times last, deepest first, so restrictive directory modes do
	// not stop the layout above and nothing later moves a timestamp.
	for index := len(names) - 1; index >= 0; index-- {
		object := state.Objects[state.Entries[names[index]]]
		local := filepath.Join(root, filepath.FromSlash(names[index]))
		if object.Kind != ObjectSymlink {
			if err := os.Chmod(local, os.FileMode(object.Mode)); err != nil {
				t.Fatal(err)
			}
		}
		if object.MtimeNs != nil || object.AtimeNs != nil {
			atime, mtime := time.Now(), time.Now()
			if object.AtimeNs != nil {
				atime = time.Unix(0, *object.AtimeNs)
			}
			if object.MtimeNs != nil {
				mtime = time.Unix(0, *object.MtimeNs)
			}
			if err := unix.UtimesNanoAt(unix.AT_FDCWD, local, []unix.Timespec{unix.NsecToTimespec(atime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// mutationLog carries one mark per step with a barrier after each, so a cut
// can sit exactly at a mark or strictly between two.
func mutationLog(t *testing.T, ledger *MutationLedger) *Log {
	t.Helper()
	entries := []synthEntry{{sector: 0, sectors: 1, flags: FlagFlush, payload: []byte("mkfs")}}
	for index, step := range ledger.Steps {
		entries = append(entries,
			synthEntry{flags: FlagMark, mark: step.Mark},
			synthEntry{sector: uint64(index + 1), sectors: 1, flags: FlagFUA, payload: []byte("b")},
		)
	}
	image := buildSynthLog(t, 512, entries)
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	return log
}

func markEntryOf(t *testing.T, log *Log, mark string) int {
	t.Helper()
	entry, found := log.MarkEntry(mark)
	if !found {
		t.Fatalf("mark %q is not in the synthetic log", mark)
	}
	return entry
}

func TestMutationLedgerRoundTrip(t *testing.T) {
	ledger := sampleMutationLedger(t)
	pathname := filepath.Join(t.TempDir(), "fskit-ledger.json")
	if err := ledger.Save(pathname); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadMutationLedger(pathname)
	if err != nil {
		t.Fatalf("LoadMutationLedger: %v", err)
	}
	if len(loaded.Steps) != len(ledger.Steps) || loaded.Prefix != ledger.Prefix {
		t.Fatalf("loaded %d steps under %q, want %d under %q", len(loaded.Steps), loaded.Prefix, len(ledger.Steps), ledger.Prefix)
	}
	last := loaded.Steps[len(loaded.Steps)-1].State
	if last.Objects["a"].Links != 1 || *last.Objects["a"].AtimeNs != sampleAtime {
		t.Fatalf("final state did not survive the round trip: %+v", last.Objects["a"])
	}
}

func TestMutationLedgerRecordKeepsAPrivateSnapshot(t *testing.T) {
	ledger := &MutationLedger{Volume: "v", Prefix: "fskit", Label: "unit"}
	state := TreeState{Entries: map[string]string{"fskit": "top"}, Objects: map[string]ObjectState{"top": directoryState(0o755)}}
	ledger.Record(MutationMkdir, "mkdir fskit", "step-a", state)
	state.Entries["fskit/x"] = "x"
	state.Objects["top"] = directoryState(0o700)
	if len(ledger.Steps[0].State.Entries) != 1 || ledger.Steps[0].State.Objects["top"].Mode != 0o755 {
		t.Fatal("a recorded step changed when the live model moved on")
	}
}

func TestMutationLedgerValidateRejectsUntrustworthyRecords(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*MutationLedger)
		wantSub string
	}{
		{"no steps", func(l *MutationLedger) { l.Steps = nil }, "records no steps"},
		{"volume is a path", func(l *MutationLedger) { l.Volume = "cell/volume" }, "not a single directory name"},
		{"unsafe prefix", func(l *MutationLedger) { l.Prefix = "../x" }, "not a single safe path element"},
		{"renumbered step", func(l *MutationLedger) { l.Steps[2].Index = 9 }, "declares index"},
		{"unknown kind", func(l *MutationLedger) { l.Steps[1].Kind = "guess" }, "unknown kind"},
		{"no description", func(l *MutationLedger) { l.Steps[1].Description = "" }, "no description"},
		{"duplicate mark", func(l *MutationLedger) { l.Steps[3].Mark = l.Steps[2].Mark }, "share mark"},
		{"shell-unsafe mark", func(l *MutationLedger) { l.Steps[0].Mark = "a; rm" }, "not a safe mark name"},
		{"path outside the prefix", func(l *MutationLedger) { l.Steps[1].State.Entries["other/a"] = "a" }, "outside the workload prefix"},
		{"escaping path", func(l *MutationLedger) { l.Steps[1].State.Entries["fskit/../a"] = "a" }, "not in clean form"},
		{"orphaned path", func(l *MutationLedger) { l.Steps[1].State.Entries["fskit/none/a"] = "a" }, "no directory entry for its parent"},
		{"undescribed object", func(l *MutationLedger) { l.Steps[1].State.Entries["fskit/x"] = "x" }, "does not describe"},
		{"unreachable object", func(l *MutationLedger) {
			l.Steps[1].State.Objects["ghost"] = fileState(0o644, 1, 0)
		}, "not reachable"},
		{"miscounted links", func(l *MutationLedger) {
			object := l.Steps[3].State.Objects["a"]
			object.Links = 1
			l.Steps[3].State.Objects["a"] = object
		}, "records 1 links but has 2 names"},
		{"digest disagrees with spans", func(l *MutationLedger) {
			object := l.Steps[2].State.Objects["a"]
			object.Spans = []ContentSpan{{0, 8192, 7}}
			l.Steps[2].State.Objects["a"] = object
		}, "digest does not match"},
		{"span outside the file", func(l *MutationLedger) {
			object := l.Steps[2].State.Objects["a"]
			object.Spans = []ContentSpan{{4096, 8192, 1}}
			l.Steps[2].State.Objects["a"] = object
		}, "outside its 8192 bytes"},
		{"symlink with a mode", func(l *MutationLedger) {
			object := l.Steps[7].State.Objects["s"]
			object.Mode = 0o777
			l.Steps[7].State.Objects["s"] = object
		}, "symlink"},
		{"hard-linked directory", func(l *MutationLedger) { l.Steps[8].State.Entries["fskit/e"] = "d" }, "exactly one name"},
		{"mode beyond permission bits", func(l *MutationLedger) {
			l.Steps[0].State.Objects["top"] = directoryState(0o10755)
		}, "outside the permission bits"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := sampleMutationLedger(t)
			test.mutate(ledger)
			err := ledger.Validate()
			if err == nil {
				t.Fatal("Validate accepted a ledger the verifier could misread")
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("Validate error = %v, want it to name %q", err, test.wantSub)
			}
			if err := ledger.Save(filepath.Join(t.TempDir(), "ledger.json")); err == nil {
				t.Fatal("Save wrote a ledger Validate rejects")
			}
		})
	}
}

func TestMutationCutAtNamesTheAcknowledgedPrefixAndTheOneInFlightStep(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	tests := []struct {
		name             string
		endEntry         int
		wantAcknowledged int
		wantInFlight     int // -1 for none
	}{
		{"before the first mark", 0, 0, 0},
		{"exactly at the first mark", markEntryOf(t, log, ledger.Steps[0].Mark), 1, -1},
		{"between the fourth and fifth marks", markEntryOf(t, log, ledger.Steps[3].Mark) + 1, 4, 4},
		{"after the final mark", len(log.Entries) - 1, len(ledger.Steps), -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cut, err := MutationCutAt(log, ledger, test.endEntry)
			if err != nil {
				t.Fatalf("MutationCutAt: %v", err)
			}
			if cut.Acknowledged != test.wantAcknowledged {
				t.Fatalf("acknowledged = %d, want %d", cut.Acknowledged, test.wantAcknowledged)
			}
			switch {
			case test.wantInFlight < 0 && cut.InFlight != nil:
				t.Fatalf("in flight = step %d, want none", cut.InFlight.Index)
			case test.wantInFlight >= 0 && (cut.InFlight == nil || cut.InFlight.Index != test.wantInFlight):
				t.Fatalf("in flight = %+v, want step %d", cut.InFlight, test.wantInFlight)
			}
			if test.wantAcknowledged == 0 && len(cut.Durable.Entries) != 0 {
				t.Fatal("a cut before every mark expects a non-empty tree")
			}
		})
	}
}

func TestMutationCutAtFailsClosedOnABrokenMarkChannel(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*MutationLedger)
		wantSub string
	}{
		{"missing mark", func(l *MutationLedger) { l.Steps[4].Mark = "step-missing" }, "the mark channel was broken"},
		{"reordered marks", func(l *MutationLedger) {
			l.Steps[3].Mark, l.Steps[4].Mark = l.Steps[4].Mark, l.Steps[3].Mark
		}, "not taken in acknowledgement order"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := sampleMutationLedger(t)
			log := mutationLog(t, ledger)
			test.mutate(ledger)
			if _, err := MutationCutAt(log, ledger, len(log.Entries)-1); err == nil || !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("MutationCutAt error = %v, want it to name %q", err, test.wantSub)
			}
			if _, err := SelectPoints(log, ledger, 2); test.name == "missing mark" && err == nil {
				t.Fatal("SelectPoints accepted a step mark the log does not carry")
			}
		})
	}
}

// TestVerifyMutationCutAcceptsEitherSideOfTheInFlightStep is the boundary the
// FSKit contract turns on: everything acknowledged is present, and the one
// mutation sent strictly after the last mark may be found wholly absent or
// wholly applied. Exact marks are checked separately without that allowance.
func TestVerifyMutationCutAcceptsEitherSideOfTheInFlightStep(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	for k := range ledger.Steps {
		endEntry := markEntryOf(t, log, ledger.Steps[k].Mark) + 1
		cut, err := MutationCutAt(log, ledger, endEntry)
		if err != nil {
			t.Fatalf("MutationCutAt: %v", err)
		}
		layouts := map[string]TreeState{"acknowledged": ledger.Steps[k].State}
		if k+1 < len(ledger.Steps) {
			layouts["in-flight applied"] = ledger.Steps[k+1].State
		}
		for name, layout := range layouts {
			report := VerifyMutationCut(materialize(t, layout), ledger, cut)
			if err := report.Err(); err != nil {
				t.Fatalf("step %d, %s layout: %v", k, name, err)
			}
			if report.Outcome == "" {
				t.Fatalf("step %d, %s layout: a conforming cut reported no outcome", k, name)
			}
		}
	}
}

func TestVerifyMutationCutReportsAcknowledgedMutationsThatDidNotSurvive(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	final := len(ledger.Steps) - 1
	tests := []struct {
		name    string
		step    int // cut at this step's mark, except the in-flight rename case
		damage  func(t *testing.T, root string)
		wantSub string
	}{
		{
			name: "an acknowledged directory is missing", step: final,
			damage:  func(t *testing.T, root string) { mustRemove(t, filepath.Join(root, "fskit", "d")) },
			wantSub: "fskit/d is missing",
		},
		{
			name: "an acknowledged unlink did not survive", step: final,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.Link(filepath.Join(root, "fskit", "c"), filepath.Join(root, "fskit", "a")))
			},
			wantSub: "lists [\"a\"]",
		},
		{
			name: "a hard link came back as a separate inode", step: 4,
			damage: func(t *testing.T, root string) {
				alias := filepath.Join(root, "fskit", "c")
				content, err := os.ReadFile(alias)
				mustRun(t, err)
				mustRemove(t, alias)
				mustRun(t, os.WriteFile(alias, content, 0o644))
			},
			wantSub: "must be hard links of one inode",
		},
		{
			name: "an acknowledged chmod was lost", step: final,
			damage:  func(t *testing.T, root string) { mustRun(t, os.Chmod(filepath.Join(root, "fskit", "d"), 0o755)) },
			wantSub: "mode is 0755; the expected state has 0750",
		},
		{
			name: "an explicitly set mtime was lost", step: final,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.Chtimes(filepath.Join(root, "fskit", "c"), time.Unix(0, sampleAtime), time.Unix(1, 0)))
			},
			wantSub: "mtime is 1000000000 ns; the explicitly set value was 1600000000987654321",
		},
		{
			name: "an explicitly set atime was lost", step: final,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.Chtimes(filepath.Join(root, "fskit", "c"), time.Unix(2, 0), time.Unix(0, sampleMtime)))
			},
			wantSub: "atime is 2000000000 ns; the explicitly set value was 1700000000123456789",
		},
		{
			name: "acknowledged bytes were lost", step: 2,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.WriteFile(filepath.Join(root, "fskit", "a"), make([]byte, 8192), 0o644))
			},
			wantSub: "digesting to",
		},
		{
			name: "a symlink came back with another target", step: final,
			damage: func(t *testing.T, root string) {
				link := filepath.Join(root, "fskit", "s")
				mustRemove(t, link)
				mustRun(t, os.Symlink("c", link))
			},
			wantSub: "symlink target is \"c\"",
		},
		{
			name: "a rename was half applied", step: 3,
			// Cut strictly after the link's mark with the rename in flight, and leave both
			// names: neither the acknowledged nor the renamed state has that.
			damage: func(t *testing.T, root string) {
				mustRun(t, os.Link(filepath.Join(root, "fskit", "b"), filepath.Join(root, "fskit", "c")))
			},
			wantSub: "against the in-flight step's state",
		},
		{
			name: "the prefix exists before any step created it", step: -1,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.MkdirAll(filepath.Join(root, "fskit", "stray"), 0o755))
			},
			wantSub: "lists [\"stray\"]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endEntry, layout := 0, TreeState{}
			if test.step >= 0 {
				endEntry, layout = markEntryOf(t, log, ledger.Steps[test.step].Mark), ledger.Steps[test.step].State
				if test.name == "a rename was half applied" {
					endEntry++
				}
			}
			root := materialize(t, layout)
			test.damage(t, root)
			cut, err := MutationCutAt(log, ledger, endEntry)
			if err != nil {
				t.Fatalf("MutationCutAt: %v", err)
			}
			err = VerifyMutationCut(root, ledger, cut).Err()
			if err == nil {
				t.Fatal("VerifyMutationCut passed a recovery that broke the FSKit contract")
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("VerifyMutationCut error = %v, want it to name %q", err, test.wantSub)
			}
		})
	}
}

// TestVerifyMutationCutAllowsOnlyPermittedTearsOfTheInFlightStep pins the two
// stated allowances, and their limits.
func TestVerifyMutationCutAllowsOnlyPermittedTearsOfTheInFlightStep(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	acknowledged := ledger.Steps[4].State.Objects["a"] // before the overwrite-and-extend at step 5
	inFlight := ledger.Steps[5].State.Objects["a"]
	torn := append([]byte(nil), acknowledged.Content()...)
	copy(torn[4096:8192], inFlight.Content()[4096:8192]) // one page of the overwrite landed, the extension did not
	tests := []struct {
		name    string
		step    int
		damage  func(t *testing.T, root string)
		wantSub string // empty: the cut must conform
	}{
		{
			name: "a page-granular mix of acknowledged and in-flight bytes", step: 4,
			damage: func(t *testing.T, root string) { writeKeepingTimes(t, filepath.Join(root, "fskit", "a"), torn) },
		},
		{
			name: "an extension that never landed reads as zeros", step: 4,
			damage: func(t *testing.T, root string) {
				extended := append(append([]byte(nil), torn...), make([]byte, 2048)...)
				writeKeepingTimes(t, filepath.Join(root, "fskit", "a"), extended)
			},
		},
		{
			name: "a byte from neither state is stale data", step: 4,
			damage: func(t *testing.T, root string) {
				stale := append([]byte(nil), torn...)
				stale[100] = ^stale[100]
				writeKeepingTimes(t, filepath.Join(root, "fskit", "a"), stale)
			},
			wantSub: "stale data or a lost acknowledged byte",
		},
		{
			name: "a zero where both states have a byte is a lost acknowledged byte", step: 4,
			damage: func(t *testing.T, root string) {
				lost := append([]byte(nil), torn...)
				lost[200] = 0
				writeKeepingTimes(t, filepath.Join(root, "fskit", "a"), lost)
			},
			wantSub: "byte 200 is 0x0",
		},
		{
			name: "a size beyond the in-flight step's", step: 4,
			damage: func(t *testing.T, root string) {
				writeKeepingTimes(t, filepath.Join(root, "fskit", "a"), make([]byte, 20000))
			},
			wantSub: "outside the acknowledged size and the in-flight step's size",
		},
		{
			name: "a directory the in-flight mkdir created still has its creation mode", step: 7,
			damage: func(t *testing.T, root string) { mustRun(t, os.Mkdir(filepath.Join(root, "fskit", "d"), 0o700)) },
		},
		{
			name: "a name the in-flight mkdir did not create", step: 7,
			damage: func(t *testing.T, root string) {
				mustRun(t, os.Mkdir(filepath.Join(root, "fskit", "d"), 0o700))
				mustRun(t, os.Mkdir(filepath.Join(root, "fskit", "e"), 0o700))
			},
			wantSub: "lists [\"e\"]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := materialize(t, ledger.Steps[test.step].State)
			test.damage(t, root)
			cut, err := MutationCutAt(log, ledger, markEntryOf(t, log, ledger.Steps[test.step].Mark)+1)
			if err != nil {
				t.Fatalf("MutationCutAt: %v", err)
			}
			err = VerifyMutationCut(root, ledger, cut).Err()
			if test.wantSub == "" {
				if err != nil {
					t.Fatalf("VerifyMutationCut rejected a permitted in-flight state: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("VerifyMutationCut error = %v, want it to name %q", err, test.wantSub)
			}
		})
	}
}

func mustRun(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, name string) {
	t.Helper()
	mustRun(t, os.RemoveAll(name))
}

// writeKeepingTimes rewrites a file's bytes without disturbing the timestamps
// the case is not about.
func writeKeepingTimes(t *testing.T, name string, content []byte) {
	t.Helper()
	info, err := os.Lstat(name)
	mustRun(t, err)
	raw, ok := rawStatOf(info)
	if !ok {
		t.Fatal("this platform exposes no atime to preserve")
	}
	mustRun(t, os.WriteFile(name, content, 0o644))
	mustRun(t, os.Chtimes(name, time.Unix(0, raw.atimeNs), info.ModTime()))
}

func TestReviewExactAcknowledgementMarkHasNoFutureMutation(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	// Step 8 acknowledges mkdir d. Step 9 later unlinks a; it cannot have
	// been sent at the exact mark for step 8 because the driver awaits its ack.
	at := markEntryOf(t, log, ledger.Steps[8].Mark)
	cut, err := MutationCutAt(log, ledger, at)
	if err != nil {
		t.Fatal(err)
	}
	report := VerifyMutationCut(materialize(t, ledger.Steps[9].State), ledger, cut)
	if report.Err() == nil {
		t.Fatalf("lost acknowledged name accepted at exact prior mark: acknowledged=%d outcome=%s", report.Acknowledged, report.Outcome)
	}
}

func TestMutationExactMarksRequireOnlyAcknowledgedState(t *testing.T) {
	ledger := sampleMutationLedger(t)
	log := mutationLog(t, ledger)
	for k, step := range ledger.Steps {
		cut, err := MutationCutAt(log, ledger, markEntryOf(t, log, step.Mark))
		mustRun(t, err)
		if cut.InFlight != nil {
			t.Fatalf("exact mark %d has a future step", k)
		}
		if err := VerifyMutationCut(materialize(t, step.State), ledger, cut).Err(); err != nil {
			t.Fatal(err)
		}
		// A future SETATTR can agree on every currently promised field when
		// the prior state did not promise timestamps; its absence is then
		// observationally indistinguishable. No in-flight allowance is used.
		if k+1 < len(ledger.Steps) && ledger.Steps[k+1].Kind != MutationSetTimes {
			if err := VerifyMutationCut(materialize(t, ledger.Steps[k+1].State), ledger, cut).Err(); err == nil {
				t.Fatalf("exact mark %d accepted the future step", k)
			}
		}
	}
}

func TestMutationRecoveryChecksDirectoryAndSymlinkTimes(t *testing.T) {
	for _, label := range []string{"d", "s"} {
		for _, damage := range []string{"none", "atime", "mtime"} {
			t.Run(label+"/"+damage, func(t *testing.T) {
				ledger := sampleMutationLedger(t)
				state := ledger.Steps[len(ledger.Steps)-1].State.Clone()
				object := state.Objects[label]
				object.AtimeNs, object.MtimeNs = int64Pointer(sampleAtime), int64Pointer(sampleMtime)
				state.Objects[label] = object
				ledger.Record(MutationSetTimes, "set metadata on "+label, "step-times", state)
				mustRun(t, ledger.Validate())
				root := materialize(t, state)
				if damage != "none" {
					atime, mtime := sampleAtime, sampleMtime
					if damage == "atime" {
						atime++
					} else {
						mtime++
					}
					name := "fskit/" + label
					mustRun(t, unix.UtimesNanoAt(unix.AT_FDCWD, filepath.Join(root, name), []unix.Timespec{unix.NsecToTimespec(atime), unix.NsecToTimespec(mtime)}, unix.AT_SYMLINK_NOFOLLOW))
				}
				cut := MutationCut{Acknowledged: len(ledger.Steps), Durable: state}
				err := VerifyMutationCut(root, ledger, cut).Err()
				if damage == "none" {
					mustRun(t, err)
				} else if err == nil || !strings.Contains(err.Error(), damage+" is") {
					t.Fatalf("lost %s: %v", damage, err)
				}
			})
		}
	}
}

func TestMutationRecoverySharesMetadataAcrossCandidateStates(t *testing.T) {
	ledger := sampleMutationLedger(t)
	after := ledger.Steps[len(ledger.Steps)-1].State.Clone()
	for _, label := range []string{"d", "s"} {
		object := after.Objects[label]
		object.AtimeNs, object.MtimeNs = int64Pointer(sampleAtime), int64Pointer(sampleMtime)
		after.Objects[label] = object
	}
	before := after.Clone()
	object := before.Objects["s"]
	object.Target = "different"
	before.Objects["s"] = object
	step := MutationStep{Kind: MutationSymlink, State: after}
	cut := MutationCut{Durable: before, InFlight: &step}
	mustRun(t, VerifyMutationCut(materialize(t, after), ledger, cut).Err())
}

func TestMutationRecoveryRetainsUnreadableObjectMetadata(t *testing.T) {
	ledger := sampleMutationLedger(t)
	state := ledger.Steps[len(ledger.Steps)-1].State.Clone()
	for label, mode := range map[string]uint32{"a": 0, "d": 0o300} {
		object := state.Objects[label]
		object.Mode = mode
		object.AtimeNs, object.MtimeNs = int64Pointer(sampleAtime), int64Pointer(sampleMtime)
		state.Objects[label] = object
	}
	root := materialize(t, state)
	metadata := snapshotMetadata(root, ledger.Prefix, state)
	// Emulate root's content access for an unprivileged host test only after
	// sampling the real mode-000 file and unreadable directory. Comparisons
	// must continue to use those original attributes.
	mustRun(t, os.Chmod(filepath.Join(root, "fskit/c"), 0o600))
	mustRun(t, os.Chmod(filepath.Join(root, "fskit/d"), 0o700))
	if mismatches := compareTree(root, ledger.Prefix, state, relaxation{}, metadata); len(mismatches) != 0 {
		t.Fatalf("unreadable metadata: %v", mismatches)
	}
}
