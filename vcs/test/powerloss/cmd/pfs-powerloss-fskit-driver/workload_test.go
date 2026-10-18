package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// localVolume applies each workload mutation to a local directory with the
// same exact-mode semantics the authority implements. It is not a model of the
// authority's durability; it exists so the workload's recorded states can be
// checked against a real filesystem's namespace, link-count and timestamp
// behaviour on any host, by the same verifier a replayed cut uses.
type localVolume struct {
	root  string
	files map[string]*os.File
}

func newLocalVolume(t *testing.T) *localVolume {
	t.Helper()
	root := filepath.Join(t.TempDir(), "powerloss-volume")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return &localVolume{root: root, files: map[string]*os.File{}}
}

func (v *localVolume) local(name string) string {
	return filepath.Join(v.root, filepath.FromSlash(name))
}

func (v *localVolume) observe(name string) (observed, error) {
	info, err := os.Lstat(v.local(name))
	if err != nil {
		return observed{}, err
	}
	links, atime, ok := rawLinksAndAtime(info)
	if !ok {
		return observed{}, errors.New("this platform exposes no link count or atime")
	}
	got := observed{mode: uint32(info.Mode().Perm()), size: info.Size(), links: links, atimeNs: atime, mtimeNs: info.ModTime().UnixNano()}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		got.kind, got.mode = powerloss.ObjectSymlink, 0
	case info.IsDir():
		got.kind = powerloss.ObjectDirectory
	default:
		got.kind = powerloss.ObjectFile
	}
	return got, nil
}

func join(parent target, name string) string {
	if parent.path == "" {
		return name
	}
	return parent.path + "/" + name
}

func (v *localVolume) Mkdir(_ context.Context, parent target, name string, mode uint32, _ string) (observed, error) {
	created := join(parent, name)
	if err := os.Mkdir(v.local(created), 0o700); err != nil {
		return observed{}, err
	}
	if err := os.Chmod(v.local(created), os.FileMode(mode)); err != nil {
		return observed{}, err
	}
	return v.observe(created)
}

func (v *localVolume) Create(_ context.Context, parent target, name string, mode uint32, label string) (observed, error) {
	created := join(parent, name)
	file, err := os.OpenFile(v.local(created), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return observed{}, err
	}
	v.files[label] = file
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return observed{}, err
	}
	return v.observe(created)
}

func (v *localVolume) Write(_ context.Context, file target, offset int64, data []byte) (observed, error) {
	if _, err := v.files[file.label].WriteAt(data, offset); err != nil {
		return observed{}, err
	}
	return v.observe(file.path)
}

func (v *localVolume) Truncate(_ context.Context, file target, size int64, throughHandle bool) (observed, error) {
	var err error
	if throughHandle {
		err = v.files[file.label].Truncate(size)
	} else {
		err = os.Truncate(v.local(file.path), size)
	}
	if err != nil {
		return observed{}, err
	}
	return v.observe(file.path)
}

func (v *localVolume) Chmod(_ context.Context, item target, mode uint32) (observed, error) {
	if err := os.Chmod(v.local(item.path), os.FileMode(mode)); err != nil {
		return observed{}, err
	}
	return v.observe(item.path)
}

func (v *localVolume) SetTimes(_ context.Context, item target, atimeNs, mtimeNs int64) (observed, error) {
	if err := os.Chtimes(v.local(item.path), time.Unix(0, atimeNs), time.Unix(0, mtimeNs)); err != nil {
		return observed{}, err
	}
	return v.observe(item.path)
}

func (v *localVolume) Link(_ context.Context, item, parent target, name string) (observed, error) {
	if err := os.Link(v.local(item.path), v.local(join(parent, name))); err != nil {
		return observed{}, err
	}
	return v.observe(item.path)
}

func (v *localVolume) Symlink(_ context.Context, parent target, name, linkTarget, _ string) (observed, error) {
	created := join(parent, name)
	if err := os.Symlink(linkTarget, v.local(created)); err != nil {
		return observed{}, err
	}
	return v.observe(created)
}

func (v *localVolume) Rename(_ context.Context, oldParent target, oldName string, newParent target, newName string) error {
	return os.Rename(v.local(join(oldParent, oldName)), v.local(join(newParent, newName)))
}

func (v *localVolume) Unlink(_ context.Context, parent target, name string, _ bool) error {
	return os.Remove(v.local(join(parent, name)))
}

func (v *localVolume) Release(context.Context) error {
	var failures []error
	for label, file := range v.files {
		failures = append(failures, file.Close())
		delete(v.files, label)
	}
	return errors.Join(failures...)
}

// markHarness is the root harness's half of the mark protocol, run in-process:
// every request is answered synchronously after onMark has looked at the
// volume at exactly the instant the mark would have been taken.
type markHarness struct {
	marks   []string
	replies bytes.Buffer
	onMark  func(label string) error
}

func (h *markHarness) Write(request []byte) (int, error) {
	label, found := strings.CutPrefix(strings.TrimSpace(string(request)), "mark ")
	reply := "ok"
	switch {
	case !found:
		reply = "error: unrecognised request"
	case h.onMark != nil:
		if err := h.onMark(label); err != nil {
			reply = "error: " + err.Error()
		}
	}
	h.marks = append(h.marks, label)
	h.replies.WriteString(reply + "\n")
	return len(request), nil
}

func (h *markHarness) Read(p []byte) (int, error) {
	if h.replies.Len() == 0 {
		return 0, io.EOF
	}
	return h.replies.Read(p)
}

func newTestWorkload(t *testing.T, v volume, harness *markHarness) (*workload, string) {
	t.Helper()
	ledgerPath := filepath.Join(t.TempDir(), "fskit-ledger.json")
	ledger := &powerloss.MutationLedger{Volume: "powerloss-volume", Prefix: "fskit", Label: "unit"}
	return newWorkload(v, powerloss.NewMarkChannel(harness, harness), ledger, ledgerPath, io.Discard), ledgerPath
}

// TestWorkloadLedgerMatchesTheFilesystemAfterEveryAcknowledgedStep runs the
// whole sequence against a real directory and, at the moment each mark is
// requested, verifies the directory against the state just recorded with the
// same verifier a replayed cut uses. A model that disagreed with real
// filesystem semantics anywhere would otherwise surface only as an
// inexplicable power-loss failure on the privileged runner.
func TestWorkloadLedgerMatchesTheFilesystemAfterEveryAcknowledgedStep(t *testing.T) {
	v := newLocalVolume(t)
	harness := &markHarness{}
	w, ledgerPath := newTestWorkload(t, v, harness)
	harness.onMark = func(label string) error {
		last := w.ledger.Steps[len(w.ledger.Steps)-1]
		if last.Mark != label {
			t.Errorf("mark %q requested for recorded step %d, whose mark is %q", label, last.Index, last.Mark)
		}
		cut := powerloss.MutationCut{EndEntry: last.Index, Acknowledged: len(w.ledger.Steps), Durable: last.State}
		if err := powerloss.VerifyMutationCut(v.root, w.ledger, cut).Err(); err != nil {
			t.Errorf("after step %d (%s): %v", last.Index, last.Description, err)
		}
		return nil
	}
	if err := w.run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := v.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	ledger, err := powerloss.LoadMutationLedger(ledgerPath)
	if err != nil {
		t.Fatalf("LoadMutationLedger: %v", err)
	}
	marks := make([]string, 0, len(ledger.Steps))
	kinds := map[powerloss.MutationKind]bool{}
	for _, step := range ledger.Steps {
		marks = append(marks, step.Mark)
		kinds[step.Kind] = true
	}
	if strings.Join(marks, " ") != strings.Join(harness.marks, " ") {
		t.Fatalf("mark requests %v do not match the ledger's marks %v", harness.marks, marks)
	}
	// Every mutation the FSKit durability contract names must stay covered.
	for _, kind := range []powerloss.MutationKind{
		powerloss.MutationMkdir, powerloss.MutationCreate, powerloss.MutationWrite, powerloss.MutationTruncateHandle,
		powerloss.MutationTruncateItem, powerloss.MutationChmod, powerloss.MutationSetTimes, powerloss.MutationLink,
		powerloss.MutationSymlink, powerloss.MutationRename, powerloss.MutationUnlink, powerloss.MutationRmdir,
	} {
		if !kinds[kind] {
			t.Errorf("the workload no longer performs a %s", kind)
		}
	}
	final := ledger.Steps[len(ledger.Steps)-1].State
	alpha := final.Objects["alpha"]
	if alpha.Links != 1 || alpha.MtimeNs == nil || *alpha.MtimeNs != explicitMtimeNs || alpha.Mode != 0o640 {
		t.Errorf("alpha's final state lost a case the workload exists to cover: %+v", alpha)
	}
	if _, survived := final.Objects["beta"]; survived {
		t.Error("the replacing rename left the replaced object reachable")
	}
	var names []string
	for name := range final.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	want := "fskit fskit/archive fskit/archive/alpha-link fskit/archive/beta fskit/docs"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("final namespace = %s, want %s", got, want)
	}
}

func TestWorkloadStopsWhenAMarkIsRefused(t *testing.T) {
	harness := &markHarness{}
	w, ledgerPath := newTestWorkload(t, newLocalVolume(t), harness)
	harness.onMark = func(string) error {
		if len(harness.marks) == 2 {
			return errors.New("dmsetup is gone")
		}
		return nil
	}
	err := w.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "could not take mark") {
		t.Fatalf("run error = %v, want it to stop at the refused mark", err)
	}
	ledger, err := powerloss.LoadMutationLedger(ledgerPath)
	if err != nil {
		t.Fatalf("LoadMutationLedger: %v", err)
	}
	if len(ledger.Steps) != 2 {
		t.Fatalf("the published ledger has %d steps; only the two whose marks were taken may appear", len(ledger.Steps))
	}
}

// lyingVolume reports a mode the chmod did not apply.
type lyingVolume struct{ *localVolume }

func (v lyingVolume) Chmod(ctx context.Context, item target, mode uint32) (observed, error) {
	got, err := v.localVolume.Chmod(ctx, item, mode)
	got.mode = 0o777
	return got, err
}

func TestWorkloadRefusesAnAcknowledgementTheLedgerDoesNotModel(t *testing.T) {
	harness := &markHarness{}
	w, _ := newTestWorkload(t, lyingVolume{newLocalVolume(t)}, harness)
	err := w.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "the ledger models") {
		t.Fatalf("run error = %v, want it to refuse the disagreeing acknowledgement", err)
	}
	for _, step := range w.ledger.Steps {
		if step.Kind == powerloss.MutationChmod {
			t.Fatal("the disagreeing chmod was recorded")
		}
	}
	if len(harness.marks) != len(w.ledger.Steps) {
		t.Fatalf("%d marks for %d recorded steps: the disagreeing step must not be marked", len(harness.marks), len(w.ledger.Steps))
	}
}

func TestWorkloadStopsWhenTheSessionContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	harness := &markHarness{}
	w, _ := newTestWorkload(t, newLocalVolume(t), harness)
	harness.onMark = func(string) error {
		if len(harness.marks) == 3 {
			cancel()
		}
		return nil
	}
	if err := w.run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want the canceled session to stop the workload", err)
	}
	if got := len(w.ledger.Steps); got != 4 {
		t.Fatalf("recorded %d steps, want the run to stop right after the fourth", got)
	}
}
