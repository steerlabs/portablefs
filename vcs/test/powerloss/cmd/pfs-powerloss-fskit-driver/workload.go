package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// observed is what the authority reported for the object a mutation targeted.
// The workload compares it with the state it is about to record, so the ledger
// can never judge a cut against a state the authority did not acknowledge.
type observed struct {
	kind    powerloss.ObjectKind
	mode    uint32
	size    int64
	links   uint32
	atimeNs int64
	mtimeNs int64
}

// target names an object by its ledger label and one volume-relative path that
// currently reaches it. The authority adapter uses the label to find the
// capability it holds; the local test volume uses the path. The volume root is
// the empty label and path.
type target struct {
	label string
	path  string
}

// volume is the FSKit-profile authority surface the workload drives. Every
// method returns only once the authority's success reply has arrived, which
// under the FSKit profile means the mutation is already durable.
type volume interface {
	Mkdir(ctx context.Context, parent target, name string, mode uint32, created string) (observed, error)
	// Create opens the new file read/write, as an FSKit CREATE does; later
	// Write and handle-backed Truncate calls use that description.
	Create(ctx context.Context, parent target, name string, mode uint32, created string) (observed, error)
	Write(ctx context.Context, file target, offset int64, data []byte) (observed, error)
	Truncate(ctx context.Context, file target, size int64, throughHandle bool) (observed, error)
	Chmod(ctx context.Context, item target, mode uint32) (observed, error)
	SetTimes(ctx context.Context, item target, atimeNs, mtimeNs int64) (observed, error)
	Link(ctx context.Context, item, parent target, name string) (observed, error)
	Symlink(ctx context.Context, parent target, name, linkTarget, created string) (observed, error)
	Rename(ctx context.Context, oldParent target, oldName string, newParent target, newName string) error
	Unlink(ctx context.Context, parent target, name string, directory bool) error
	// Release returns every description and capability the session holds, the
	// way an unmount does. It runs after the last acknowledged step and so
	// carries no durability claim of its own.
	Release(ctx context.Context) error
}

// Timestamps the workload sets explicitly. They are far from any clock the run
// could produce, so a value that survived by accident cannot pass for one that
// was made durable.
const (
	explicitAtimeNs = int64(1700000000123456789)
	explicitMtimeNs = int64(1600000000987654321)
)

// workload drives the acknowledged-mutation sequence and keeps the ledger.
type workload struct {
	volume     volume
	marks      *powerloss.MarkChannel
	ledger     *powerloss.MutationLedger
	ledgerPath string
	progress   io.Writer
	state      powerloss.TreeState
}

func newWorkload(v volume, marks *powerloss.MarkChannel, ledger *powerloss.MutationLedger, ledgerPath string, progress io.Writer) *workload {
	return &workload{
		volume: v, marks: marks, ledger: ledger, ledgerPath: ledgerPath, progress: progress,
		state: powerloss.TreeState{Entries: map[string]string{}, Objects: map[string]powerloss.ObjectState{}},
	}
}

// run performs the sequence. Every step is one authority mutation covering a
// case the FSKit durability contract names: CREATE and its data, positioned
// overwrite and extension (including a hole), MKDIR, hard LINK, SYMLINK,
// RENAME within a directory, across directories and over an existing name,
// truncation through both a handle and an item, chmod, explicit timestamps,
// UNLINK of one of two names and of a symlink, and a directory removal. The
// order is fixed so a failure names a reproducible step.
func (w *workload) run(ctx context.Context) error {
	top := w.ledger.Prefix
	docs, archive := top+"/docs", top+"/archive"
	steps := []func() error{
		func() error { return w.mkdir(ctx, top, "top", 0o755) },
		func() error { return w.mkdir(ctx, docs, "docs", 0o755) },
		func() error { return w.mkdir(ctx, archive, "archive", 0o700) },
		func() error { return w.create(ctx, docs+"/alpha", "alpha", 0o644) },
		func() error { return w.write(ctx, "alpha", 0, 24576) },     // extend an empty file
		func() error { return w.write(ctx, "alpha", 8192, 4096) },   // overwrite in place
		func() error { return w.write(ctx, "alpha", 24576, 10000) }, // extend to an unaligned size
		func() error { return w.create(ctx, docs+"/beta", "beta", 0o600) },
		func() error { return w.write(ctx, "beta", 0, 16384) },
		func() error { return w.truncate(ctx, "beta", 5000, true) },    // handle-backed SETATTR size
		func() error { return w.truncate(ctx, "alpha", 20000, false) }, // item-backed SETATTR size
		func() error { return w.chmod(ctx, "alpha", 0o640) },
		func() error { return w.setTimes(ctx, "alpha", explicitAtimeNs, explicitMtimeNs) },
		func() error { return w.link(ctx, "alpha", archive+"/alpha-link") },
		func() error { return w.symlink(ctx, docs+"/alpha-symlink", "symlink", "alpha") },
		func() error { return w.rename(ctx, docs+"/beta", docs+"/beta-renamed") },
		func() error { return w.rename(ctx, docs+"/beta-renamed", archive+"/beta") },
		func() error { return w.create(ctx, archive+"/gamma", "gamma", 0o644) },
		func() error { return w.write(ctx, "gamma", 4096, 8192) },                // leaves a hole at [0, 4096)
		func() error { return w.rename(ctx, archive+"/gamma", archive+"/beta") }, // replaces beta
		func() error { return w.unlink(ctx, docs+"/alpha", false) },              // alpha keeps its other name
		func() error { return w.unlink(ctx, docs+"/alpha-symlink", false) },
		func() error { return w.mkdir(ctx, docs+"/scratch", "scratch", 0o755) },
		func() error { return w.unlink(ctx, docs+"/scratch", true) },
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("the workload stopped after %d acknowledged steps: %w", len(w.ledger.Steps), err)
		}
		if err := step(); err != nil {
			return fmt.Errorf("step %d: %w", len(w.ledger.Steps), err)
		}
	}
	return nil
}

// acknowledge runs after the authority's success reply. It checks the reply
// against the modelled state, records the step, takes the mark - so the mark
// lands after the acknowledgement and before the next mutation is sent - and
// only then publishes the ledger. A failure anywhere stops the run: a step that
// is acknowledged but unmarked, or marked but unrecorded, has no cut to be
// judged at.
func (w *workload) acknowledge(kind powerloss.MutationKind, description string, next powerloss.TreeState, label string, got *observed) error {
	if got != nil {
		if err := matchObserved(next.Objects[label], *got); err != nil {
			return fmt.Errorf("%s: %w", description, err)
		}
	}
	mark := fmt.Sprintf("fskit-%03d", len(w.ledger.Steps))
	w.ledger.Record(kind, description, mark, next)
	if err := w.marks.Take(mark); err != nil {
		return err
	}
	if err := w.ledger.Save(w.ledgerPath); err != nil {
		return err
	}
	w.state = next
	fmt.Fprintf(w.progress, "pfs-powerloss-fskit-driver: step %d acknowledged and marked %s: %s\n", len(w.ledger.Steps)-1, mark, description)
	return nil
}

func matchObserved(want powerloss.ObjectState, got observed) error {
	mismatch := func(field string, gotValue, wantValue any) error {
		return fmt.Errorf("the authority acknowledged %s %v, but the ledger models %v; the ledger would judge every cut against a state the authority never applied", field, gotValue, wantValue)
	}
	if got.kind != want.Kind {
		return mismatch("kind", got.kind, want.Kind)
	}
	if want.Kind != powerloss.ObjectSymlink && got.mode != want.Mode {
		return mismatch("mode", fmt.Sprintf("%#o", got.mode), fmt.Sprintf("%#o", want.Mode))
	}
	if want.Kind == powerloss.ObjectFile {
		if got.size != want.Size {
			return mismatch("size", got.size, want.Size)
		}
		if got.links != want.Links {
			return mismatch("hard-link count", got.links, want.Links)
		}
	}
	if want.AtimeNs != nil && got.atimeNs != *want.AtimeNs {
		return mismatch("atime", got.atimeNs, *want.AtimeNs)
	}
	if want.MtimeNs != nil && got.mtimeNs != *want.MtimeNs {
		return mismatch("mtime", got.mtimeNs, *want.MtimeNs)
	}
	return nil
}

// parentOf resolves the directory containing name. The prefix's parent is the
// volume root.
func (w *workload) parentOf(name string) (target, error) {
	parent := path.Dir(name)
	if parent == "." {
		return target{}, nil
	}
	label, exists := w.state.Entries[parent]
	if !exists {
		return target{}, fmt.Errorf("the workload has no directory %s", parent)
	}
	return target{label: label, path: parent}, nil
}

// reach returns a path that currently names label.
func (w *workload) reach(label string) (target, error) {
	best := ""
	for name, owner := range w.state.Entries {
		if owner == label && (best == "" || name < best) {
			best = name
		}
	}
	if best == "" {
		return target{}, fmt.Errorf("the workload has no name for object %q", label)
	}
	return target{label: label, path: best}, nil
}

// settle recomputes hard-link counts from the names and drops objects that
// lost their last name, so a recorded state is always self-consistent.
func settle(state powerloss.TreeState) {
	counts := make(map[string]uint32, len(state.Objects))
	for _, label := range state.Entries {
		counts[label]++
	}
	for label, object := range state.Objects {
		switch {
		case counts[label] == 0:
			delete(state.Objects, label)
		case object.Kind == powerloss.ObjectFile:
			object.Links = counts[label]
			state.Objects[label] = object
		}
	}
}

func (w *workload) mkdir(ctx context.Context, name, label string, mode uint32) error {
	parent, err := w.parentOf(name)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	next.Entries[name] = label
	next.Objects[label] = powerloss.ObjectState{Kind: powerloss.ObjectDirectory, Mode: mode}
	got, err := w.volume.Mkdir(ctx, parent, path.Base(name), mode, label)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", name, err)
	}
	return w.acknowledge(powerloss.MutationMkdir, fmt.Sprintf("mkdir %s mode %#o", name, mode), next, label, &got)
}

func (w *workload) create(ctx context.Context, name, label string, mode uint32) error {
	parent, err := w.parentOf(name)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	next.Entries[name] = label
	next.Objects[label] = powerloss.ObjectState{Kind: powerloss.ObjectFile, Mode: mode, Links: 1, SHA256: powerloss.Digest(nil)}
	got, err := w.volume.Create(ctx, parent, path.Base(name), mode, label)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	return w.acknowledge(powerloss.MutationCreate, fmt.Sprintf("create %s mode %#o", name, mode), next, label, &got)
}

func (w *workload) write(ctx context.Context, label string, offset, length int64) error {
	file, err := w.reach(label)
	if err != nil {
		return err
	}
	// Seeds are unique per write, so bytes from different writes are never
	// interchangeable and the stale-data rule can tell them apart.
	seed := 1000 + len(w.ledger.Steps)
	next := w.state.Clone()
	object := next.Objects[label]
	object.Spans = append(object.Spans, powerloss.ContentSpan{Offset: offset, Length: length, Seed: seed})
	object.Size = max(object.Size, offset+length)
	object.MtimeNs = nil
	object.SHA256 = powerloss.Digest(object.Content())
	next.Objects[label] = object
	got, err := w.volume.Write(ctx, file, offset, powerloss.GenerateContent(seed, length))
	if err != nil {
		return fmt.Errorf("write %s: %w", file.path, err)
	}
	description := fmt.Sprintf("write %s [%d, %d)", file.path, offset, offset+length)
	return w.acknowledge(powerloss.MutationWrite, description, next, label, &got)
}

func (w *workload) truncate(ctx context.Context, label string, size int64, throughHandle bool) error {
	file, err := w.reach(label)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	object := next.Objects[label]
	spans := object.Spans[:0:0]
	for _, span := range object.Spans {
		if span.Offset >= size {
			continue
		}
		span.Length = min(span.Length, size-span.Offset)
		spans = append(spans, span)
	}
	object.Spans, object.Size, object.MtimeNs = spans, size, nil
	object.SHA256 = powerloss.Digest(object.Content())
	next.Objects[label] = object
	got, err := w.volume.Truncate(ctx, file, size, throughHandle)
	if err != nil {
		return fmt.Errorf("truncate %s: %w", file.path, err)
	}
	kind, how := powerloss.MutationTruncateItem, "item"
	if throughHandle {
		kind, how = powerloss.MutationTruncateHandle, "handle"
	}
	return w.acknowledge(kind, fmt.Sprintf("truncate %s to %d through its %s", file.path, size, how), next, label, &got)
}

func (w *workload) chmod(ctx context.Context, label string, mode uint32) error {
	item, err := w.reach(label)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	object := next.Objects[label]
	object.Mode = mode
	next.Objects[label] = object
	got, err := w.volume.Chmod(ctx, item, mode)
	if err != nil {
		return fmt.Errorf("chmod %s: %w", item.path, err)
	}
	return w.acknowledge(powerloss.MutationChmod, fmt.Sprintf("chmod %s %#o", item.path, mode), next, label, &got)
}

func (w *workload) setTimes(ctx context.Context, label string, atimeNs, mtimeNs int64) error {
	item, err := w.reach(label)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	object := next.Objects[label]
	object.AtimeNs, object.MtimeNs = &atimeNs, &mtimeNs
	next.Objects[label] = object
	got, err := w.volume.SetTimes(ctx, item, atimeNs, mtimeNs)
	if err != nil {
		return fmt.Errorf("set times on %s: %w", item.path, err)
	}
	return w.acknowledge(powerloss.MutationSetTimes, fmt.Sprintf("set atime %d and mtime %d on %s", atimeNs, mtimeNs, item.path), next, label, &got)
}

func (w *workload) link(ctx context.Context, label, name string) error {
	item, err := w.reach(label)
	if err != nil {
		return err
	}
	parent, err := w.parentOf(name)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	next.Entries[name] = label
	settle(next)
	got, err := w.volume.Link(ctx, item, parent, path.Base(name))
	if err != nil {
		return fmt.Errorf("link %s to %s: %w", item.path, name, err)
	}
	return w.acknowledge(powerloss.MutationLink, fmt.Sprintf("link %s as %s", item.path, name), next, label, &got)
}

func (w *workload) symlink(ctx context.Context, name, label, linkTarget string) error {
	parent, err := w.parentOf(name)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	next.Entries[name] = label
	next.Objects[label] = powerloss.ObjectState{Kind: powerloss.ObjectSymlink, Target: linkTarget}
	got, err := w.volume.Symlink(ctx, parent, path.Base(name), linkTarget, label)
	if err != nil {
		return fmt.Errorf("symlink %s: %w", name, err)
	}
	return w.acknowledge(powerloss.MutationSymlink, fmt.Sprintf("symlink %s to %s", name, linkTarget), next, label, &got)
}

// rename moves one file name. Directory renames would also move every
// descendant path, which this model does not need and so does not implement.
func (w *workload) rename(ctx context.Context, from, to string) error {
	label, exists := w.state.Entries[from]
	if !exists || w.state.Objects[label].Kind != powerloss.ObjectFile {
		return fmt.Errorf("the workload renames only existing files, and %s is not one", from)
	}
	oldParent, err := w.parentOf(from)
	if err != nil {
		return err
	}
	newParent, err := w.parentOf(to)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	replaced := next.Entries[to]
	delete(next.Entries, from)
	next.Entries[to] = label
	settle(next)
	if err := w.volume.Rename(ctx, oldParent, path.Base(from), newParent, path.Base(to)); err != nil {
		return fmt.Errorf("rename %s to %s: %w", from, to, err)
	}
	description := fmt.Sprintf("rename %s to %s", from, to)
	if replaced != "" {
		description += fmt.Sprintf(", replacing object %q", replaced)
	}
	return w.acknowledge(powerloss.MutationRename, description, next, label, nil)
}

func (w *workload) unlink(ctx context.Context, name string, directory bool) error {
	label, exists := w.state.Entries[name]
	if !exists {
		return fmt.Errorf("the workload has no name %s to remove", name)
	}
	if directory {
		for other := range w.state.Entries {
			if strings.HasPrefix(other, name+"/") {
				return errors.New("the workload removes only empty directories")
			}
		}
	}
	parent, err := w.parentOf(name)
	if err != nil {
		return err
	}
	next := w.state.Clone()
	delete(next.Entries, name)
	settle(next)
	if err := w.volume.Unlink(ctx, parent, path.Base(name), directory); err != nil {
		return fmt.Errorf("unlink %s: %w", name, err)
	}
	kind, verb := powerloss.MutationUnlink, "unlink"
	if directory {
		kind, verb = powerloss.MutationRmdir, "rmdir"
	}
	// A surviving hard link's new count is visible only through the other
	// name; the next cut checks it, so the reply needs no comparison here.
	return w.acknowledge(kind, fmt.Sprintf("%s %s (object %q)", verb, name, label), next, label, nil)
}
