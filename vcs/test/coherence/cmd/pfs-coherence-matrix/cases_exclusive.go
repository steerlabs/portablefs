package main

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"syscall"
)

// exclusiveCases run only in exclusive-writer mode, where mount A is the
// volume's only writer and mount B a reader.
func exclusiveCases() []coherenceCase {
	return []coherenceCase{
		{
			name: "writer_exclusion_refuses_reader_mutations",
			what: "while the writer is attached, every reader mutation and write-intent open fails with EBUSY and changes nothing either mount can observe",
			run:  runWriterExclusion,
		},
	}
}

// readerMutationAttempts names every kind of visible mutation the reader must
// be refused, against the fixture the case creates. Each request is issued
// directly on the reader's own mount.
func readerMutationAttempts(c *caseRun) []request {
	return []request{
		{Op: "open", Path: c.p("kept"), Flags: []string{"rdwr"}},
		{Op: "open", Path: c.p("kept"), Flags: []string{"wronly", "trunc"}},
		{Op: "open", Path: c.p("created"), Flags: []string{"wronly", "create", "excl"}, Mode: 0o644},
		{Op: "writefile", Path: c.p("written"), Data: []byte("reader"), Mode: 0o644},
		{Op: "remove", Path: c.p("kept")},
		{Op: "rename", Path: c.p("kept"), To: c.p("renamed")},
		{Op: "mkdir", Path: c.p("newdir"), Mode: 0o755},
		{Op: "remove", Path: c.p("keptdir")},
		{Op: "chmod", Path: c.p("kept"), Mode: 0o600},
		{Op: "truncate", Path: c.p("kept"), Size: 0},
		{Op: "utimes", Path: c.p("kept"), AtimeNs: 1_000_000_000, MtimeNs: 1_000_000_000},
		{Op: "symlink", Path: c.p("symlinked"), To: "kept"},
		{Op: "link", Path: c.p("kept"), To: c.p("hardlinked")},
	}
}

// exclusionMetadata includes the targets, their containing directory, and its
// parent. Compare each mount with itself: owner mapping, directory sizes and
// timestamp representations need not agree between FSKit and Linux.
type exclusionMetadata struct {
	kept, keptdir, dir, parent statInfo
}

// Preserve the initial cross-mount checks for the common logical attributes.
// FSKit exposes authority inode + 1; Linux exposes the authority inode itself.
// The full per-mount comparisons below retain each mount's own inode.
func (s exclusionMetadata) sameFixture(o exclusionMetadata) bool {
	return s.kept.Size == o.kept.Size && s.kept.Perm == o.kept.Perm &&
		s.kept.Nlink == o.kept.Nlink && s.kept.MtimeNs == o.kept.MtimeNs &&
		s.keptdir.Perm == o.keptdir.Perm && s.keptdir.IsDir == o.keptdir.IsDir
}

func (s exclusionMetadata) String() string {
	return fmt.Sprintf("kept=%s keptdir=%s dir=%s parent=%s", &s.kept, &s.keptdir, &s.dir, &s.parent)
}

func exclusionMetadataOn(c *caseRun, who actor) exclusionMetadata {
	var s exclusionMetadata
	for _, target := range []struct {
		path string
		stat *statInfo
	}{
		{c.p("kept"), &s.kept},
		{c.p("keptdir"), &s.keptdir},
		{c.dir, &s.dir},
		{path.Dir(c.dir), &s.parent},
	} {
		st, err := c.stat(who, target.path)
		if err != "" || st == nil {
			c.abort("%s: stat %s: %s (metadata present: %t)", who.name(), target.path, err, st != nil)
		}
		*target.stat = *st
	}
	return s
}

type exclusionSnapshot struct {
	names    []string
	keptData []byte
}

func (s exclusionSnapshot) equal(o exclusionSnapshot) bool {
	return slices.Equal(s.names, o.names) && bytes.Equal(s.keptData, o.keptData)
}

func (s exclusionSnapshot) String() string {
	return fmt.Sprintf("names=%v data=%q", s.names, preview(s.keptData))
}

// Observe contents only after both mounts' timestamp checks: reads and readdir
// can update the shared inode's atime even when exclusion is working.
func snapshotOn(c *caseRun, who actor) exclusionSnapshot {
	names := c.names(who, c.dir)
	data, err := c.readBytes(who, c.p("kept"))
	if err != "" {
		c.abort("%s: read kept: %s", who.name(), err)
	}
	return exclusionSnapshot{names: names, keptData: data}
}

func runWriterExclusion(c *caseRun) {
	if c.writer == nil || c.reader == nil {
		c.skipCase("needs --exclusive-writer: a macOS FSKit writer as mount A and a Linux reader as mount B")
	}
	c.writeFile(c.writer, c.p("kept"), []byte("written-by-the-exclusive-writer\n"), 0o644)
	c.ok(c.writer, request{Op: "mkdirall", Path: c.p("keptdir"), Mode: 0o755})
	before := snapshotOn(c, c.writer)
	if readerView := snapshotOn(c, c.reader); !readerView.equal(before) {
		c.abort("the reader does not observe the writer's fixture before any attempt: writer %s, reader %s", before, readerView)
	}

	writerMetadata, readerMetadata := exclusionMetadataOn(c, c.writer), exclusionMetadataOn(c, c.reader)
	if !readerMetadata.sameFixture(writerMetadata) {
		c.abort("the reader does not observe the writer's initial metadata: writer %s, reader %s", writerMetadata, readerMetadata)
	}
	mounts := []actor{c.writer, c.reader}
	for _, req := range readerMutationAttempts(c) {
		// All observational reads from the preceding attempt finish before
		// these baselines; no content read intervenes until both checks end.
		beforeMetadata := make([]exclusionMetadata, len(mounts))
		for i, who := range mounts {
			beforeMetadata[i] = exclusionMetadataOn(c, who)
		}
		out := c.do(c.reader, req)
		if out.Handle != 0 {
			// A write-intent open that succeeded is itself the violation;
			// release the descriptor so the case can still report the rest.
			c.do(c.reader, request{Op: "closehandle", Handle: out.Handle})
		}
		switch {
		case out.Err == "":
			c.fail("%s: %s %s succeeded while the writer is attached; writer exclusion requires EBUSY", c.reader.name(), req.Op, req.Path)
		case out.Errno != int(syscall.EBUSY):
			c.fail("%s: %s %s failed with errno=%d (%s), want EBUSY from writer exclusion", c.reader.name(), req.Op, req.Path, out.Errno, out.Err)
		}
		// No refused attempt may leave a partial effect visible to either
		// mount, and both mounts must still read the fixture.
		for i, who := range mounts {
			if after := exclusionMetadataOn(c, who); after != beforeMetadata[i] {
				c.fail("%s: metadata changed after the reader's refused %s %s: before %s, after %s",
					who.name(), req.Op, req.Path, beforeMetadata[i], after)
			}
		}
		for _, who := range mounts {
			if after := snapshotOn(c, who); !after.equal(before) {
				c.fail("%s: the fixture changed after the reader's refused %s %s: before %s, after %s",
					who.name(), req.Op, req.Path, before, after)
			}
		}
	}

	// The refusals must not have wedged either mount: the writer still
	// mutates and the reader still observes the change coherently.
	c.writeFile(c.writer, c.p("after"), []byte("still-writable\n"), 0o644)
	c.expectBytes(c.reader, c.p("after"), []byte("still-writable\n"), "writer mutation after the refused reader attempts")
}
