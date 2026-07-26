package workfs

import (
	"fmt"
	"os"
	"sort"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// SupportsAtomicXattrFlags marks both workfs generations as consumers of the
// conditional xattr flags. fsproto advertises its rolling-upgrade capability
// only when this explicit marker is present.
func (*FS) SupportsAtomicXattrFlags() bool { return true }

// Extended-attribute serving and legacy-compaction persistence.
//
// Xattrs are keyed by stable ino in fs.xattrs, mutated by
// OpSetxattr/OpRemovexattr through the ordinary journaled apply paths, and
// served by the read methods below. They remain outside legacy manifests and
// tree hashes, but managed PFT2 cuts materialize filesystem-homed attributes
// into the user root so snapshots and forks preserve them. Live state must
// never silently lose them:
//
//   - managed generations: the HistoryCut materializer folds xattr records
//     through the shared transition engine. Named-tree rows are anchored on
//     both Root and RecoveryRoot; parked-orphan rows are recovery-only.
//     PFT2-base adoption restores both projections, so trimming below the cut
//     cannot drop them;
//   - the legacy WAL store: the backend manifest cannot carry xattrs, so
//     CompactWAL/ResetWAL re-append the live xattr state as ordinary
//     path-addressed OpSetxattr records AT/ABOVE the compaction cut (the
//     same discipline as the control snapshot) — replay re-applies them
//     idempotently. Parked orphans are the one exception: legacy orphans are
//     themselves not persisted across restart (see the orphans field docs),
//     so their xattrs honestly share that documented fate.

// GetxattrHandle returns the named extended attribute of the inode addressed
// by ino (else path) — named or parked orphan. A missing attribute is
// errNoXattr (ENODATA); a missing inode is os.ErrNotExist. The returned
// value is a private copy.
func (fs *FS) GetxattrHandle(path string, ino uint64, name string) ([]byte, error) {
	var out []byte
	err := fs.withReadHandle(path, ino, func(n *inode) error {
		if n == nil {
			return os.ErrNotExist
		}
		v, ok := fs.xattrs[n.ino][name]
		if !ok {
			return errNoXattr
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// ListxattrHandle returns the sorted extended-attribute names of the inode
// addressed by ino (else path). A file with no xattrs lists empty (nil).
func (fs *FS) ListxattrHandle(path string, ino uint64) ([]string, error) {
	var out []string
	err := fs.withReadHandle(path, ino, func(n *inode) error {
		if n == nil {
			return os.ErrNotExist
		}
		for name := range fs.xattrs[n.ino] {
			out = append(out, name)
		}
		sort.Strings(out)
		return nil
	})
	return out, err
}

// XattrsByIno returns a copy of one inode's live xattrs (tests/diagnostics).
func (fs *FS) XattrsByIno(ino uint64) map[string][]byte {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	m := fs.xattrs[ino]
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// xattrSnapshotRecords re-materializes the whole live NAMED-tree xattr state
// as path-addressed OpSetxattr records, sorted by (path, name) for
// deterministic bytes. Path-addressed (Ino=0) on purpose: a pre-identity
// manifest reload renumbers inos, so a logged ino could dangle — the path at
// this LSN always names the same inode because every later rename/remove
// rides a later record. Parked orphans have no name and are skipped (legacy
// orphans do not survive a restart anyway — documented above).
// Caller holds fs.mu (read or write).
func (fs *FS) xattrSnapshotRecordsLocked() []wal.Record {
	type row struct {
		path, name string
		value      []byte
	}
	var rows []row
	var walk func(prefix string, n *inode)
	walk = func(prefix string, n *inode) {
		for childName, c := range n.children {
			p := childName
			if prefix != "" {
				p = prefix + "/" + childName
			}
			for name, value := range fs.xattrs[c.ino] {
				rows = append(rows, row{path: p, name: name, value: value})
			}
			if c.kind == "directory" {
				walk(p, c)
			}
		}
	}
	// Root-inode xattrs (path "") are addressable: OpSetxattr resolves the
	// empty path to the root like every other handle-less attr op.
	for name, value := range fs.xattrs[fs.root.ino] {
		rows = append(rows, row{path: "", name: name, value: value})
	}
	walk("", fs.root)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		return rows[i].name < rows[j].name
	})
	out := make([]wal.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, wal.Record{
			Op: wal.OpSetxattr, Path: r.path, XattrName: r.name,
			Data: append([]byte(nil), r.value...),
		})
	}
	return out
}

// appendXattrSnapshot re-appends the live xattr state to the WAL so it
// survives a checkpoint compaction whose backend manifest cannot carry it —
// the exact discipline of appendControlSnapshot. The records land at LSNs at
// or above the compaction watermark, so CompactThrough keeps them and replay
// re-applies them idempotently (set semantics). State is unchanged here: the
// live tree already holds these xattrs, so nothing is applied, versioned, or
// published.
func (fs *FS) appendXattrSnapshot() error {
	fs.mu.Lock()
	records := fs.xattrSnapshotRecordsLocked()
	if len(records) == 0 {
		fs.mu.Unlock()
		return nil
	}
	_, end, bufErr := fs.wal.AppendBatchBuffered(records)
	fs.mu.Unlock()
	if bufErr != nil {
		return bufErr
	}
	if cErr := fs.wal.CommitThrough(end - 1); cErr != nil {
		return fmt.Errorf("%w (xattr snapshot durability: %v)", ErrDurabilityUnknown, cErr)
	}
	return nil
}
