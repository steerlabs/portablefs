package workfs

import (
	"os"
	"sort"
)

// SupportsAtomicXattrFlags marks both workfs generations as consumers of the
// conditional xattr flags. fsproto advertises its rolling-upgrade capability
// only when this explicit marker is present.
func (*FS) SupportsAtomicXattrFlags() bool { return true }

// Extended-attribute serving.
//
// Xattrs are keyed by stable ino in fs.xattrs, mutated by
// OpSetxattr/OpRemovexattr through the ordinary journaled apply paths, and
// served by the read methods below. They remain outside tree hashes, but
// PFT2 cuts materialize filesystem-homed attributes into the user root so
// snapshots and forks preserve them: the HistoryCut materializer folds xattr
// records through the shared transition engine (named-tree rows anchored on
// both Root and RecoveryRoot; parked-orphan rows recovery-only), and
// PFT2-base adoption restores both projections, so trimming below the cut
// cannot drop them.

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
