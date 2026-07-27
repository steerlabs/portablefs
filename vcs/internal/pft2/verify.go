package pft2

import "bytes"

// Per-edge child verification.
//
// Every parent-advertised child summary (first key, last key, entry count)
// is a claim about the exact canonical content of the referenced child.
// Builders and the path-copy updater always emit exact summaries, so a
// fetched child must reproduce its advertisement exactly: the child's kind
// belongs to the edge's family (checked by fetchNode), its actual first and
// last keys equal the advertised bounds, and its actual entry count (leaf
// length, or the checked sum of its children's counts) equals the advertised
// count. Anything else is a crafted or corrupt graph and fails closed with
// ErrCorrupt before a single entry is served or copied.
//
// Verification is per fetched edge only: it inspects the already-decoded
// node and performs no additional fetches, so lazy reads stay lazy and
// unrelated subtrees are never scanned. A lie behind an edge that is never
// fetched is undetectable until that edge is traversed (see the residual
// notes in docs/history.md).

// edgeSummary is the canonical (firstKey, lastKey, entryCount) summary of
// one B+tree edge. Keys are normalized to canonical bytes: raw name bytes
// for directory trees, big-endian uint64 for extent and inode-index trees,
// and raw key bytes for control maps.
type edgeSummary struct {
	first []byte
	last  []byte
	count uint64
}

func directoryChildSummary(c *DirectoryIndexChild) edgeSummary {
	return edgeSummary{first: []byte(c.FirstName), last: []byte(c.LastName), count: c.EntryCount}
}

func extentChildSummary(c *ExtentIndexChild) edgeSummary {
	return edgeSummary{first: u64Key(c.FirstPage), last: u64Key(c.LastPage), count: c.EntryCount}
}

func inodeChildSummary(c *InodeIndexChild) edgeSummary {
	return edgeSummary{first: u64Key(c.FirstIno), last: u64Key(c.LastIno), count: c.EntryCount}
}

// nodeSummary returns the actual canonical summary of one fetched B+tree
// node. Aggregate counts are summed with checked arithmetic even though the
// node's own validation already bounds them, so no unchecked count addition
// exists anywhere.
func nodeSummary(n *Node) (edgeSummary, error) {
	switch n.Kind {
	case KindDirectoryLeaf:
		entries := n.DirectoryLeaf.Entries
		return edgeSummary{
			first: []byte(entries[0].Name),
			last:  []byte(entries[len(entries)-1].Name),
			count: uint64(len(entries)),
		}, nil
	case KindDirectoryIndex:
		children := n.DirectoryIndex.Children
		var total uint64
		for i := range children {
			var err error
			if total, err = addCount("directory index summary", total, children[i].EntryCount); err != nil {
				return edgeSummary{}, err
			}
		}
		return edgeSummary{
			first: []byte(children[0].FirstName),
			last:  []byte(children[len(children)-1].LastName),
			count: total,
		}, nil
	case KindExtentLeaf:
		entries := n.ExtentLeaf.Entries
		return edgeSummary{
			first: u64Key(entries[0].PageOffset),
			last:  u64Key(entries[len(entries)-1].PageOffset),
			count: uint64(len(entries)),
		}, nil
	case KindExtentIndex:
		children := n.ExtentIndex.Children
		var total uint64
		for i := range children {
			var err error
			if total, err = addCount("extent index summary", total, children[i].EntryCount); err != nil {
				return edgeSummary{}, err
			}
		}
		return edgeSummary{
			first: u64Key(children[0].FirstPage),
			last:  u64Key(children[len(children)-1].LastPage),
			count: total,
		}, nil
	case KindInodeIndexLeaf:
		entries := n.InodeIndexLeaf.Entries
		return edgeSummary{
			first: u64Key(entries[0].Ino),
			last:  u64Key(entries[len(entries)-1].Ino),
			count: uint64(len(entries)),
		}, nil
	case KindInodeIndexIndex:
		children := n.InodeIndexIndex.Children
		var total uint64
		for i := range children {
			var err error
			if total, err = addCount("inode index summary", total, children[i].EntryCount); err != nil {
				return edgeSummary{}, err
			}
		}
		return edgeSummary{
			first: u64Key(children[0].FirstIno),
			last:  u64Key(children[len(children)-1].LastIno),
			count: total,
		}, nil
	case KindControlLeaf:
		entries := n.ControlLeaf.Entries
		return edgeSummary{
			first: entries[0].Key,
			last:  entries[len(entries)-1].Key,
			count: uint64(len(entries)),
		}, nil
	case KindControlIndex:
		children := n.ControlIndex.Children
		var total uint64
		for i := range children {
			var err error
			if total, err = addCount("control index summary", total, children[i].EntryCount); err != nil {
				return edgeSummary{}, err
			}
		}
		return edgeSummary{
			first: children[0].FirstKey,
			last:  children[len(children)-1].LastKey,
			count: total,
		}, nil
	default:
		return edgeSummary{}, corruptf("node kind %s carries no child summary", n.Kind)
	}
}

// verifyEdgeSummary fails closed unless the fetched child's actual summary
// exactly equals the parent-advertised one.
func verifyEdgeSummary(what string, ref Ref, n *Node, want edgeSummary) error {
	got, err := nodeSummary(n)
	if err != nil {
		return err
	}
	if !bytes.Equal(got.first, want.first) || !bytes.Equal(got.last, want.last) || got.count != want.count {
		return corruptf(
			"%s: object %s actual summary (first %x, last %x, count %d) does not match advertised (first %x, last %x, count %d)",
			what, ref.Hex(), got.first, got.last, got.count, want.first, want.last, want.count)
	}
	return nil
}

// verifyFSIndexRootFacts pins the filesystem inode index root against the
// ROOT object's verified facts: the index must hold exactly InodeCount
// entries, its first inode must be the root directory (inode 1 is always
// live), and its last inode must not exceed the MaxInoSeen allocation
// high-water (which is an upper bound, not the exact maximum present, so
// only <= is provable).
func verifyFSIndexRootFacts(facts *Root, ref Ref, n *Node) error {
	got, err := nodeSummary(n)
	if err != nil {
		return err
	}
	if got.count != facts.InodeCount {
		return corruptf("inode index root %s holds %d entries, root advertised inode_count %d",
			ref.Hex(), got.count, facts.InodeCount)
	}
	if !bytes.Equal(got.first, u64Key(RootIno)) {
		return corruptf("inode index root %s first ino %d is not root ino %d",
			ref.Hex(), keyToU64(got.first), RootIno)
	}
	if bytes.Compare(got.last, u64Key(facts.MaxInoSeen)) > 0 {
		return corruptf("inode index root %s last ino %d exceeds max_ino_seen %d",
			ref.Hex(), keyToU64(got.last), facts.MaxInoSeen)
	}
	return nil
}
