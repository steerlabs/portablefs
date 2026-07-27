package pft2

import (
	"bytes"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// EncodeNode encodes a validated node into its unique canonical PFT2 byte
// string ("PFT2" magic plus strict pfwire body). Encoding a node the strict
// decoder would reject is an error, so the two directions accept exactly the
// same value space.
func EncodeNode(n *Node) ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	body := pfwire.AppendUint(nil, 1, uint64(n.Kind))
	armField := uint32(n.Kind) + 1
	var arm []byte
	switch n.Kind {
	case KindRoot:
		arm = appendRoot(nil, n.Root)
	case KindInode:
		arm = appendInode(nil, n.Inode)
	case KindDirectoryLeaf:
		arm = appendDirectoryLeaf(nil, n.DirectoryLeaf)
	case KindDirectoryIndex:
		arm = appendDirectoryIndex(nil, n.DirectoryIndex)
	case KindExtentLeaf:
		arm = appendExtentLeaf(nil, n.ExtentLeaf)
	case KindExtentIndex:
		arm = appendExtentIndex(nil, n.ExtentIndex)
	case KindInodeIndexLeaf:
		arm = appendInodeIndexLeaf(nil, n.InodeIndexLeaf)
	case KindInodeIndexIndex:
		arm = appendInodeIndexIndex(nil, n.InodeIndexIndex)
	case KindRecoveryRoot:
		arm = appendRecoveryRoot(nil, n.RecoveryRoot)
	case KindDataPage:
		arm = appendDataPage(nil, n.DataPage)
	case KindControlRoot:
		arm = appendControlRoot(nil, n.ControlRoot)
	case KindControlLeaf:
		arm = appendControlLeaf(nil, n.ControlLeaf)
	case KindControlIndex:
		arm = appendControlIndex(nil, n.ControlIndex)
	case KindXattrLeaf:
		arm = appendXattrLeaf(nil, n.XattrLeaf)
	}
	// Validation guarantees every arm encodes at least one field, so the
	// pfwire empty-message omission rule can never drop a required arm.
	body = pfwire.AppendBytes(body, armField, arm)
	out := make([]byte, 0, len(Magic)+len(body))
	out = append(out, Magic[:]...)
	out = append(out, body...)
	if len(out) > MaxNodeBytes {
		return nil, invalidf("encoded %s node is %d bytes (max %d)", n.Kind, len(out), MaxNodeBytes)
	}
	return out, nil
}

// MustEncodeNode encodes a node the caller has already constructed validly;
// it panics on a programming error. Builders use it after Validate.
func MustEncodeNode(n *Node) []byte {
	encoded, err := EncodeNode(n)
	if err != nil {
		panic(err)
	}
	return encoded
}

// DecodeNode strictly decodes one canonical PFT2 object. It rejects anything
// non-canonical, unknown, out of bounds, or trailing, and re-validates the
// decoded structure, so any accepted object re-encodes to identical bytes.
// Callers must have verified size and digest first (VerifyObjectBytes).
func DecodeNode(data []byte) (*Node, error) {
	if len(data) > MaxNodeBytes {
		return nil, invalidf("node is %d bytes (max %d)", len(data), MaxNodeBytes)
	}
	if len(data) < MinNodeBytes {
		return nil, invalidf("node is %d bytes (min %d)", len(data), MinNodeBytes)
	}
	if !bytes.Equal(data[:4], Magic[:]) {
		return nil, invalidf("object does not begin with the PFT2 magic")
	}
	n, err := decodeNodeBody(data[4:])
	if err != nil {
		return nil, err
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// DecodeNodeKind decodes data and additionally requires the node kind
// advertised by the edge the object was reached through, so a filesystem walk
// can never continue into a node of the wrong type.
func DecodeNodeKind(data []byte, want Kind) (*Node, error) {
	n, err := DecodeNode(data)
	if err != nil {
		return nil, err
	}
	if n.Kind != want {
		return nil, corruptf("expected %s node, decoded %s", want, n.Kind)
	}
	return n, nil
}

// ─── shared sub-encoders ────────────────────────────────────────────────────

func appendRefBody(dst []byte, r Ref) []byte {
	dst = pfwire.AppendBytes(dst, 1, r.Digest[:])
	dst = pfwire.AppendUint(dst, 2, r.Size)
	return dst
}

func appendRef(dst []byte, field uint32, r Ref) []byte {
	return pfwire.AppendBytes(dst, field, appendRefBody(nil, r))
}

func appendOptionalRef(dst []byte, field uint32, r *Ref) []byte {
	if r == nil {
		return dst
	}
	return appendRef(dst, field, *r)
}

func appendRoot(dst []byte, r *Root) []byte {
	dst = appendRef(dst, 1, r.RootInode)
	dst = appendRef(dst, 2, r.InodeIndex)
	dst = pfwire.AppendUint(dst, 3, r.MaxInoSeen)
	dst = pfwire.AppendUint(dst, 4, r.InodeCount)
	dst = pfwire.AppendUint(dst, 5, r.DirentCount)
	dst = pfwire.AppendUint(dst, 6, r.LogicalBytes)
	dst = pfwire.AppendUint(dst, 7, r.Features)
	for _, ref := range r.XattrLeaves {
		dst = appendRef(dst, 8, ref)
	}
	return dst
}

func appendInode(dst []byte, ino *Inode) []byte {
	dst = pfwire.AppendUint(dst, 1, ino.Ino)
	dst = pfwire.AppendUint(dst, 2, uint64(ino.Kind))
	dst = pfwire.AppendUint(dst, 3, uint64(ino.Mode))
	dst = pfwire.AppendUint(dst, 4, uint64(ino.UID))
	dst = pfwire.AppendUint(dst, 5, uint64(ino.GID))
	dst = pfwire.AppendUint(dst, 6, ino.Nlink)
	dst = pfwire.AppendUint(dst, 7, ino.Size)
	dst = pfwire.AppendSint(dst, 8, ino.MtimeMs)
	dst = pfwire.AppendSint(dst, 9, ino.CtimeMs)
	dst = pfwire.AppendSint(dst, 10, ino.AtimeMs)
	dst = appendOptionalRef(dst, 11, ino.DirectoryRoot)
	dst = appendOptionalRef(dst, 12, ino.ExtentRoot)
	dst = pfwire.AppendString(dst, 13, ino.SymlinkTarget)
	return dst
}

func appendDirEntry(dst []byte, e *DirEntry) []byte {
	dst = pfwire.AppendString(dst, 1, e.Name)
	dst = pfwire.AppendUint(dst, 2, e.Ino)
	dst = pfwire.AppendUint(dst, 3, uint64(e.Kind))
	return dst
}

func appendDirectoryLeaf(dst []byte, l *DirectoryLeaf) []byte {
	for i := range l.Entries {
		dst = pfwire.AppendBytes(dst, 1, appendDirEntry(nil, &l.Entries[i]))
	}
	return dst
}

func appendDirectoryIndex(dst []byte, x *DirectoryIndex) []byte {
	for i := range x.Children {
		c := &x.Children[i]
		child := pfwire.AppendString(nil, 1, c.FirstName)
		child = pfwire.AppendString(child, 2, c.LastName)
		child = appendRef(child, 3, c.Child)
		child = pfwire.AppendUint(child, 4, c.EntryCount)
		dst = pfwire.AppendBytes(dst, 1, child)
	}
	return dst
}

func appendExtentLeaf(dst []byte, l *ExtentLeaf) []byte {
	for i := range l.Entries {
		e := &l.Entries[i]
		entry := pfwire.AppendUint(nil, 1, e.PageOffset)
		entry = appendRef(entry, 2, e.Page)
		dst = pfwire.AppendBytes(dst, 1, entry)
	}
	return dst
}

func appendExtentIndex(dst []byte, x *ExtentIndex) []byte {
	for i := range x.Children {
		c := &x.Children[i]
		child := pfwire.AppendUint(nil, 1, c.FirstPage)
		child = pfwire.AppendUint(child, 2, c.LastPage)
		child = appendRef(child, 3, c.Child)
		child = pfwire.AppendUint(child, 4, c.EntryCount)
		dst = pfwire.AppendBytes(dst, 1, child)
	}
	return dst
}

func appendInodeIndexLeaf(dst []byte, l *InodeIndexLeaf) []byte {
	for i := range l.Entries {
		e := &l.Entries[i]
		entry := pfwire.AppendUint(nil, 1, e.Ino)
		entry = appendRef(entry, 2, e.Inode)
		dst = pfwire.AppendBytes(dst, 1, entry)
	}
	return dst
}

func appendInodeIndexIndex(dst []byte, x *InodeIndexIndex) []byte {
	for i := range x.Children {
		c := &x.Children[i]
		child := pfwire.AppendUint(nil, 1, c.FirstIno)
		child = pfwire.AppendUint(child, 2, c.LastIno)
		child = appendRef(child, 3, c.Child)
		child = pfwire.AppendUint(child, 4, c.EntryCount)
		dst = pfwire.AppendBytes(dst, 1, child)
	}
	return dst
}

func appendRecoveryRoot(dst []byte, r *RecoveryRoot) []byte {
	dst = pfwire.AppendUint(dst, 1, r.AsOfSeq)
	dst = appendRef(dst, 2, r.FilesystemRoot)
	dst = appendOptionalRef(dst, 3, r.ControlRoot)
	dst = appendOptionalRef(dst, 4, r.OrphanIndex)
	dst = pfwire.AppendUint(dst, 5, uint64(r.InoNamespace))
	dst = pfwire.AppendUint(dst, 6, r.NextLocal)
	dst = pfwire.AppendUint(dst, 7, r.Features)
	for _, ref := range r.XattrLeaves {
		dst = appendRef(dst, 8, ref)
	}
	return dst
}

func appendXattrLeaf(dst []byte, l *XattrLeaf) []byte {
	for i := range l.Entries {
		e := &l.Entries[i]
		entry := pfwire.AppendUint(nil, 1, e.Ino)
		entry = pfwire.AppendString(entry, 2, e.Name)
		entry = pfwire.AppendBytes(entry, 3, e.Value)
		dst = pfwire.AppendBytes(dst, 1, entry)
	}
	return dst
}

func appendDataPage(dst []byte, p *DataPage) []byte {
	for i, c := range p.Cells {
		if c == nil {
			continue
		}
		cell := pfwire.AppendBytes(nil, 1, c.CellDigest[:])
		cell = appendRef(cell, 2, c.Object)
		cell = pfwire.AppendUint(cell, 3, c.ObjectOffset)
		dst = pfwire.AppendBytes(dst, uint32(i+1), cell)
	}
	return dst
}

func appendControlRoot(dst []byte, r *ControlRoot) []byte {
	dst = pfwire.AppendUint(dst, 1, r.Schema)
	dst = appendOptionalRef(dst, 2, r.MapRoot)
	dst = pfwire.AppendUint(dst, 3, r.NextCheckoutEpoch)
	dst = pfwire.AppendUint(dst, 4, r.Features)
	for i := range r.Counts {
		c := &r.Counts[i]
		count := pfwire.AppendUint(nil, 1, c.Kind)
		count = pfwire.AppendUint(count, 2, c.Count)
		dst = pfwire.AppendBytes(dst, 5, count)
	}
	dst = pfwire.AppendUint(dst, 6, r.DbTimeFloorMs)
	return dst
}

func appendControlLeaf(dst []byte, l *ControlLeaf) []byte {
	for i := range l.Entries {
		e := &l.Entries[i]
		entry := pfwire.AppendBytes(nil, 1, e.Key)
		entry = pfwire.AppendUint(entry, 2, e.Kind)
		entry = pfwire.AppendBytes(entry, 3, e.Value)
		dst = pfwire.AppendBytes(dst, 1, entry)
	}
	return dst
}

func appendControlIndex(dst []byte, x *ControlIndex) []byte {
	for i := range x.Children {
		c := &x.Children[i]
		child := pfwire.AppendBytes(nil, 1, c.FirstKey)
		child = pfwire.AppendBytes(child, 2, c.LastKey)
		child = appendRef(child, 3, c.Child)
		child = pfwire.AppendUint(child, 4, c.EntryCount)
		dst = pfwire.AppendBytes(dst, 1, child)
	}
	return dst
}

// ─── strict decoders ────────────────────────────────────────────────────────

func decodeNodeBody(body []byte) (*Node, error) {
	rd := pfwire.NewReader("pft2 node", body)
	n := &Node{}
	armSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		if field == 1 {
			if wt != pfwire.TypeVarint {
				return nil, rd.Malformedf("kind wire type %d", wt)
			}
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v < uint64(minKind) || v > uint64(maxKind) {
				return nil, rd.Malformedf("unknown kind %d", v)
			}
			n.Kind = Kind(v)
			continue
		}
		if n.Kind == 0 {
			return nil, rd.Malformedf("arm field %d before kind", field)
		}
		if field != uint32(n.Kind)+1 {
			return nil, rd.Malformedf("kind %s cannot carry arm field %d", n.Kind, field)
		}
		if wt != pfwire.TypeBytes {
			return nil, rd.Malformedf("arm field %d wire type %d", field, wt)
		}
		msg, err := rd.Bytes(field, MaxNodeBytes)
		if err != nil {
			return nil, err
		}
		armSeen = true
		switch n.Kind {
		case KindRoot:
			n.Root, err = decodeRoot(msg)
		case KindInode:
			n.Inode, err = decodeInode(msg)
		case KindDirectoryLeaf:
			n.DirectoryLeaf, err = decodeDirectoryLeaf(msg)
		case KindDirectoryIndex:
			n.DirectoryIndex, err = decodeDirectoryIndex(msg)
		case KindExtentLeaf:
			n.ExtentLeaf, err = decodeExtentLeaf(msg)
		case KindExtentIndex:
			n.ExtentIndex, err = decodeExtentIndex(msg)
		case KindInodeIndexLeaf:
			n.InodeIndexLeaf, err = decodeInodeIndexLeaf(msg)
		case KindInodeIndexIndex:
			n.InodeIndexIndex, err = decodeInodeIndexIndex(msg)
		case KindRecoveryRoot:
			n.RecoveryRoot, err = decodeRecoveryRoot(msg)
		case KindDataPage:
			n.DataPage, err = decodeDataPage(msg)
		case KindControlRoot:
			n.ControlRoot, err = decodeControlRoot(msg)
		case KindControlLeaf:
			n.ControlLeaf, err = decodeControlLeaf(msg)
		case KindControlIndex:
			n.ControlIndex, err = decodeControlIndex(msg)
		case KindXattrLeaf:
			n.XattrLeaf, err = decodeXattrLeaf(msg)
		}
		if err != nil {
			return nil, err
		}
	}
	if n.Kind == 0 {
		return nil, invalidf("node is missing kind")
	}
	if !armSeen {
		return nil, invalidf("kind %s node is missing its arm", n.Kind)
	}
	return n, nil
}

func decodeRef(what string, body []byte) (Ref, error) {
	rd := pfwire.NewReader(what, body)
	var r Ref
	digestSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return Ref{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return Ref{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, DigestBytes)
			if err != nil {
				return Ref{}, err
			}
			if len(b) != DigestBytes {
				return Ref{}, rd.Malformedf("digest is %d bytes (want %d)", len(b), DigestBytes)
			}
			copy(r.Digest[:], b)
			digestSeen = true
		case field == 2 && wt == pfwire.TypeVarint:
			if r.Size, err = rd.Uint(field); err != nil {
				return Ref{}, err
			}
		default:
			return Ref{}, rd.RejectUnknown(field)
		}
	}
	if !digestSeen {
		return Ref{}, rd.Malformedf("missing digest")
	}
	if r.Size == 0 {
		return Ref{}, rd.Malformedf("missing size")
	}
	return r, nil
}

func decodeRefField(rd *pfwire.Reader, field uint32, what string) (Ref, error) {
	msg, err := rd.Bytes(field, MaxNodeBytes)
	if err != nil {
		return Ref{}, err
	}
	return decodeRef(what, msg)
}

func decodeRoot(body []byte) (*Root, error) {
	rd := pfwire.NewReader("pft2 root", body)
	var r Root
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if field == 8 {
			if err := rd.RequireRepeated(field); err != nil {
				return nil, err
			}
		} else if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if r.RootInode, err = decodeRefField(rd, field, "pft2 root inode ref"); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if r.InodeIndex, err = decodeRefField(rd, field, "pft2 root inode index ref"); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			if r.MaxInoSeen, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if r.InodeCount, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if r.DirentCount, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeVarint:
			if r.LogicalBytes, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if r.Features, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 8 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 root xattr leaf ref")
			if err != nil {
				return nil, err
			}
			r.XattrLeaves = append(r.XattrLeaves, ref)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &r, nil
}

func decodeInode(body []byte) (*Inode, error) {
	rd := pfwire.NewReader("pft2 inode", body)
	var ino Inode
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if ino.Ino, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return nil, err
			}
			if v > uint64(FileKindSymlink) {
				return nil, rd.Malformedf("unknown file kind %d", v)
			}
			ino.Kind = FileKind(v)
		case field == 3 && wt == pfwire.TypeVarint:
			if ino.Mode, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if ino.UID, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeVarint:
			if ino.GID, err = rd.Uint32(field); err != nil {
				return nil, err
			}
		case field == 6 && wt == pfwire.TypeVarint:
			if ino.Nlink, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if ino.Size, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 8 && wt == pfwire.TypeVarint:
			if ino.MtimeMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 9 && wt == pfwire.TypeVarint:
			if ino.CtimeMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 10 && wt == pfwire.TypeVarint:
			if ino.AtimeMs, err = rd.Sint(field); err != nil {
				return nil, err
			}
		case field == 11 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 inode directory root ref")
			if err != nil {
				return nil, err
			}
			ino.DirectoryRoot = &ref
		case field == 12 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 inode extent root ref")
			if err != nil {
				return nil, err
			}
			ino.ExtentRoot = &ref
		case field == 13 && wt == pfwire.TypeBytes:
			if ino.SymlinkTarget, err = rd.String(field, MaxSymlinkTargetBytes); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &ino, nil
}

func decodeDirEntry(body []byte) (DirEntry, error) {
	rd := pfwire.NewReader("pft2 dir entry", body)
	var e DirEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return DirEntry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return DirEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if e.Name, err = rd.String(field, MaxNameBytes); err != nil {
				return DirEntry{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if e.Ino, err = rd.Uint(field); err != nil {
				return DirEntry{}, err
			}
		case field == 3 && wt == pfwire.TypeVarint:
			v, err := rd.Uint(field)
			if err != nil {
				return DirEntry{}, err
			}
			if v > uint64(FileKindSymlink) {
				return DirEntry{}, rd.Malformedf("unknown file kind %d", v)
			}
			e.Kind = FileKind(v)
		default:
			return DirEntry{}, rd.RejectUnknown(field)
		}
	}
	return e, nil
}

// decodeRepeated drives a message whose only field is a bounded repeated
// message at field 1.
func decodeRepeated(what string, body []byte, decode func(msg []byte) error) error {
	rd := pfwire.NewReader(what, body)
	count := 0
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if field != 1 || wt != pfwire.TypeBytes {
			return rd.RejectUnknown(field)
		}
		if err := rd.RequireRepeated(field); err != nil {
			return err
		}
		msg, err := rd.Bytes(field, MaxNodeBytes)
		if err != nil {
			return err
		}
		count++
		if count > MaxLeafEntries {
			return rd.Malformedf("more than %d elements", MaxLeafEntries)
		}
		if err := decode(msg); err != nil {
			return err
		}
	}
}

func decodeDirectoryLeaf(body []byte) (*DirectoryLeaf, error) {
	var l DirectoryLeaf
	err := decodeRepeated("pft2 directory leaf", body, func(msg []byte) error {
		e, err := decodeDirEntry(msg)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func decodeDirectoryIndexChild(body []byte) (DirectoryIndexChild, error) {
	rd := pfwire.NewReader("pft2 directory index child", body)
	var c DirectoryIndexChild
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return DirectoryIndexChild{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return DirectoryIndexChild{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			if c.FirstName, err = rd.String(field, MaxNameBytes); err != nil {
				return DirectoryIndexChild{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if c.LastName, err = rd.String(field, MaxNameBytes); err != nil {
				return DirectoryIndexChild{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if c.Child, err = decodeRefField(rd, field, "pft2 directory index child ref"); err != nil {
				return DirectoryIndexChild{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if c.EntryCount, err = rd.Uint(field); err != nil {
				return DirectoryIndexChild{}, err
			}
		default:
			return DirectoryIndexChild{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodeDirectoryIndex(body []byte) (*DirectoryIndex, error) {
	var x DirectoryIndex
	err := decodeRepeated("pft2 directory index", body, func(msg []byte) error {
		c, err := decodeDirectoryIndexChild(msg)
		if err != nil {
			return err
		}
		x.Children = append(x.Children, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func decodeExtentEntry(body []byte) (ExtentEntry, error) {
	rd := pfwire.NewReader("pft2 extent entry", body)
	var e ExtentEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ExtentEntry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ExtentEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if e.PageOffset, err = rd.Uint(field); err != nil {
				return ExtentEntry{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if e.Page, err = decodeRefField(rd, field, "pft2 extent page ref"); err != nil {
				return ExtentEntry{}, err
			}
		default:
			return ExtentEntry{}, rd.RejectUnknown(field)
		}
	}
	return e, nil
}

func decodeExtentLeaf(body []byte) (*ExtentLeaf, error) {
	var l ExtentLeaf
	err := decodeRepeated("pft2 extent leaf", body, func(msg []byte) error {
		e, err := decodeExtentEntry(msg)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func decodeExtentIndexChild(body []byte) (ExtentIndexChild, error) {
	rd := pfwire.NewReader("pft2 extent index child", body)
	var c ExtentIndexChild
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ExtentIndexChild{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ExtentIndexChild{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if c.FirstPage, err = rd.Uint(field); err != nil {
				return ExtentIndexChild{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if c.LastPage, err = rd.Uint(field); err != nil {
				return ExtentIndexChild{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if c.Child, err = decodeRefField(rd, field, "pft2 extent index child ref"); err != nil {
				return ExtentIndexChild{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if c.EntryCount, err = rd.Uint(field); err != nil {
				return ExtentIndexChild{}, err
			}
		default:
			return ExtentIndexChild{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodeExtentIndex(body []byte) (*ExtentIndex, error) {
	var x ExtentIndex
	err := decodeRepeated("pft2 extent index", body, func(msg []byte) error {
		c, err := decodeExtentIndexChild(msg)
		if err != nil {
			return err
		}
		x.Children = append(x.Children, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func decodeInodeIndexEntry(body []byte) (InodeIndexEntry, error) {
	rd := pfwire.NewReader("pft2 inode index entry", body)
	var e InodeIndexEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return InodeIndexEntry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return InodeIndexEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if e.Ino, err = rd.Uint(field); err != nil {
				return InodeIndexEntry{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if e.Inode, err = decodeRefField(rd, field, "pft2 inode index inode ref"); err != nil {
				return InodeIndexEntry{}, err
			}
		default:
			return InodeIndexEntry{}, rd.RejectUnknown(field)
		}
	}
	return e, nil
}

func decodeInodeIndexLeaf(body []byte) (*InodeIndexLeaf, error) {
	var l InodeIndexLeaf
	err := decodeRepeated("pft2 inode index leaf", body, func(msg []byte) error {
		e, err := decodeInodeIndexEntry(msg)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func decodeInodeIndexChild(body []byte) (InodeIndexChild, error) {
	rd := pfwire.NewReader("pft2 inode index child", body)
	var c InodeIndexChild
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return InodeIndexChild{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return InodeIndexChild{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if c.FirstIno, err = rd.Uint(field); err != nil {
				return InodeIndexChild{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if c.LastIno, err = rd.Uint(field); err != nil {
				return InodeIndexChild{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			if c.Child, err = decodeRefField(rd, field, "pft2 inode index child ref"); err != nil {
				return InodeIndexChild{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if c.EntryCount, err = rd.Uint(field); err != nil {
				return InodeIndexChild{}, err
			}
		default:
			return InodeIndexChild{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodeInodeIndexIndex(body []byte) (*InodeIndexIndex, error) {
	var x InodeIndexIndex
	err := decodeRepeated("pft2 inode index index", body, func(msg []byte) error {
		c, err := decodeInodeIndexChild(msg)
		if err != nil {
			return err
		}
		x.Children = append(x.Children, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func decodeRecoveryRoot(body []byte) (*RecoveryRoot, error) {
	rd := pfwire.NewReader("pft2 recovery root", body)
	var r RecoveryRoot
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if field == 8 {
			if err := rd.RequireRepeated(field); err != nil {
				return nil, err
			}
		} else if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if r.AsOfSeq, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if r.FilesystemRoot, err = decodeRefField(rd, field, "pft2 recovery filesystem root ref"); err != nil {
				return nil, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 recovery control root ref")
			if err != nil {
				return nil, err
			}
			r.ControlRoot = &ref
		case field == 4 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 recovery orphan index ref")
			if err != nil {
				return nil, err
			}
			r.OrphanIndex = &ref
		case field == 5 && wt == pfwire.TypeVarint:
			v, err := rd.Uint32(field)
			if err != nil {
				return nil, err
			}
			r.InoNamespace = v
		case field == 6 && wt == pfwire.TypeVarint:
			if r.NextLocal, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 7 && wt == pfwire.TypeVarint:
			if r.Features, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 8 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 recovery xattr leaf ref")
			if err != nil {
				return nil, err
			}
			r.XattrLeaves = append(r.XattrLeaves, ref)
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &r, nil
}

func decodeXattrLeaf(body []byte) (*XattrLeaf, error) {
	var l XattrLeaf
	err := decodeRepeated("pft2 xattr leaf", body, func(msg []byte) error {
		e, err := decodeXattrEntry(msg)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func decodeXattrEntry(body []byte) (XattrEntry, error) {
	rd := pfwire.NewReader("pft2 xattr entry", body)
	var e XattrEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return XattrEntry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return XattrEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if e.Ino, err = rd.Uint(field); err != nil {
				return XattrEntry{}, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			if e.Name, err = rd.String(field, MaxXattrNameBytes); err != nil {
				return XattrEntry{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, MaxXattrValueBytes)
			if err != nil {
				return XattrEntry{}, err
			}
			e.Value = append([]byte(nil), b...)
		default:
			return XattrEntry{}, rd.RejectUnknown(field)
		}
	}
	return e, nil
}

func decodeCellRef(body []byte) (*CellRef, error) {
	rd := pfwire.NewReader("pft2 cell ref", body)
	var c CellRef
	digestSeen := false
	objectSeen := false
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, DigestBytes)
			if err != nil {
				return nil, err
			}
			if len(b) != DigestBytes {
				return nil, rd.Malformedf("cell digest is %d bytes (want %d)", len(b), DigestBytes)
			}
			copy(c.CellDigest[:], b)
			digestSeen = true
		case field == 2 && wt == pfwire.TypeBytes:
			if c.Object, err = decodeRefField(rd, field, "pft2 cell object ref"); err != nil {
				return nil, err
			}
			objectSeen = true
		case field == 3 && wt == pfwire.TypeVarint:
			if c.ObjectOffset, err = rd.Uint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	if !digestSeen || !objectSeen {
		return nil, rd.Malformedf("cell ref requires digest and object")
	}
	return &c, nil
}

func decodeDataPage(body []byte) (*DataPage, error) {
	rd := pfwire.NewReader("pft2 data page", body)
	var p DataPage
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return nil, err
		}
		if field < 1 || field > CellsPerPage {
			return nil, rd.RejectUnknown(field)
		}
		if wt != pfwire.TypeBytes {
			return nil, rd.Malformedf("cell field %d wire type %d", field, wt)
		}
		msg, err := rd.Bytes(field, MaxNodeBytes)
		if err != nil {
			return nil, err
		}
		cell, err := decodeCellRef(msg)
		if err != nil {
			return nil, err
		}
		p.Cells[field-1] = cell
	}
	return &p, nil
}

func decodeControlRoot(body []byte) (*ControlRoot, error) {
	rd := pfwire.NewReader("pft2 control root", body)
	var r ControlRoot
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if field == 5 {
			if err := rd.RequireRepeated(field); err != nil {
				return nil, err
			}
		} else if err := rd.Require(field); err != nil {
			return nil, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if r.Schema, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 2 && wt == pfwire.TypeBytes:
			ref, err := decodeRefField(rd, field, "pft2 control map root ref")
			if err != nil {
				return nil, err
			}
			r.MapRoot = &ref
		case field == 3 && wt == pfwire.TypeVarint:
			if r.NextCheckoutEpoch, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if r.Features, err = rd.Uint(field); err != nil {
				return nil, err
			}
		case field == 5 && wt == pfwire.TypeBytes:
			msg, err := rd.Bytes(field, MaxNodeBytes)
			if err != nil {
				return nil, err
			}
			if len(r.Counts) >= MaxControlEntryKind {
				return nil, rd.Malformedf("more than %d kind counts", MaxControlEntryKind)
			}
			count, err := decodeControlKindCount(msg)
			if err != nil {
				return nil, err
			}
			r.Counts = append(r.Counts, count)
		case field == 6 && wt == pfwire.TypeVarint:
			if r.DbTimeFloorMs, err = rd.Uint(field); err != nil {
				return nil, err
			}
		default:
			return nil, rd.RejectUnknown(field)
		}
	}
	return &r, nil
}

func decodeControlKindCount(body []byte) (ControlKindCount, error) {
	rd := pfwire.NewReader("pft2 control kind count", body)
	var c ControlKindCount
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ControlKindCount{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ControlKindCount{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeVarint:
			if c.Kind, err = rd.Uint(field); err != nil {
				return ControlKindCount{}, err
			}
		case field == 2 && wt == pfwire.TypeVarint:
			if c.Count, err = rd.Uint(field); err != nil {
				return ControlKindCount{}, err
			}
		default:
			return ControlKindCount{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodeControlEntry(body []byte) (ControlEntry, error) {
	rd := pfwire.NewReader("pft2 control entry", body)
	var e ControlEntry
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ControlEntry{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ControlEntry{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, MaxControlKeyBytes)
			if err != nil {
				return ControlEntry{}, err
			}
			e.Key = append([]byte(nil), b...)
		case field == 2 && wt == pfwire.TypeVarint:
			if e.Kind, err = rd.Uint(field); err != nil {
				return ControlEntry{}, err
			}
		case field == 3 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, MaxControlValueBytes)
			if err != nil {
				return ControlEntry{}, err
			}
			e.Value = append([]byte(nil), b...)
		default:
			return ControlEntry{}, rd.RejectUnknown(field)
		}
	}
	return e, nil
}

func decodeControlLeaf(body []byte) (*ControlLeaf, error) {
	var l ControlLeaf
	err := decodeRepeated("pft2 control leaf", body, func(msg []byte) error {
		e, err := decodeControlEntry(msg)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func decodeControlIndexChild(body []byte) (ControlIndexChild, error) {
	rd := pfwire.NewReader("pft2 control index child", body)
	var c ControlIndexChild
	for {
		field, wt, ok, err := rd.Next()
		if err != nil {
			return ControlIndexChild{}, err
		}
		if !ok {
			break
		}
		if err := rd.Require(field); err != nil {
			return ControlIndexChild{}, err
		}
		switch {
		case field == 1 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, MaxControlKeyBytes)
			if err != nil {
				return ControlIndexChild{}, err
			}
			c.FirstKey = append([]byte(nil), b...)
		case field == 2 && wt == pfwire.TypeBytes:
			b, err := rd.Bytes(field, MaxControlKeyBytes)
			if err != nil {
				return ControlIndexChild{}, err
			}
			c.LastKey = append([]byte(nil), b...)
		case field == 3 && wt == pfwire.TypeBytes:
			if c.Child, err = decodeRefField(rd, field, "pft2 control index child ref"); err != nil {
				return ControlIndexChild{}, err
			}
		case field == 4 && wt == pfwire.TypeVarint:
			if c.EntryCount, err = rd.Uint(field); err != nil {
				return ControlIndexChild{}, err
			}
		default:
			return ControlIndexChild{}, rd.RejectUnknown(field)
		}
	}
	return c, nil
}

func decodeControlIndex(body []byte) (*ControlIndex, error) {
	var x ControlIndex
	err := decodeRepeated("pft2 control index", body, func(msg []byte) error {
		c, err := decodeControlIndexChild(msg)
		if err != nil {
			return err
		}
		x.Children = append(x.Children, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &x, nil
}
