package fuse

import "encoding/binary"

// EncodePFSObjectState emits the fixed Linux private wire layout without
// depending on the host's native fuse.Attr layout. Darwin's Attr contains
// additional fields, while this protocol remains the Linux 88-byte fuse_attr.
func EncodePFSObjectState(out []byte, state *PFSObjectState) bool {
	if len(out) < PFSObjectStateSize || state == nil {
		return false
	}
	binary.LittleEndian.PutUint64(out[0:8], state.Nodeid)
	binary.LittleEndian.PutUint64(out[8:16], state.ObjectVersion)
	copy(out[16:32], state.StableIdentity[:])
	copy(out[32:120], state.Attr[:])
	binary.LittleEndian.PutUint32(out[120:124], state.Roles)
	binary.LittleEndian.PutUint32(out[124:128], state.InodeFlags)
	binary.LittleEndian.PutUint64(out[128:136], uint64(state.BirthTimeNS))
	binary.LittleEndian.PutUint32(out[136:140], state.PFSClass)
	binary.LittleEndian.PutUint32(out[140:144], state.RecordFlags)
	return true
}

// EncodePFSCacheStamp emits the stamped-read extension used by LOOKUP,
// GETATTR, and every READDIRPLUS record.
func EncodePFSCacheStamp(out []byte, stamp *PFSCacheStamp) bool {
	if len(out) < PFSCacheStampSize || stamp == nil {
		return false
	}
	binary.LittleEndian.PutUint64(out[0:8], stamp.SnapshotSequence)
	binary.LittleEndian.PutUint64(out[8:16], stamp.ObjectVersion)
	binary.LittleEndian.PutUint64(out[16:24], uint64(stamp.BirthTimeNS))
	binary.LittleEndian.PutUint32(out[24:28], stamp.InodeFlags)
	binary.LittleEndian.PutUint32(out[28:32], stamp.Reserved)
	return true
}
