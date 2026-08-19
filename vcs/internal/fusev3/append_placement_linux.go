//go:build linux

package fusev3

// appendPlacement is the wire placement one FUSE_WRITE resolves to. Exactly one
// of append, positioned, or refuse describes a decision.
type appendPlacement struct {
	// append asks the authority to place the payload at the object's true EOF.
	// position is then meaningless and is sent as zero.
	append bool
	// position is the offset a positioned write is placed at.
	position uint64
	// offsetMatchesClientSize tells the authority that position is this mount's
	// kernel i_size, which it must confirm is the true EOF before placing bytes.
	offsetMatchesClientSize bool
	// refuse fails the write closed. The daemon cannot tell where the bytes
	// belong, so it must not choose.
	refuse bool
}

// resolveAppendPlacement decides where one FUSE_WRITE belongs.
//
// The inputs are everything stock Linux offers: whether the writing file
// description carries O_APPEND (which FUSE_WRITE.flags reports), the offset the
// kernel computed, this mount's shadow of the kernel i_size, and whether that
// shadow came from a size refresh the kernel made through this same file handle.
// The kernel sets its offset to i_size for every append -- both O_APPEND and
// per-call RWF_APPEND, which stock FUSE does not forward -- so offset == shadow
// is the only observable trace an append leaves.
//
// The last row is the delicate one. Every ordinary sequential write also lands
// at i_size, so flagging offset == shadow on its own would refuse honest
// concurrent writers whenever a peer had grown the file. What separates the two
// is that the kernel refreshes STATX_SIZE through the writing file immediately
// before an appending write (fuse_file_write_iter), so a hidden append is
// preceded by a GETATTR carrying this write's own handle, with nothing else
// touching the inode in between.
//
//	appendFlag  offset==shadow  refreshed  decision
//	true        true            any        append at the authority's EOF
//	true        false           any        positioned; only RWF_NOAPPEND
//	                                       (Linux >= 6.9) produces this
//	false       false           any        positioned; no append fits here
//	false       true            false      positioned; the offset was not
//	                                       refreshed for this handle, so no
//	                                       append this daemon answered can be
//	                                       hiding behind it
//	false       true            true       positioned, but flagged: the
//	                                       authority refuses unless the offset
//	                                       really is EOF, because a hidden
//	                                       RWF_APPEND would otherwise land short
//	any         shadow unknown  any        refused
func resolveAppendPlacement(appendFlag bool, offset, shadow uint64, shadowKnown, refreshedForHandle bool) appendPlacement {
	if !shadowKnown {
		return appendPlacement{refuse: true}
	}
	if appendFlag && offset == shadow {
		return appendPlacement{append: true}
	}
	return appendPlacement{
		position:                offset,
		offsetMatchesClientSize: !appendFlag && offset == shadow && refreshedForHandle,
	}
}
