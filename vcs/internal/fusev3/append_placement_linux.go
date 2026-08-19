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
// kernel computed, and this mount's shadow of the kernel i_size. The kernel sets
// its offset to i_size for every append -- both O_APPEND and per-call
// RWF_APPEND, which stock FUSE does not forward -- so offset == shadow is the
// only observable trace an append leaves.
//
//	appendFlag  offset==shadow  decision
//	true        true            append at the authority's EOF
//	true        false           positioned; only RWF_NOAPPEND (Linux >= 6.9)
//	                            produces a non-i_size offset on an append fd
//	false       false           positioned; an append cannot be hiding here
//	false       true            positioned, but flagged: the authority refuses
//	                            unless the offset really is EOF, because a
//	                            hidden RWF_APPEND would otherwise land short
//	any         shadow unknown  refused
func resolveAppendPlacement(appendFlag bool, offset, shadow uint64, shadowKnown bool) appendPlacement {
	if !shadowKnown {
		return appendPlacement{refuse: true}
	}
	if appendFlag && offset == shadow {
		return appendPlacement{append: true}
	}
	return appendPlacement{position: offset, offsetMatchesClientSize: !appendFlag && offset == shadow}
}
