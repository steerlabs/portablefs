//go:build linux

package fusev3

// appendPlacement is the wire placement one FUSE_WRITE resolves to.
type appendPlacement struct {
	// append asks the authority to place the payload at the object's true EOF.
	// position is then meaningless and is sent as zero.
	append bool
	// position is the offset a positioned write is placed at.
	position uint64
}

// resolveAppendPlacement decides where one FUSE_WRITE belongs.
//
// Stock FUSE_WRITE reports the writing description's O_APPEND state in flags,
// and that is the whole decision: an append is placed by the authority at the
// object's true EOF, and every other write is placed exactly where the kernel
// asked. The kernel's own offset is never reinterpreted, and never consulted for
// an append -- for a shared volume it is derived from an i_size that is only an
// advisory shadow of another machine's EOF, so trusting it would silently
// overwrite records another mount had already appended.
//
// Two per-call flags are outside this decision because stock Linux does not
// forward them, and both are documented deviations rather than inferences:
// RWF_APPEND on a description without O_APPEND is placed at the offset the
// kernel derived, and RWF_NOAPPEND on a description with O_APPEND is placed at
// EOF like any other append.
func resolveAppendPlacement(appendFlag bool, offset uint64) appendPlacement {
	if appendFlag {
		return appendPlacement{append: true}
	}
	return appendPlacement{position: offset}
}
