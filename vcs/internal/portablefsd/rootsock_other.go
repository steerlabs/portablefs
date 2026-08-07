//go:build !darwin

package portablefsd

import "errors"

// The mount-root handoff exists for the sandboxed macOS FSKit extension; no
// other frontend needs it. The listener still runs (the socket is part of the
// daemon's canonical directory on every platform), but every request is
// refused rather than pretending another platform's mount table semantics
// were verified.
func openVerifiedMountRoot(string, string) (int, error) {
	return -1, errors.New("mount-root handoff is a macOS FSKit mechanism")
}

func closeMountRootFD(int) {}
func duplicateMountRootFD(int) (int, error) {
	return -1, errors.New("mount-root duplication is a macOS FSKit mechanism")
}
func mountRootRights(int) []byte { return nil }

func actuateRepair(int, repairActuationPlan) (byte, error) {
	return 0, errors.New("repair actuation is a macOS FSKit mechanism")
}
