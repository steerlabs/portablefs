//go:build darwin && cgo

package hostctl

/*
#cgo LDFLAGS: -lbsm -lproc
#include <stdint.h>
#include <stdlib.h>

int portablefs_capture_socket_peer_witness(
	int fd,
	uint32_t token_out[8],
	int *pid_out,
	int *pid_version_out,
	uint32_t *euid_out,
	char **path_out
);
int portablefs_process_witness_matches(
	const uint32_t token[8],
	int pid,
	int pid_version,
	const char *expected_path,
	char **observed_path_out
);
*/
import "C"

import (
	"fmt"
	"path/filepath"
	"unsafe"
)

// ProcessWitness binds one process execution, not merely a reusable pid. The
// opaque audit token carries Darwin's pidversion; proc_pidpath_audittoken then
// re-proves that same execution and its executable path at each use.
type ProcessWitness struct {
	PID            int
	PIDVersion     int
	ExecutablePath string
	auditToken     [8]uint32
}

func captureSocketPeerProcessWitness(fd int) (ProcessWitness, uint32, error) {
	var token [8]C.uint32_t
	var pid C.int
	var pidVersion C.int
	var euid C.uint32_t
	var path *C.char
	status := C.portablefs_capture_socket_peer_witness(
		C.int(fd),
		&token[0],
		&pid,
		&pidVersion,
		&euid,
		&path,
	)
	if path != nil {
		defer C.free(unsafe.Pointer(path))
	}
	if status != 0 {
		return ProcessWitness{}, 0, fmt.Errorf("capture audit-token host process witness: errno %d", int(status))
	}
	witness := ProcessWitness{
		PID:            int(pid),
		PIDVersion:     int(pidVersion),
		ExecutablePath: C.GoString(path),
	}
	for index := range witness.auditToken {
		witness.auditToken[index] = uint32(token[index])
	}
	if err := witness.validate(); err != nil {
		return ProcessWitness{}, 0, err
	}
	return witness, uint32(euid), nil
}

func (witness ProcessWitness) validate() error {
	if witness.PID <= 0 || witness.PIDVersion <= 0 ||
		!filepath.IsAbs(witness.ExecutablePath) ||
		filepath.Clean(witness.ExecutablePath) != witness.ExecutablePath {
		return fmt.Errorf("host process witness is incomplete")
	}
	return nil
}

// RequireCurrentExecutable proves that the exact audit-token process execution
// captured from the authenticated update socket is still live at expectedPath.
// A departed process or pid reuse is a mismatch, never a new authority.
func (witness ProcessWitness) RequireCurrentExecutable(expectedPath string) error {
	if err := witness.validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(expectedPath) || filepath.Clean(expectedPath) != expectedPath {
		return fmt.Errorf("expected host executable path is not absolute and clean")
	}
	cExpected := C.CString(expectedPath)
	defer C.free(unsafe.Pointer(cExpected))
	var token [8]C.uint32_t
	for index := range witness.auditToken {
		token[index] = C.uint32_t(witness.auditToken[index])
	}
	var observed *C.char
	status := C.portablefs_process_witness_matches(
		&token[0],
		C.int(witness.PID),
		C.int(witness.PIDVersion),
		cExpected,
		&observed,
	)
	if observed != nil {
		defer C.free(unsafe.Pointer(observed))
	}
	switch {
	case status < 0:
		return fmt.Errorf("re-prove audit-token host process witness: errno %d", -int(status))
	case status == 0:
		observedPath := "<departed>"
		if observed != nil {
			observedPath = C.GoString(observed)
		}
		return fmt.Errorf(
			"prepared host process witness pid %d/%d path %s does not match %s",
			witness.PID,
			witness.PIDVersion,
			observedPath,
			expectedPath,
		)
	case status == 1:
		return nil
	default:
		return fmt.Errorf("re-prove audit-token host process witness: invalid native status %d", int(status))
	}
}
