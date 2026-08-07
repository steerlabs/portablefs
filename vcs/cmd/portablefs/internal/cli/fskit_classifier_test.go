package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyFSKitMountFailureIsConservative(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    fskitMountFailure
	}{
		{
			"resource load wins over helper text",
			"mount_pfs: Loading resource: Input/output error",
			fskitFailureResourceLoad,
		},
		{"missing helper", "mount_pfs: No such file or directory", fskitFailureModuleMissing},
		{
			// mount(8) always falls through to the legacy helper, so the
			// helper-missing text accompanies EVERY FSKit failure; a final
			// mount step error is the stronger evidence and reports FSKit
			// host state, never an enablement problem.
			"final mount step wins over helper fallback text",
			"mount: Final mount step ended with error: The file couldn’t be saved because a file with the same name already exists.\nmount: exec /Library/Filesystems/pfs.fs/Contents/Resources/mount_pfs for /x: No such file or directory",
			fskitFailureFinalMountStep,
		},
		{"helper named without missing evidence", "mount_pfs: permission denied", fskitFailureUnknown},
		{"generic errno number", "mount failed with errno 45", fskitFailureUnknown},
		{"operation unsupported", "Operation not supported", fskitFailureUnknown},
		{"unknown filesystem", "unknown filesystem", fskitFailureUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFSKitMountFailure("pfs", tc.message); got != tc.want {
				t.Fatalf("classification = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFSKitMountHintDoesNotClaimEnablement(t *testing.T) {
	resource := fskitMountHint("pfs", errors.New("mount_pfs: Loading resource: I/O error"))
	if !strings.Contains(resource.Error(), "extension was reached") ||
		strings.Contains(resource.Error(), "not enabled") {
		t.Fatalf("resource hint = %v", resource)
	}
	unknown := errors.New("Operation not supported")
	if got := fskitMountHint("pfs", unknown); got != unknown {
		t.Fatalf("generic failure was rewritten: %v", got)
	}
}
