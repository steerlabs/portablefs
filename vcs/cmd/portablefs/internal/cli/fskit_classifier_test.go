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
