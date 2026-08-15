//go:build linux

package mountv3

import "testing"

func TestPreKernelMountAbsenceObserverRequiresAttemptIdentity(t *testing.T) {
	for _, test := range []struct {
		path string
		id   string
	}{
		{"", "mnt_AAAAAAAAAAAAAAAAAAAAAA"},
		{"/mnt/portablefs", ""},
		{"/mnt/portablefs", "portablefs"},
	} {
		if observer, err := PreKernelMountAbsenceObserver(test.path, test.id); err == nil || observer != nil {
			t.Fatalf("observer(%q, %q) = (%v, %v), want refusal", test.path, test.id, observer, err)
		}
	}
}
