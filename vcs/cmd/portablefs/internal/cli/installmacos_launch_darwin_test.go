//go:build darwin

package cli

import (
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/apphost"
)

func TestRequestExactMacOSHostForProofAllowsOnlyCompletionAmbiguity(t *testing.T) {
	original := launchExactMacOSApp
	t.Cleanup(func() { launchExactMacOSApp = original })

	ambiguous := &apphost.LaunchCompletionAmbiguousError{Cause: errors.New("callback timeout")}
	launchExactMacOSApp = func(string) error { return ambiguous }
	if err := requestExactMacOSHostForProof("/Applications/PortableFS.app"); err != nil {
		t.Fatalf("ambiguous request = %v", err)
	}

	rejected := errors.New("request rejected")
	launchExactMacOSApp = func(string) error { return rejected }
	if err := requestExactMacOSHostForProof("/Applications/PortableFS.app"); !errors.Is(err, rejected) {
		t.Fatalf("rejected request = %v", err)
	}
}
