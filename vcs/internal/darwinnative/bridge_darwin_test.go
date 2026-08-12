//go:build darwin && cgo

package darwinnative

import (
	"errors"
	"strings"
	"testing"
)

func TestExactAppLaunchStatusDistinguishesTimeoutFromRejection(t *testing.T) {
	if err := exactAppLaunchStatusError(exactAppLaunchCompleted, ""); err != nil {
		t.Fatalf("completed launch = %v", err)
	}

	rejected := exactAppLaunchStatusError(exactAppLaunchRejected, "rejected")
	var timeout *AppLaunchCompletionTimeoutError
	if rejected == nil || errors.As(rejected, &timeout) ||
		!strings.Contains(rejected.Error(), "rejected") {
		t.Fatalf("rejected launch = %v", rejected)
	}

	ambiguous := exactAppLaunchStatusError(exactAppLaunchCompletionTimedOut, "")
	if !errors.As(ambiguous, &timeout) {
		t.Fatalf("timeout launch = %T %v", ambiguous, ambiguous)
	}

	wrongThread := exactAppLaunchStatusError(exactAppLaunchWrongThread, "")
	var threadError *AppLaunchWrongThreadError
	if !errors.As(wrongThread, &threadError) || errors.As(wrongThread, &timeout) {
		t.Fatalf("wrong-thread launch = %T %v", wrongThread, wrongThread)
	}
}

func TestExactAppLaunchStatusRejectsImpossibleNativeResults(t *testing.T) {
	for _, test := range []struct {
		status int
		detail string
	}{
		{exactAppLaunchCompleted, "unexpected"},
		{99, ""},
	} {
		if err := exactAppLaunchStatusError(test.status, test.detail); err == nil {
			t.Fatalf("status %d detail %q accepted", test.status, test.detail)
		}
	}
}
