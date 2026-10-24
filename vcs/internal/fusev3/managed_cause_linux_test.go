//go:build linux

package fusev3

import (
	"errors"
	"testing"
	"time"
)

func TestManagedTerminalRemovalCarriesOriginalCause(t *testing.T) {
	cause := errors.New("original authority validation failed")
	var got error
	m := &Mount{fatalErr: cause, withdrawalTimeout: time.Second,
		managedRemoval: func(mode string, err error) error {
			if mode != "terminal" {
				t.Error(mode)
			}
			got = err
			return nil
		}}
	_ = m.withdrawKernelState()
	if !errors.Is(got, cause) {
		t.Fatal("privileged handoff erased the cause", got)
	}
}
