//go:build linux

package authorityrpc

import (
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"syscall"
	"testing"
)

func TestSessionExpiryRefusalCarriesTerminalWitness(t *testing.T) {
	h, _, _ := newWriteHarness(t)
	for _, tc := range []struct {
		err      error
		terminal bool
	}{
		{volumeserver.ErrSessionExpired, true}, {fmt.Errorf("session: %w", volumeserver.ErrSessionFenced), true},
		{xfsstore.ErrStaleOpen, false}, {syscall.ESTALE, false}, {volumeserver.ErrEpochMismatch, false},
	} {
		response := h.errorResponse(1, tc.err, false)
		if response.GetErrno() != int32(syscall.ESTALE) || response.GetSessionTerminal() != tc.terminal || response.GetUncertain() {
			t.Fatalf("%v: %v", tc.err, response)
		}
	}
}
