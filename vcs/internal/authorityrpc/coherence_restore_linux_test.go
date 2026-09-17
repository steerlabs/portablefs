//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func TestCoherenceActiveRestoreRefusesKernelDataCache(t *testing.T) {
	// Active() needs no hydrated entry: the health contract covers the volume,
	// including newly created and already hydrated files.
	h := &VolumeHandler{Restore: &restoremode.Mode{}}
	for _, writeIntent := range []bool{false, true} {
		admitted, err := h.coherenceAdmitOpen(volumeserver.SessionID{}, xfsstore.Capability{}, [16]byte{1}, true, writeIntent)
		if err != nil || admitted {
			t.Fatalf("restore cache admission(write=%v) = %v, %v", writeIntent, admitted, err)
		}
	}
}
