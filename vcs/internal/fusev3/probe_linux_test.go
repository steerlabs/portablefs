//go:build linux

package fusev3

import "testing"

// TestKernelFUSEProbeCompletesInit is the falsifiable half of
// `portablefs mount-check --probe-mount`: a client whose mount options this
// kernel refuses, or whose negotiated interface cannot carry the coherence
// contract, cannot get past INIT here.
//
// It runs in the privileged suite, which provisions /dev/fuse and
// CAP_SYS_ADMIN. There is no skip: a run without a real FUSE device is a
// failure of the harness, not a licence to report a pass.
func TestKernelFUSEProbeCompletesInit(t *testing.T) {
	probe, err := ProbeKernelFUSE()
	if err != nil {
		t.Fatalf("throwaway FUSE probe mount: %v", err)
	}
	if probe.ProtocolMajor != portableFuseMajor || probe.ProtocolMinor < portableFuseMinor {
		t.Fatalf("probe negotiated FUSE %d.%d, want %d.%d or newer",
			probe.ProtocolMajor, probe.ProtocolMinor, portableFuseMajor, portableFuseMinor)
	}
	if probe.MaxWrite != probeMaxIO {
		t.Fatalf("probe negotiated max write %d, want %d", probe.MaxWrite, probeMaxIO)
	}
	if probe.InitFlags == 0 {
		t.Fatal("probe reported no kernel INIT capabilities")
	}
}
