//go:build darwin

package cli

import (
	"strings"
	"testing"
)

func TestMacOSDaemonStopRefusesBeforeControlMutation(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := cmdDaemon(e, []string{"stop"}); rc != 1 {
		t.Fatalf("daemon stop rc = %d, stderr=%q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "host-owned, zero-mount update transaction") {
		t.Fatalf("daemon stop diagnostic = %q", stderr.String())
	}
}
