//go:build linux

package fusev3

import (
	"os"
	"runtime"
	"testing"
)

func reviewR2FDs(t *testing.T) (int, []string) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		target, _ := os.Readlink("/proc/self/fd/" + e.Name())
		names = append(names, e.Name()+"->"+target)
	}
	return len(entries), names
}

// Descriptor accounting across gate binding, Close/Recovery/Prepared/Open churn,
// written-settlement schedules and fixture teardown.
func TestReviewR2DescriptorAccounting(t *testing.T) {
	before, beforeNames := reviewR2FDs(t)
	for i := 0; i < 2; i++ {
		t.Run("churn", TestReviewGateChurnStress)
		t.Run("written-settlement", TestWorkspaceCohortIncludesWrittenSettlement)
		t.Run("terminal-settlement", TestWorkspaceCohortJoinsTerminalSettlement)
		t.Run("fsync-close-reset", TestReviewR2AdmittedFsyncCloseThenColdReset)
		t.Run("setattr-refusal", TestWorkspaceSetattrRefusalKeepsNoChangeOwner)
		t.Run("closed-flush", TestWorkspaceClosedCleanFlushSucceeds)
	}
	runtime.GC()
	after, afterNames := reviewR2FDs(t)
	t.Logf("fds before=%d after=%d", before, after)
	if after != before {
		t.Errorf("descriptor delta %d\nbefore=%v\nafter=%v", after-before, beforeNames, afterNames)
	}
}
