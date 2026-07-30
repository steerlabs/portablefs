package accountsession

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSessionGuardExcludesMutation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	shared, err := AcquireShared(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if exclusive, err := AcquireExclusive(stateDir); err == nil {
		_ = exclusive.Close()
		t.Fatal("exclusive mutation guard acquired during a live shared session")
	}
	info, err := os.Stat(Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %04o", info.Mode().Perm())
	}
}
