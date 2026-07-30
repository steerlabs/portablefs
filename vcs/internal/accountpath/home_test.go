package accountpath

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestHomeIgnoresMutableHOME(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "fake"))
	t.Setenv("PORTABLEFS_E2E_ACCOUNT_HOME", filepath.Join(t.TempDir(), "e2e-fake"))
	got, err := Home()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if got != entry.HomeDir {
		t.Fatalf("Home = %q, account database = %q", got, entry.HomeDir)
	}
}
