//go:build portablefs_e2e

package accountpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EAccountRootStillUsesProductionValidation(t *testing.T) {
	if os.Getenv("PORTABLEFS_E2E_ACCOUNT_HOME_HELPER") == "1" {
		_, err := Home()
		if err != nil {
			_, _ = os.Stdout.WriteString(err.Error())
			os.Exit(2)
		}
		os.Exit(0)
	}

	realRoot := t.TempDir()
	symlinkRoot := filepath.Join(t.TempDir(), "account-link")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		root      string
		wantError string
	}{
		{name: "real absolute root", root: realRoot},
		{name: "relative root", root: "relative/account", wantError: "non-canonical home"},
		{name: "symlink root", root: symlinkRoot, wantError: "not a real directory"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestE2EAccountRootStillUsesProductionValidation$")
			command.Env = append(
				os.Environ(),
				"PORTABLEFS_E2E_ACCOUNT_HOME_HELPER=1",
				"PORTABLEFS_E2E_ACCOUNT_HOME="+test.root,
			)
			output, err := command.CombinedOutput()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("helper failed: %v: %s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), test.wantError) {
				t.Fatalf("helper error = %v, output = %q, want %q", err, output, test.wantError)
			}
		})
	}
}
