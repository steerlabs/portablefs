package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceResourceWitnessIsAbsenceOnly(t *testing.T) {
	for _, kind := range []string{"absent", "empty file", "directory", "symlink", "invalid private state"} {
		t.Run(kind, func(t *testing.T) {
			state := t.TempDir()
			os.Chmod(state, 0700)
			dir := filepath.Join(state, "workspace")
			os.Mkdir(dir, 0700)
			marker := filepath.Join(dir, "resources.present")
			switch kind {
			case "empty file":
				os.WriteFile(marker, nil, 0600)
			case "directory":
				os.Mkdir(marker, 0700)
			case "symlink":
				os.Symlink("missing", marker)
			case "invalid private state":
				os.WriteFile(filepath.Join(dir, "desired.json"), []byte("private registry is not our decoder"), 0600)
			}
			err := requireWorkspaceResourcesAbsent(state)
			if kind == "absent" || kind == "invalid private state" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("resource witness presence accepted")
			}
		})
	}
}
