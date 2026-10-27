//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

func TestWorkspacePublicationExclusionRetainsBothOwners(t *testing.T) {
	for _, presence := range []string{"", "resources.present", "control.sock", "ssh.sock"} {
		t.Run("presence-"+presence, func(t *testing.T) {
			root, err := os.MkdirTemp("/private/tmp", "pfs-remove-exclusion-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			directory := filepath.Join(root, "workspace")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if presence != "" {
				if err := os.WriteFile(filepath.Join(directory, presence), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			release, err := excludeAbsentWorkspace(root, macOSInstallLayout{codeIdentity: macOSInstallDeveloperIDRelease})
			if presence != "" {
				if err == nil {
					release()
					t.Fatal("unproven workspace absence accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"service.lock", "owner.lock"} {
				guard, lockErr := mountlifecycle.AcquireNamedExclusive(directory, name)
				if presence == "" {
					if lockErr == nil {
						guard.Close()
						t.Fatalf("%s was not retained", name)
					}
				} else {
					if lockErr != nil {
						t.Fatalf("failed proof leaked %s: %v", name, lockErr)
					}
					guard.Close()
				}
			}
			if presence == "" {
				release()
			}
		})
	}
}

func TestMacOSAppRemovalPreservesDataAndRefusesReplacement(t *testing.T) {
	for _, cut := range []string{"clean", "foreign-link", "changed-link", "changed-app", "changed-parent"} {
		t.Run(cut, func(t *testing.T) {
			root, err := os.MkdirTemp("/private/tmp", "pfs-remove-owned-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			app := filepath.Join(root, "Applications", "PortableFS.app")
			link := filepath.Join(root, "bin", "portablefs")
			data := filepath.Join(root, "state", "workspace", "data.ext4")
			for _, path := range []string{filepath.Join(app, "Contents", "Helpers"), filepath.Dir(link), filepath.Dir(data)} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{filepath.Join(app, "Contents", "Helpers", "portablefs"), data} {
				if err := os.WriteFile(path, []byte("preserve-user-content"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(app, "Contents", "Helpers", "portablefs")
			if cut == "foreign-link" {
				target = data
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			removal, err := prepareMacOSAppRemoval(app, link)
			if cut == "foreign-link" {
				if err == nil {
					t.Fatal("foreign CLI link accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				switch cut {
				case "changed-link":
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(data, link); err != nil {
						t.Fatal(err)
					}
				case "changed-app":
					if err := os.Rename(app, app+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(app, 0o700); err != nil {
						t.Fatal(err)
					}
				case "changed-parent":
					parent := filepath.Dir(link)
					if err := os.Rename(parent, parent+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(parent, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				err = removal.commit()
				if (err == nil) != (cut == "clean") {
					t.Fatalf("commit %s: %v", cut, err)
				}
			}
			if got, err := os.ReadFile(data); err != nil || string(got) != "preserve-user-content" {
				t.Fatalf("workspace data changed: %q %v", got, err)
			}
			_, err = os.Lstat(app)
			if cut == "clean" {
				if !os.IsNotExist(err) {
					t.Fatalf("app remains: %v", err)
				}
				if _, err := os.Lstat(link); !os.IsNotExist(err) {
					t.Fatalf("link remains: %v", err)
				}
			} else if err != nil {
				t.Fatalf("replacement or original app was removed: %v", err)
			}
		})
	}
}

func TestRemovalAbsenceProofPreservesRecreatedProgramNames(t *testing.T) {
	for _, change := range []string{"app", "link", "parent"} {
		t.Run(change, func(t *testing.T) {
			root, err := os.MkdirTemp("/private/tmp", "pfs-remove-final-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			app := filepath.Join(root, "Applications", "PortableFS.app")
			link := filepath.Join(root, "bin", "portablefs")
			for _, path := range []string{app, filepath.Dir(link)} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(filepath.Join(app, "Contents", "Helpers", "portablefs"), link); err != nil {
				t.Fatal(err)
			}
			removal, err := prepareMacOSAppRemoval(app, link)
			if err != nil {
				t.Fatal(err)
			}
			if err := removal.commit(); err != nil {
				t.Fatal(err)
			}
			replacement := link
			switch change {
			case "app":
				replacement = app
			case "parent":
				replacement = filepath.Dir(app)
				if err := os.Rename(replacement, replacement+".original"); err != nil {
					t.Fatal(err)
				}
			}
			if change == "link" {
				if err := os.WriteFile(replacement, []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(replacement, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := removal.requireAbsent(); err == nil {
				t.Fatal("changed program namespace authorized completion")
			}
			if _, err := os.Lstat(replacement); err != nil {
				t.Fatalf("replacement was removed: %v", err)
			}
		})
	}
}
