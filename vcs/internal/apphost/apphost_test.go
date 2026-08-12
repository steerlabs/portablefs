package apphost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainingAppAcceptsOnlyExactEmbeddedHelperLayout(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "PortableFS.app")
	helperDir := filepath.Join(app, "Contents", "Helpers")
	if err := os.MkdirAll(helperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(helperDir, "portablefs")
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := containingApp(helper)
	if err != nil {
		t.Fatal(err)
	}
	realApp, err := filepath.EvalSymlinks(app)
	if err != nil {
		t.Fatal(err)
	}
	if got != realApp {
		t.Fatalf("containing app = %q, want %q", got, realApp)
	}

	for _, path := range []string{
		filepath.Join(root, "portablefs"),
		filepath.Join(app, "portablefs"),
		filepath.Join(app, "Contents", "portablefs"),
	} {
		if _, err := containingApp(path); err == nil {
			t.Fatalf("accepted non-embedded path %q", path)
		}
	}
}

func TestContainingAppResolvesTheInstalledCLISymlink(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "PortableFS.app")
	helperDir := filepath.Join(app, "Contents", "Helpers")
	if err := os.MkdirAll(helperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(helperDir, "portablefs")
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "portablefs")
	if err := os.Symlink(helper, link); err != nil {
		t.Fatal(err)
	}
	got, err := containingApp(link)
	if err != nil {
		t.Fatal(err)
	}
	realApp, err := filepath.EvalSymlinks(app)
	if err != nil {
		t.Fatal(err)
	}
	if got != realApp {
		t.Fatalf("containing app = %q, want %q", got, realApp)
	}
}

func TestContainingAppRejectsAChangedContainingDirectory(t *testing.T) {
	root := t.TempDir()
	contents := filepath.Join(root, "not-an-app", "Contents", "Helpers")
	if err := os.MkdirAll(contents, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(contents, "portablefs")
	if err := os.WriteFile(helper, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := containingApp(helper)
	if err == nil || !strings.Contains(err.Error(), "app bundle") {
		t.Fatalf("non-app error = %v", err)
	}
}
