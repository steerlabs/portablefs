//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsLooseUnixPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"currentProfile":"default","profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("loadConfig loose-directory error = %v", err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("loadConfig loose-file error = %v", err)
	}
}

func TestSaveConfigRefusesUnsafeUnixPermissionsWithoutRepair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	cfg := &Config{CurrentProfile: "default", Profiles: map[string]Profile{}}
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("saveConfig accepted an unsafe config directory")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("refused save published a config file: %v", err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe config directory was silently repaired to %o", dirInfo.Mode().Perm())
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("do-not-replace"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("saveConfig accepted an unsafe existing config file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("unsafe config file was silently repaired to %o", info.Mode().Perm())
	}
}
