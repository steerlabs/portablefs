package workspaceimage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func record(raw []byte) Record {
	h := sha256.Sum256(raw)
	return Record{SHA256: hex.EncodeToString(h[:]), Size: uint64(len(raw))}
}
func fixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	inputs := []byte("inputs")
	r := Release{Version: "0.5.0", Commit: strings.Repeat("a", 40), Digest: record(inputs).SHA256, Major: 8}
	m := Manifest{Format: 8, Release: r, Files: map[string]Record{}}
	for _, name := range required {
		raw := []byte(name)
		switch name {
		case "image-inputs.json":
			raw = inputs
		case "release.json":
			raw, _ = json.Marshal(r)
		case "source-manifest.json":
			raw = []byte(`{"format":8,"commit":"` + r.Commit + `","archive":{"sha256":"` + strings.Repeat("b", 64) + `","size":123}}`)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		m.Files[name] = record(raw)
	}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, record(raw).SHA256
}
func TestSealedImageRefusesCorruptionAndSubstitution(t *testing.T) {
	for _, test := range []string{"valid", "kernel corruption", "manifest substitution", "wrong commit", "wrong version", "extra member", "symlink"} {
		t.Run(test, func(t *testing.T) {
			dir, pin := fixture(t)
			commit := strings.Repeat("a", 40)
			version := "0.5.0"
			switch test {
			case "kernel corruption":
				os.WriteFile(filepath.Join(dir, "kernel"), []byte("corrupt"), 0600)
			case "manifest substitution":
				pin = strings.Repeat("b", 64)
			case "wrong commit":
				commit = strings.Repeat("c", 40)
			case "wrong version":
				version = "0.5.1"
			case "extra member":
				os.WriteFile(filepath.Join(dir, "extra"), []byte("unexpected"), 0600)
			case "symlink":
				os.Rename(filepath.Join(dir, "kernel"), filepath.Join(dir, "target"))
				os.Symlink("target", filepath.Join(dir, "kernel"))
			}
			size, err := Verify(dir, pin, commit, version)
			if test == "valid" {
				if err != nil || size == 0 {
					t.Fatalf("valid: %d %v", size, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "Workspace image failed verification") {
				t.Fatalf("unsafe image accepted: %v", err)
			}
		})
	}
}
