package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Compile the injected transport constructor only in the regression subprocess.
// The real HTTP handlers and readonlyfs resource owners run without a public
// test hook in the shipping library.
func TestHTTPAbandonedCloseRetiresSession(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	overlay := map[string]map[string]string{"Replace": {
		filepath.Join(cwd, "cleanup_regression_test.go"):              filepath.Join(cwd, "testdata/cleanup/http_test.go"),
		filepath.Join(cwd, "../../readonlyfs/cleanup_constructor.go"): filepath.Join(cwd, "testdata/cleanup/constructor.go"),
	}}
	data, err := json.Marshal(overlay)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "go", "test", "-race", "-count=1", "-timeout=60s", "-overlay", path, "-run", "^TestReviewHTTPAbandonedCloseRetainsSessionOwner$", ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("HTTP cleanup regression: %v\n%s", err, output)
	}
}
