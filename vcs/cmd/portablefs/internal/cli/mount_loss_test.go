package cli

import (
	"encoding/json"
	"runtime"
	"slices"
	"testing"
)

func TestVersionAdvertisesLiveMountLossOnlyOnLinux(t *testing.T) {
	e, stdout, stderr := testEnv(t)
	if code := e.run([]string{"version", "--json"}); code != 0 {
		t.Fatalf("version code=%d stderr=%s", code, stderr.String())
	}
	var version struct {
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &version); err != nil {
		t.Fatal(err)
	}
	if advertised := slices.Contains(version.Features, "linux-mount-loss-observation-v1"); advertised != (runtime.GOOS == "linux") {
		t.Fatalf("platform %s advertised live Linux loss feature=%t", runtime.GOOS, advertised)
	}
}
