package cli

import (
	"fmt"
	"strings"
	"testing"
)

func probeFor(goos string, fusermount bool) strategyProbe {
	return strategyProbe{
		goos: goos,
		lookPath: func(name string) (string, error) {
			if fusermount && (name == "fusermount3" || name == "fusermount") {
				return "/usr/bin/" + name, nil
			}
			return "", fmt.Errorf("%s not found", name)
		},
	}
}

func TestResolveStrategyMatrix(t *testing.T) {
	cases := []struct {
		name       string
		explicit   string
		goos       string
		fusermount bool
		want       string
		wantErr    string
	}{
		// One transport per platform, no fallbacks: darwin is always FSKit,
		// linux is FUSE (with a specific failure when the helper is absent).
		{"darwin auto", "auto", "darwin", false, "fskit", ""},
		{"darwin empty defaults to auto", "", "darwin", false, "fskit", ""},
		{"darwin explicit fskit", "fskit", "darwin", false, "fskit", ""},
		{"linux auto with helper", "auto", "linux", true, "fuse", ""},
		{"linux auto without helper", "auto", "linux", false, "", "fusermount"},
		{"linux empty defaults to auto", "", "linux", true, "fuse", ""},
		{"linux explicit fuse with helper", "fuse", "linux", true, "fuse", ""},
		{"linux explicit fuse without helper", "fuse", "linux", false, "", "fusermount"},
		{"linux explicit fskit", "fskit", "linux", true, "", "darwin"},
		{"darwin explicit fuse", "fuse", "darwin", false, "", "fskit"},
		{"retired webdav strategy", "webdav", "darwin", false, "", "unknown --strategy"},
		{"unsupported os", "auto", "windows", false, "", "not supported"},
		{"unknown strategy", "webdav", "linux", true, "", "unknown --strategy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveStrategy(tc.explicit, probeFor(tc.goos, tc.fusermount))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want mention of %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("strategy = %q, want %q", got, tc.want)
			}
		})
	}
}
