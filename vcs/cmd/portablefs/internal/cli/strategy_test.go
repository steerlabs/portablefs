package cli

import (
	"strings"
	"testing"
)

func TestResolveStrategyMatrix(t *testing.T) {
	cases := []struct {
		name     string
		explicit string
		goos     string
		want     string
		wantErr  string
	}{
		{"darwin auto", "auto", "darwin", "fskit", ""},
		{"darwin empty defaults to auto", "", "darwin", "fskit", ""},
		{"darwin explicit fskit", "fskit", "darwin", "fskit", ""},
		// Linux selection is deterministic even when fusermount is absent:
		// direct mount is a first-class mechanism and host facts are separate.
		{"linux auto", "auto", "linux", "fuse", ""},
		{"linux empty defaults to auto", "", "linux", "fuse", ""},
		{"linux explicit fuse", "fuse", "linux", "fuse", ""},
		{"linux explicit fskit", "fskit", "linux", "", "darwin"},
		{"darwin explicit fuse", "fuse", "darwin", "", "fskit"},
		{"retired webdav strategy", "webdav", "darwin", "", "unknown --strategy"},
		{"unsupported os", "auto", "windows", "", "not supported"},
		{"unknown strategy", "webdav", "linux", "", "unknown --strategy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveStrategy(tc.explicit, tc.goos)
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
