package workfs

import "testing"

// POSIX requires a symlink's st_size to equal the length of its target path.
// FSKit's kernel readlink reads exactly st_size bytes, so a zero size silently
// truncates every symlink target on macOS (FUSE never exposed this because
// readlink is an explicit op there).
func TestSymlinkSizeIsTargetLength(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if err := fs.Symlink("target.txt", "l"); err != nil {
		t.Fatal(err)
	}
	fi, err := fs.Lstat("l")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fi.Size(), int64(len("target.txt")); got != want {
		t.Fatalf("symlink size = %d, want %d", got, want)
	}
}
