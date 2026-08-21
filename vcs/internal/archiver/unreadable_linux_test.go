//go:build linux

package archiver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"golang.org/x/sys/unix"
)

// A volume may legitimately contain an inode whose mode denies its own owner: a
// mode-0000 file, a directory with no owner search bit. Those trees have to be
// archivable, so the archiver unit is granted CAP_DAC_READ_SEARCH - read and
// traverse, nothing else - in deploy/systemd/portablefs-archiver@.service.
//
// What this case proves and what it does not. The capability grant is
// configuration, and this test cannot exercise it: no Go test can raise its own
// ambient capability set. What it does prove is the other half, which is the
// half that lives in this repository - that once the reads are permitted the
// archiver treats such inodes as ordinary ones, walking through them and
// sealing a manifest that describes them at full fidelity, mode bits included.
// It runs only where discretionary access is already satisfied: as root, which
// is how the Linux suites run in the repository's containers and is the same
// access CAP_DAC_READ_SEARCH grants in production, or as an identity that
// happens to hold the capability. It skips otherwise rather than pretending.
//
// The complementary negative - that an identity holding neither capability nor
// permission fails loudly instead of sealing an incomplete manifest - is
// TestArchiveRefusesAnUnreadableFile, which skips as root for the same reason
// this one requires it.
func TestArchiveSealsInodesThatDenyTheirOwner(t *testing.T) {
	if os.Geteuid() != 0 && !holdsDACReadSearch(t) {
		t.Skip("this identity can neither bypass nor override discretionary access; " +
			"in production CAP_DAC_READ_SEARCH is what makes these modes readable")
	}
	root := t.TempDir()
	payload := []byte("bytes behind a mode that denies its owner")

	write := func(relative string, mode os.FileMode, content []byte) {
		t.Helper()
		full := filepath.Join(root, relative)
		if err := os.WriteFile(full, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatalf("chmod %s: %v", relative, err)
		}
	}

	// A file its owner may not open at all, at the top of the tree.
	write("locked.bin", 0o000, payload)
	// A directory its owner may not search, holding a file its owner may not
	// read. Reaching the inner file at all costs CAP_DAC_READ_SEARCH twice: once
	// to traverse the directory, once to open the file.
	if err := os.Mkdir(filepath.Join(root, "sealed"), 0o700); err != nil {
		t.Fatalf("mkdir sealed: %v", err)
	}
	write(filepath.Join("sealed", "inner.bin"), 0o000, payload)
	if err := os.Symlink("inner.bin", filepath.Join(root, "sealed", "alias")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// A directory that can be searched but not listed, which refuses a readdir
	// rather than a lookup.
	if err := os.Mkdir(filepath.Join(root, "opaque"), 0o700); err != nil {
		t.Fatalf("mkdir opaque: %v", err)
	}
	write(filepath.Join("opaque", "hidden.txt"), 0o400, []byte("listed only with the capability"))
	// The directory modes land last, exactly as a restore applies them, so that
	// building the tree never depends on the capability.
	if err := os.Chmod(filepath.Join(root, "opaque"), 0o100); err != nil {
		t.Fatalf("chmod opaque: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "sealed"), 0o000); err != nil {
		t.Fatalf("chmod sealed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "sealed"), 0o700)
		_ = os.Chmod(filepath.Join(root, "opaque"), 0o700)
	})

	client, store := newTestStore(t)
	resultDir := t.TempDir()
	if err := Run(context.Background(), Options{
		LaunchConfigPath: writeLaunchConfig(t, t.TempDir(), testLaunchConfig()),
		VolumeRoot:       root,
		ResultDir:        resultDir,
		Client:           client,
		Now:              func() time.Time { return time.Unix(1_700_000_100, 0) },
		Logf:             t.Logf,
	}); err != nil {
		t.Fatalf("archive a tree whose modes deny its owner: %v", err)
	}
	sealed, err := ReadSealed(sealedPath(resultDir))
	if err != nil {
		t.Fatalf("read seal: %v", err)
	}
	raw, ok := store.object(sealed.Manifest.Key)
	if !ok {
		t.Fatal("the manifest is not in the store")
	}
	manifest, err := archive.Decode(raw)
	if err != nil {
		t.Fatalf("decode the sealed manifest: %v", err)
	}

	byPath := map[string]*archive.Entry{}
	for index := range manifest.Entries {
		components, err := manifest.Path(uint32(index))
		if err != nil {
			t.Fatalf("path of entry %d: %v", index, err)
		}
		parts := make([]string, 0, len(components))
		for _, component := range components {
			parts = append(parts, string(component))
		}
		byPath[filepath.Join(parts...)] = &manifest.Entries[index]
	}

	for _, want := range []struct {
		path string
		kind archive.EntryType
		mode uint32
		size uint64
	}{
		{"locked.bin", archive.TypeRegular, 0o000, uint64(len(payload))},
		{"sealed", archive.TypeDirectory, 0o000, 0},
		{"sealed/inner.bin", archive.TypeRegular, 0o000, uint64(len(payload))},
		{"sealed/alias", archive.TypeSymlink, 0, uint64(len("inner.bin"))},
		{"opaque", archive.TypeDirectory, 0o100, 0},
		{"opaque/hidden.txt", archive.TypeRegular, 0o400, uint64(len("listed only with the capability"))},
	} {
		entry, present := byPath[want.path]
		if !present {
			t.Fatalf("%q is missing from the sealed manifest; the archive omitted an inode it could not read", want.path)
		}
		if entry.Type != want.kind {
			t.Errorf("%q is archived as %s, want %s", want.path, entry.Type, want.kind)
		}
		if want.kind != archive.TypeSymlink && entry.Mode&0o7777 != want.mode {
			t.Errorf("%q is archived with mode %#o, want %#o", want.path, entry.Mode&0o7777, want.mode)
		}
		if entry.Size != want.size {
			t.Errorf("%q is archived as %d bytes, want %d", want.path, entry.Size, want.size)
		}
	}
	// Content, not just names: an unreadable file's bytes have to be in the pack
	// or the manifest would be describing an inode it never read.
	locked := byPath["locked.bin"]
	inner := byPath["sealed/inner.bin"]
	if len(locked.Chunks) == 0 || locked.ContentDigest != inner.ContentDigest {
		t.Fatal("the two unreadable files hold identical bytes and must seal identical content digests")
	}
}

// holdsDACReadSearch reports whether this process has the capability in its
// effective set, which is the production posture the archiver unit establishes.
func holdsDACReadSearch(t *testing.T) bool {
	t.Helper()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return false
	}
	const index, bit = unix.CAP_DAC_READ_SEARCH / 32, unix.CAP_DAC_READ_SEARCH % 32
	return data[index].Effective&(1<<bit) != 0
}
