//go:build linux

package xfsstore

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The restrictive-mode hydration suite.
//
// A restore materializes the whole namespace at its archived modes and then
// fills the bytes in behind it, so RestoreFiles routinely has to write into a
// file that is 0444 or 0000 and to walk a directory that is 0000. None of that
// is possible for the identity that owns the volume without moving the mode:
// ownership is not access, and no cell component holds CAP_DAC_OVERRIDE.
//
// The whole of that mode movement lives in the binding walk, which runs before
// the volume server accepts a session. Once ResolveRestoreFiles has returned,
// every hydration write goes through a descriptor that was opened for writing
// while the mode was out of the way, and no mode is ever touched again - which
// is what these cases are here to pin.
//
// Root bypasses discretionary access entirely, so as root these cases would
// pass without the code under test existing. The Linux suites run as root in a
// container, so each case re-executes this binary as an unprivileged uid and
// reports that child's result; the child is where the assertions mean anything.

const (
	unprivilegedUID = 65534
	unprivilegedGID = 65534
)

func runsUnprivileged() bool { return os.Geteuid() != 0 }

// rerunUnprivileged re-executes this test binary as an unprivileged uid running
// exactly the named case. The binary is copied somewhere world-executable first
// - `go test` builds it under a root-only temporary directory - and the child
// gets a TMPDIR it owns so t.TempDir() works there.
func rerunUnprivileged(t *testing.T, name string) {
	t.Helper()
	stage, err := os.MkdirTemp("", "portablefs-unprivileged-")
	if err != nil {
		t.Fatalf("stage directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stage) })
	if err := os.Chmod(stage, 0o755); err != nil {
		t.Fatalf("chmod stage: %v", err)
	}
	binary := filepath.Join(stage, "case.test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatalf("open the test binary: %v", err)
	}
	destination, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		_ = source.Close()
		t.Fatalf("stage the test binary: %v", err)
	}
	_, copyErr := io.Copy(destination, source)
	_ = source.Close()
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("stage the test binary: %v / %v", copyErr, closeErr)
	}
	work := filepath.Join(stage, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatalf("work directory: %v", err)
	}
	if err := os.Chown(work, unprivilegedUID, unprivilegedGID); err != nil {
		t.Fatalf("chown work directory: %v", err)
	}
	command := exec.Command(binary, "-test.run", "^"+name+"$", "-test.v")
	command.Env = append(os.Environ(), "TMPDIR="+work, "HOME="+work)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: unprivilegedUID, Gid: unprivilegedGID},
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s as uid %d failed: %v\n%s", name, unprivilegedUID, err, output)
	}
	if !strings.Contains(string(output), "PASS") {
		t.Fatalf("%s as uid %d did not report PASS:\n%s", name, unprivilegedUID, output)
	}
	t.Logf("%s ran as uid %d:\n%s", name, unprivilegedUID, output)
}

// restoredVolume builds the shape a restore leaves behind: a file whose
// archived mode denies its owner every access, a file that is readable but not
// writable, and a directory that denies its owner both, holding a child that
// was created before the mode landed. The bindings map names the two regular
// files, which is exactly what the hydrator's binding table names.
type restoredVolume struct {
	volume     *Volume
	path       string
	identities map[[16]byte]uint32
	modes      map[uint32]uint32
	names      map[uint32]string
	// caps are the volume's own O_PATH references. They are how this case reads
	// the mode of a file behind a 0000 directory at all: a descriptor addresses
	// the inode directly, where a path would have to be walked through a
	// directory that denies the walk.
	caps   map[uint32]Capability
	sealed Capability
}

const (
	entryReadOnly uint32 = 1
	entryUnopened uint32 = 2
	sealedName           = "sealed"
	readOnlyName         = "read-only"
	unopenedName         = "deep"
)

func buildRestoredVolume(t *testing.T) restoredVolume {
	t.Helper()
	path := filepath.Clean(t.TempDir())
	volume, err := open(path, false, 0, nil)
	if err != nil {
		t.Fatalf("open volume: %v", err)
	}
	t.Cleanup(func() {
		if err := volume.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		// The 0000 directory would otherwise defeat the temporary directory's
		// own cleanup.
		_ = os.Chmod(filepath.Join(path, sealedName), 0o700)
	})
	root, err := volume.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	readOnly, _, err := volume.Create(root, readOnlyName, 0o444, true)
	if err != nil {
		t.Fatalf("create %s: %v", readOnlyName, err)
	}
	sealed, _, err := volume.Mkdir(root, sealedName, 0o700)
	if err != nil {
		t.Fatalf("mkdir %s: %v", sealedName, err)
	}
	unopened, _, err := volume.Create(sealed, unopenedName, 0o000, true)
	if err != nil {
		t.Fatalf("create %s: %v", unopenedName, err)
	}
	// The directory's archived mode lands only after its child exists, which is
	// the ordering the hydrator's materialization guarantees.
	if err := volume.Chmod(sealed, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", sealedName, err)
	}
	readOnlyIdentity, err := volume.Identity(readOnly)
	if err != nil {
		t.Fatalf("identity %s: %v", readOnlyName, err)
	}
	unopenedIdentity, err := volume.Identity(unopened)
	if err != nil {
		t.Fatalf("identity %s: %v", unopenedName, err)
	}
	return restoredVolume{
		volume: volume,
		path:   path,
		identities: map[[16]byte]uint32{
			readOnlyIdentity: entryReadOnly,
			unopenedIdentity: entryUnopened,
		},
		modes: map[uint32]uint32{entryReadOnly: 0o444, entryUnopened: 0o000},
		names: map[uint32]string{
			entryReadOnly: readOnlyName,
			entryUnopened: filepath.Join(sealedName, unopenedName),
		},
		caps:   map[uint32]Capability{entryReadOnly: readOnly, entryUnopened: unopened},
		sealed: sealed,
	}
}

func (r restoredVolume) modeOf(t *testing.T, display string, id Capability) uint32 {
	t.Helper()
	attr, err := r.volume.Getattr(id)
	if err != nil {
		t.Fatalf("read the mode of %q: %v", display, err)
	}
	bits := uint32(attr.Mode.Perm())
	if attr.Mode&os.ModeSticky != 0 {
		bits |= unix.S_ISVTX
	}
	return bits
}

// TestRestoreHydratesInodesTheirOwnerMayNotOpen is the whole point of binding
// descriptors before serving: hydration must land in a file whose archived mode
// forbids the write, through a descriptor the walk obtained, and must leave
// every mode in the tree exactly as it found it.
func TestRestoreHydratesInodesTheirOwnerMayNotOpen(t *testing.T) {
	if !runsUnprivileged() {
		rerunUnprivileged(t, "TestRestoreHydratesInodesTheirOwnerMayNotOpen")
		return
	}
	restored := buildRestoredVolume(t)

	// The premise. If this identity could open the 0444 file for writing, or
	// read the 0000 directory, there would be nothing to step around and the
	// rest of this case would prove nothing.
	if fd, err := unix.Open(filepath.Join(restored.path, readOnlyName), unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Close(fd)
		t.Fatalf("%q could be opened for writing; this identity is not constrained by the mode", readOnlyName)
	} else if !errors.Is(err, unix.EACCES) {
		t.Fatalf("open %q for writing = %v, want EACCES", readOnlyName, err)
	}
	if fd, err := unix.Open(filepath.Join(restored.path, sealedName), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Close(fd)
		t.Fatalf("%q could be opened for reading; this identity is not constrained by the mode", sealedName)
	} else if !errors.Is(err, unix.EACCES) {
		t.Fatalf("open %q for reading = %v, want EACCES", sealedName, err)
	}

	// ResolveRestoreFiles has to walk into the 0000 directory to bind the file
	// inside it, and has to leave that directory's mode exactly as it was.
	files, err := restored.volume.ResolveRestoreFiles(restored.identities, 64)
	if err != nil {
		t.Fatalf("resolve restore bindings through a 0000 directory: %v", err)
	}
	defer files.Close()
	if len(files.files) != len(restored.identities) {
		t.Fatalf("the walk bound %d of %d restored files", len(files.files), len(restored.identities))
	}
	if mode := restored.modeOf(t, sealedName, restored.sealed); mode != 0o000 {
		t.Fatalf("the binding walk left %q at mode %#o, not the %#o it found", sealedName, mode, 0o000)
	}
	for entry, want := range restored.modes {
		if mode := restored.modeOf(t, restored.names[entry], restored.caps[entry]); mode != want {
			t.Fatalf("the binding walk left %q at mode %#o, not the %#o it found",
				restored.names[entry], mode, want)
		}
	}

	payload := bytes.Repeat([]byte("hydrated."), 64)
	for entry, want := range restored.modes {
		name := restored.names[entry]
		if err := files.PWrite(entry, 0, payload); err != nil {
			t.Fatalf("PWrite into %q (mode %#o): %v", name, want, err)
		}
		if err := files.Fdatasync(entry); err != nil {
			t.Fatalf("Fdatasync %q (mode %#o): %v", name, want, err)
		}
		if err := files.RestoreMtime(entry); err != nil {
			t.Fatalf("RestoreMtime %q (mode %#o): %v", name, want, err)
		}
		if mode := restored.modeOf(t, name, restored.caps[entry]); mode != want {
			t.Fatalf("after a hydration write %q is mode %#o, not the %#o it started at", name, mode, want)
		}
		size, err := files.LogicalSize(entry)
		if err != nil || size != int64(len(payload)) {
			t.Fatalf("LogicalSize %q = %d, %v; want %d", name, size, err, len(payload))
		}
	}

	// The bytes actually landed. Reading them back costs read permission the
	// files do not grant, so the modes are widened here - after every mode
	// assertion above has already been made.
	for entry := range restored.modes {
		name := restored.names[entry]
		if err := os.Chmod(filepath.Join(restored.path, sealedName), 0o700); err != nil {
			t.Fatalf("widen %q to read the result: %v", sealedName, err)
		}
		if err := os.Chmod(filepath.Join(restored.path, name), 0o400); err != nil {
			t.Fatalf("widen %q to read the result: %v", name, err)
		}
		got, err := os.ReadFile(filepath.Join(restored.path, name))
		if err != nil {
			t.Fatalf("read %q: %v", name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%q holds %d bytes that do not match the hydration write", name, len(got))
		}
	}
}

// TestAUserChmodDuringServingSurvivesHydration is the defect the descriptor
// redesign removes. The earlier shape read the mode, widened it, wrote, and
// wrote the mode it had read back; a user chmod that landed inside that window
// was acknowledged and then silently reverted, because the authority's SETATTR
// path does not take the restore entry lock. Nothing reverts anything now: the
// mode the user set is the mode that stands, in either direction, and hydration
// keeps working through the descriptor the walk already holds.
func TestAUserChmodDuringServingSurvivesHydration(t *testing.T) {
	if !runsUnprivileged() {
		rerunUnprivileged(t, "TestAUserChmodDuringServingSurvivesHydration")
		return
	}
	restored := buildRestoredVolume(t)
	files, err := restored.volume.ResolveRestoreFiles(restored.identities, 64)
	if err != nil {
		t.Fatalf("resolve restore bindings: %v", err)
	}
	defer files.Close()

	// Widening and narrowing are both a user's business, and a hydration write
	// must survive - and disturb - neither.
	for _, step := range []struct {
		entry uint32
		mode  fs.FileMode
	}{
		{entryReadOnly, 0o755},
		{entryReadOnly, 0o000},
		{entryUnopened, 0o644},
		{entryUnopened, 0o000},
	} {
		name := restored.names[step.entry]
		if err := restored.volume.Chmod(restored.caps[step.entry], step.mode); err != nil {
			t.Fatalf("chmod %q to %#o: %v", name, step.mode, err)
		}
		if err := files.PWrite(step.entry, 0, []byte("hydration after a user chmod")); err != nil {
			t.Fatalf("PWrite into %q at user mode %#o: %v", name, step.mode, err)
		}
		if err := files.Fdatasync(step.entry); err != nil {
			t.Fatalf("Fdatasync %q at user mode %#o: %v", name, step.mode, err)
		}
		if err := files.RestoreMtime(step.entry); err != nil {
			t.Fatalf("RestoreMtime %q at user mode %#o: %v", name, step.mode, err)
		}
		if mode := restored.modeOf(t, name, restored.caps[step.entry]); mode != uint32(step.mode) {
			t.Fatalf("hydration moved %q from the user's %#o to %#o", name, step.mode, mode)
		}
		// A write the kernel refuses must not be an excuse to touch the mode
		// either: a volume that blocks mid-restore is inspected by a human.
		if err := files.PWrite(step.entry, -1, []byte("x")); err == nil {
			t.Fatalf("PWrite into %q at a negative offset succeeded", name)
		}
		if mode := restored.modeOf(t, name, restored.caps[step.entry]); mode != uint32(step.mode) {
			t.Fatalf("a failed hydration write moved %q from the user's %#o to %#o", name, step.mode, mode)
		}
	}
}

// TestTheBindingWalkOpensAndRestoresAReadOnlyMode isolates the walk's EACCES
// path. The volume here is flat, so the walk needs no help traversing anything
// and the only thing that can refuse the O_RDWR open is the file's own 0444.
func TestTheBindingWalkOpensAndRestoresAReadOnlyMode(t *testing.T) {
	if !runsUnprivileged() {
		rerunUnprivileged(t, "TestTheBindingWalkOpensAndRestoresAReadOnlyMode")
		return
	}
	path := filepath.Clean(t.TempDir())
	volume, err := open(path, false, 0, nil)
	if err != nil {
		t.Fatalf("open volume: %v", err)
	}
	t.Cleanup(func() {
		if err := volume.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	root, err := volume.Root()
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := volume.Create(root, readOnlyName, 0o444, true)
	if err != nil {
		t.Fatalf("create %s: %v", readOnlyName, err)
	}
	identity, err := volume.Identity(published)
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Open(filepath.Join(path, readOnlyName), unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Close(fd)
		t.Fatalf("%q could be opened for writing; this identity is not constrained by the mode", readOnlyName)
	} else if !errors.Is(err, unix.EACCES) {
		t.Fatalf("open %q for writing = %v, want EACCES", readOnlyName, err)
	}
	files, err := volume.ResolveRestoreFiles(map[[16]byte]uint32{identity: entryReadOnly}, 64)
	if err != nil {
		t.Fatalf("resolve restore bindings: %v", err)
	}
	defer files.Close()
	// The walk had to widen this file to open it, and the mode has to be back
	// before anything else happens - the walk is the only place a mode moves,
	// and it must not survive the walk's return.
	if attr, err := volume.Getattr(published); err != nil {
		t.Fatal(err)
	} else if attr.Mode.Perm() != 0o444 {
		t.Fatalf("the binding walk left the file at mode %#o, not the %#o it found", attr.Mode.Perm(), 0o444)
	}
	// The descriptor the walk retained still writes even though nothing can
	// open this file for writing any more.
	if fd, err := unix.Open(filepath.Join(path, readOnlyName), unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Close(fd)
		t.Fatalf("%q became writable to a fresh open; the walk did not narrow it back", readOnlyName)
	} else if !errors.Is(err, unix.EACCES) {
		t.Fatalf("open %q for writing after the walk = %v, want EACCES", readOnlyName, err)
	}
	payload := []byte("bytes the archive holds for a file its owner may not write")
	if err := files.PWrite(entryReadOnly, 0, payload); err != nil {
		t.Fatalf("PWrite into a 0444 file: %v", err)
	}
	if err := files.Fdatasync(entryReadOnly); err != nil {
		t.Fatalf("Fdatasync a 0444 file: %v", err)
	}
	if err := files.RestoreMtime(entryReadOnly); err != nil {
		t.Fatalf("RestoreMtime on a 0444 file: %v", err)
	}
	attr, err := volume.Getattr(published)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o444 {
		t.Fatalf("after a hydration write the file is mode %#o, not the %#o it started at", attr.Mode.Perm(), 0o444)
	}
	got, err := os.ReadFile(filepath.Join(path, readOnlyName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("the file holds %q, not the bytes the hydration write supplied", got)
	}
}
