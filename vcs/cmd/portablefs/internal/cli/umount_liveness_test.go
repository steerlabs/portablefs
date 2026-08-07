package cli

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE FIRST THING `portablefs umount` DID WAS CALL INTO THE FILESYSTEM IT WAS
// ASKED TO UNMOUNT.
//
// canonicalMountPath lstats the mount point, and lstat on a mount point resolves
// to the mounted filesystem's root vnode. On the wedged mount from the live
// battery that call never returned, so both `umount` and `umount --force` hung
// for more than five minutes without executing one line of unmount logic. This
// test wedges the statter exactly that way. On the base revision it hangs
// forever; the probe is now bounded and falls through to the kernel mount table,
// which never resolves a pathname through a filesystem.
func TestCanonicalMountPathSurvivesAWedgedStatter(t *testing.T) {
	const wedged = "/Volumes/portablefs-wedged"
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	stubMountIdentification(t,
		func(string) (fs.FileInfo, error) {
			<-blocked // models an lstat the extension will never answer
			return nil, nil
		},
		func(path string) ([]kernelMountIdentity, error) {
			if path != wedged {
				return nil, nil
			}
			return []kernelMountIdentity{{path: wedged, fsType: defaultFskitType, source: "portablefs"}}, nil
		},
	)
	restore := mountPathProbeBudget
	mountPathProbeBudget = 100 * time.Millisecond
	t.Cleanup(func() { mountPathProbeBudget = restore })

	done := make(chan struct{})
	var got string
	var err error
	go func() {
		got, err = canonicalMountPath(wedged)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("canonicalMountPath never returned on a wedged mount point; umount cannot begin")
	}
	if err != nil {
		t.Fatalf("a wedged mount point must still be nameable through the kernel mount table: %v", err)
	}
	if got != wedged {
		t.Fatalf("canonical path = %q, want %q", got, wedged)
	}
}

// /sbin/umount ON A WEDGED MOUNT BLOCKS IN THE SAME UNINTERRUPTIBLE KERNEL WAIT.
// The CLI used to run it with exec.Command(...).CombinedOutput(): no deadline,
// and an output read that cannot finish until the child releases its pipes.
func TestPlatformUnmountHelperIsAbandonedRatherThanWaitedOn(t *testing.T) {
	sleep := ""
	for _, candidate := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if _, err := os.Stat(candidate); err == nil {
			sleep = candidate
			break
		}
	}
	if sleep == "" {
		t.Skip("no sleep binary available to model a wedged unmount helper")
	}
	start := time.Now()
	_, err := boundedCombinedOutput(150*time.Millisecond, sleep, "30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a helper that never returns must not be reported as a completed unmount")
	}
	if !errors.Is(err, errPlatformUnmountAbandoned) {
		t.Fatalf("want an abandoned-helper verdict, got %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("the CLI waited %s on a wedged unmount helper", elapsed)
	}
}

// failingReader fails the test if anything reads it. A force path that needs
// interactive input cannot be used by the scripts, CI jobs and recovery runbooks
// that are the only things running it.
type failingReader struct{ t *testing.T }

func (r failingReader) Read([]byte) (int, error) {
	r.t.Fatal("umount read standard input; no unmount path — least of all --force — may require interactive input")
	return 0, io.EOF
}

// umountLivenessEnv is the shared umount test environment with an input
// source that fails the test if anything reads it.
func umountLivenessEnv(t *testing.T) (*cmdEnv, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	e, out, errBuf, stateDir := umountTestEnv(t)
	e.stdin = failingReader{t: t}
	e.stdinIsTTY = func() bool { return false }
	return e, out, errBuf, stateDir
}

func TestUmountForceNeverReadsStandardInput(t *testing.T) {
	mountPath := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	stubMountIdentification(t, nil, func(string) ([]kernelMountIdentity, error) { return nil, nil })

	e, _, _, _ := umountLivenessEnv(t)
	// No recorded state: umount must refuse. The point is that it refuses
	// WITHOUT ever touching stdin, on a non-tty, under --force.
	if code := cmdUmount(e, []string{"--force", mountPath}); code == 0 {
		t.Fatal("an untracked path must not report a successful forced unmount")
	}
}

// KILLING A HUNG UMOUNT MUST NOT PRODUCE STATE ONLY A TEXT EDITOR CAN CLEAR.
//
// The live battery left an intent latched at phase "unmounting". Every later
// mount at that path was refused, no supported command resolved it, and the
// operator had to delete ~/.local/state/portablefs/mounts/*.json by hand.
func TestDiscardRecordClearsALatchedUnmountingIntent(t *testing.T) {
	mountPath := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	stubMountIdentification(t, nil, func(string) ([]kernelMountIdentity, error) { return nil, nil })

	e, out, _, mountStateDir := umountLivenessEnv(t)
	writeLatchedUnmountingIntent(t, mountStateDir, mountPath)
	if code := cmdUmount(e, []string{"--discard-record", mountPath}); code != 0 {
		t.Fatalf("discard refused a record whose owners and resources are all gone: %s", out.String())
	}
	_, intentPath := mountOperationPaths(mountStateDir, mountPath)
	if _, err := os.Lstat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("the latched intent must be gone, %s survived (%v)", intentPath, err)
	}
	// And a mount at that path is no longer blocked by the incomplete operation.
	op, err := acquireMountOperation(mountStateDir, mountPath, "vol_1", "main", "fskit")
	if err != nil {
		t.Fatalf("mounting must be possible again after the record is discarded: %v", err)
	}
	_ = op.close(true)
}

func TestDiscardRecordRefusesWhileAKernelMountSurvives(t *testing.T) {
	mountPath := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
		return []kernelMountIdentity{{path: path, fsType: defaultFskitType, source: "portablefs"}}, nil
	})

	e, _, errBuf, mountStateDir := umountLivenessEnv(t)
	writeLatchedUnmountingIntent(t, mountStateDir, mountPath)
	if code := cmdUmount(e, []string{"--discard-record", mountPath}); code == 0 {
		t.Fatal("discard must never remove the record of a path that is still mounted")
	}
	if !strings.Contains(errBuf.String(), "kernel mount is still present") {
		t.Fatalf("the refusal must name the surviving resource: %s", errBuf.String())
	}
	_, intentPath := mountOperationPaths(mountStateDir, mountPath)
	if _, err := os.Lstat(intentPath); err != nil {
		t.Fatalf("a refused discard must preserve the record: %v", err)
	}
}

func TestDiscardRecordAndForceAreDifferentOperations(t *testing.T) {
	mountPath := filepath.Join(t.TempDir(), "mnt")
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		t.Fatal(err)
	}
	stubMountIdentification(t, nil, func(string) ([]kernelMountIdentity, error) { return nil, nil })
	e, _, _, _ := umountLivenessEnv(t)
	if code := cmdUmount(e, []string{"--discard-record", "--force", mountPath}); code == 0 {
		t.Fatal("--discard-record must never be usable as a stronger --force")
	}
}

// writeLatchedUnmountingIntent reproduces the exact artifact a killed umount
// leaves behind: a phase "unmounting" intent whose operation owner is gone.
func writeLatchedUnmountingIntent(t *testing.T, mountStateDir, mountPath string) {
	t.Helper()
	_, intentPath := mountOperationPaths(mountStateDir, mountPath)
	intent := mountIntent{
		SchemaVersion:               2,
		Phase:                       "unmounting",
		MountPath:                   mountPath,
		VolumeID:                    "vol_1",
		Branch:                      "main",
		Strategy:                    "fskit",
		AttachRef:                   "att_AAAAAAAAAAAAAAAAAAAAAA",
		FSType:                      defaultFskitType,
		MountInstanceID:             "mnt_AAAAAAAAAAAAAAAAAAAAAA",
		StartedAtMs:                 42,
		AuthorityURL:                "127.0.0.1:2050",
		DataPlaneTransport:          dataPlaneTransportPlaintext,
		OperationOwnerPID:           1,
		OperationOwnerStartIdentity: "this-identity-can-never-match-pid-1",
		UpdatedAtMs:                 42,
	}
	if err := writeMountIntentRecord(intentPath, &intent); err != nil {
		t.Fatal(err)
	}
}
