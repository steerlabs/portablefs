//go:build linux

package xfsstore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This explicitly selected root fixture owns every loop device and mapper it
// creates. The service child holds all root descriptions before a data-sector
// fault in B; no mocked syscall or replacement error cursor participates.
func TestSharedXFSWritebackDomain(t *testing.T) {
	if os.Getenv("PORTABLEFS_XFS_DOMAIN_TEST") != "1" {
		t.Skip("requires the explicit privileged shared-domain fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-domain provisioning requires root")
	}
	for _, name := range []string{"losetup", "dmsetup", "mkfs.xfs", "mount", "umount", "blockdev", "xfs_quota", "xfs_io"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("fault fixture dependency %s: %v", name, err)
		}
	}
	provisioner := os.Getenv("PORTABLEFS_TEST_PROVISIONER")
	if !filepath.IsAbs(provisioner) {
		t.Fatal("fault fixture needs the exact provision-xfs-volume.sh path")
	}
	dir := t.TempDir()
	for _, path := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	command := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	makeLoop := func(name string) string {
		t.Helper()
		file := filepath.Join(dir, name+".img")
		f, err := os.Create(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(512 << 20); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		loop := command("losetup", "--find", "--show", file)
		t.Cleanup(func() {
			if out, err := exec.Command("losetup", "-d", loop).CombinedOutput(); err != nil {
				t.Errorf("release owned loop %s: %v %s", loop, err, out)
			}
		})
		return loop
	}
	sharedLoop, controlLoop := makeLoop("shared"), makeLoop("control")
	sectors, err := strconv.ParseUint(command("blockdev", "--getsz", sharedLoop), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	mapper := fmt.Sprintf("pfs-p2-%d-%s", os.Getpid(), filepath.Base(filepath.Dir(dir)))
	linear := fmt.Sprintf("0 %d linear %s 0", sectors, sharedLoop)
	command("dmsetup", "create", mapper, "--table", linear)
	command("dmsetup", "mknodes", mapper)
	t.Cleanup(func() {
		if out, err := exec.Command("dmsetup", "remove", mapper).CombinedOutput(); err != nil {
			t.Errorf("remove owned mapper: %v %s", err, out)
		}
	})
	device := filepath.Join("/dev/mapper", mapper)
	shared, control := filepath.Join(dir, "shared"), filepath.Join(dir, "control")
	for _, pair := range [][2]string{{device, shared}, {controlLoop, control}} {
		command("mkfs.xfs", "-q", "-f", pair[0])
		if err := os.Mkdir(pair[1], 0755); err != nil {
			t.Fatal(err)
		}
		command("mount", "-o", "prjquota,nodev,nosuid,noexec,noatime", pair[0], pair[1])
		mount := pair[1]
		t.Cleanup(func() {
			if out, err := exec.Command("umount", mount).CombinedOutput(); err != nil {
				t.Errorf("unmount owned fixture: %v %s", err, out)
			}
		})
	}
	command("bash", provisioner, shared, "a", "42101", "200001", "200001", "64m", "20000")
	command("bash", provisioner, shared, "b", "42102", "200001", "200001", "8m", "20000")
	command("bash", provisioner, control, "c", "42103", "200001", "200001", "64m", "20000")
	input, childInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	childOutput, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, "domain-service.test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	source.Close()
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), executable, "-test.run=^TestSharedXFSWritebackDomainChild$", "-test.v")
	child.ExtraFiles = []*os.File{input, output}
	child.Env = append(os.Environ(), "PORTABLEFS_XFS_DOMAIN_CHILD=1", "PORTABLEFS_DOMAIN_A="+filepath.Join(shared, "a"), "PORTABLEFS_DOMAIN_B="+filepath.Join(shared, "b"), "PORTABLEFS_DOMAIN_C="+filepath.Join(control, "c"))
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 200001, Gid: 200001}}
	var childLog bytes.Buffer
	child.Stdout = &childLog
	child.Stderr = &childLog
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	input.Close()
	output.Close()
	joined := false
	defer func() {
		childInput.Close()
		childOutput.Close()
		if !joined {
			child.Process.Kill()
			child.Wait()
		}
		t.Logf("service child:\n%s", childLog.Bytes())
	}()
	reader := bufio.NewReader(childOutput)
	await := func(want string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			line, err := reader.ReadString('\n')
			if err == nil && strings.TrimSpace(line) != want {
				err = fmt.Errorf("phase %q, want %q", line, want)
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("service child stalled before %s", want)
		}
	}
	send := func(phase string) {
		t.Helper()
		if _, err := fmt.Fprintln(childInput, phase); err != nil {
			t.Fatal(err)
		}
	}
	await("quota-and-baseline-synced")
	physical := firstPhysicalBlock(t, filepath.Join(shared, "b", "fault"))
	if physical%512 != 0 || physical/512+8 >= sectors {
		t.Fatal("fault sector is outside the owned mapper")
	}
	send("dirty")
	await("dirty")
	start := physical / 512
	end := start + 8
	table := fmt.Sprintf("0 %d linear %s 0\n%d 8 error\n%d %d linear %s %d", start, sharedLoop, start, end, sectors-end, sharedLoop, end)
	command("dmsetup", "suspend", "--noflush", mapper)
	command("dmsetup", "reload", mapper, "--table", table)
	command("dmsetup", "resume", mapper)
	// Always restore this exact mapper before unmount, including child failure.
	defer func() {
		exec.Command("dmsetup", "suspend", "--noflush", mapper).Run()
		exec.Command("dmsetup", "reload", mapper, "--table", linear).Run()
		exec.Command("dmsetup", "resume", mapper).Run()
	}()
	send("sync")
	await("shared-error-control-healthy")
	if err := child.Wait(); err != nil {
		joined = true
		t.Fatalf("service child: %v", err)
	}
	joined = true
}

type domainFiemapExtent struct {
	Logical, Physical, Length uint64
	Reserved                  [2]uint64
	Flags                     uint32
	Reserved32                [3]uint32
}
type domainFiemap struct {
	Start, Length                  uint64
	Flags, Mapped, Count, Reserved uint32
	Extent                         domainFiemapExtent
}

func firstPhysicalBlock(t *testing.T, path string) uint64 {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	mapping := domainFiemap{Length: 4096, Flags: 1, Count: 1}
	if unsafe.Sizeof(mapping) != 88 {
		t.Fatal("unexpected FIEMAP ABI size")
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), 0xc020660b, uintptr(unsafe.Pointer(&mapping)))
	if errno != 0 || mapping.Mapped != 1 || mapping.Extent.Logical != 0 || mapping.Extent.Length < 4096 || mapping.Extent.Flags&6 != 0 {
		t.Fatalf("identity-bound FIEMAP: %+v %v", mapping, errno)
	}
	return mapping.Extent.Physical
}

func TestSharedXFSWritebackDomainChild(t *testing.T) {
	if os.Getenv("PORTABLEFS_XFS_DOMAIN_CHILD") != "1" {
		t.Skip("service subprocess only")
	}
	if os.Geteuid() != 200001 {
		t.Fatal("fault observer is not the unprivileged service identity")
	}
	commands := bufio.NewScanner(os.NewFile(3, "domain-commands"))
	status := os.NewFile(4, "domain-status")
	defer status.Close()
	phase := func(want string) {
		t.Helper()
		if !commands.Scan() || commands.Text() != want {
			t.Fatalf("missing phase %s", want)
		}
	}
	var aCalls atomic.Int32
	openStore := func(key string, id uint32) *Volume {
		t.Helper()
		v, err := Open(os.Getenv(key), Config{ExpectedProjectID: id, ExpectedOwnerUID: 200001, ExpectedOwnerGID: 200001, OnStorageSync: func(StorageSync) {
			if id == 42101 {
				aCalls.Add(1)
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { v.Close() })
		return v
	}
	a, b, c := openStore("PORTABLEFS_DOMAIN_A", 42101), openStore("PORTABLEFS_DOMAIN_B", 42102), openStore("PORTABLEFS_DOMAIN_C", 42103)
	aRootFD := a.rootFD
	var aStat, cStat unix.Stat_t
	if err := unix.Fstat(a.rootFD, &aStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(c.rootFD, &cStat); err != nil {
		t.Fatal(err)
	}
	if aStat.Dev == cStat.Dev {
		t.Fatal("superblock control shares the fault filesystem")
	}
	root, _ := b.Root()
	quota, _, err := b.Create(root, "quota", 0600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := b.OpenFile(quota, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1<<20)
	var quotaErr error
	for n := 0; n < 32; n++ {
		_, quotaErr = b.WriteAt(handle, payload, int64(n)*int64(len(payload)))
		if quotaErr != nil {
			break
		}
	}
	if !errors.Is(quotaErr, syscall.ENOSPC) && !errors.Is(quotaErr, syscall.EDQUOT) {
		t.Fatalf("project quota did not refuse synchronously: %v", quotaErr)
	}
	if err := a.SyncFS(); err != nil || a.Health() != nil {
		t.Fatalf("B's synchronous quota refusal fenced healthy A: %v", err)
	}
	if err := b.Truncate(handle, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncFS(); err != nil {
		t.Fatal(err)
	}
	if err := b.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	if err := b.Unlink(root, "quota", false); err != nil {
		t.Fatal(err)
	}
	file, _, err := b.Create(root, "fault", 0600, true)
	if err != nil {
		t.Fatal(err)
	}
	fault, err := b.OpenFile(file, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.WriteAt(fault, make([]byte, 65536), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.FsyncCoalesced(fault, false); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncFS(); err != nil {
		t.Fatal(err)
	}
	if err := c.SyncFS(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(status, "quota-and-baseline-synced")
	phase("dirty")
	if _, err := b.WriteAt(fault, []byte(strings.Repeat("d", 4096)), 0); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(status, "dirty")
	phase("sync")
	// Renew dirtiness after fault installation, so a background flush of the
	// earlier page cannot accidentally turn this into a clean-file fsync.
	if _, err := b.WriteAt(fault, []byte(strings.Repeat("e", 4096)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.FsyncCoalesced(fault, false); err == nil {
		t.Fatal("real B data writeback fault did not fail fsync")
	}
	if err := a.SyncFS(); err == nil || a.Health() == nil {
		t.Fatalf("A did not observe shared superblock writeback failure: %v", err)
	} else {
		t.Logf("A retained-root syncfs observed B data-sector fault: %v", err)
	}
	if a.rootFD != aRootFD {
		t.Fatal("A reset its retained root error cursor")
	}
	before := aCalls.Load()
	if err := a.SyncFS(); err == nil || aCalls.Load() != before {
		t.Fatal("A's first writeback failure was not sticky")
	}
	if err := c.SyncFS(); err != nil || c.Health() != nil {
		t.Fatalf("separate-superblock control failed: %v", err)
	}
	fmt.Fprintln(status, "shared-error-control-healthy")
}
