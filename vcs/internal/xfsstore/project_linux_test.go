//go:build linux

package xfsstore

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const fsIOCFSSetXattr = 0x401c5820

// projectVolume opens the volume the XFS job provisioned. Everything below
// needs a real XFS with project quota: no other filesystem can answer these
// questions, and none may stand in for it.
func projectVolume(t *testing.T) (*Volume, string, uint32) {
	t.Helper()
	root, project := requireProvisionedXFS(t)
	v, err := Open(root, Config{ExpectedProjectID: project,
		ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, root, project
}

// setProject rewrites an inode's XFS project accounting the way a restored
// backup or a host process would leave it. It needs a descriptor opened for
// access and CAP_FOWNER, which is the same constraint the store itself lives
// under and the reason the store can only read a project through such a
// descriptor.
func setProject(t *testing.T, path string, project uint32, inherit bool) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var attr fsxattr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIOCFSGetXattr, uintptr(unsafe.Pointer(&attr))); errno != 0 {
		t.Fatalf("FSGETXATTR: %v", errno)
	}
	attr.ProjectID = project
	if inherit {
		attr.XFlags |= fsXFlagProjInherit
	} else {
		attr.XFlags &^= fsXFlagProjInherit
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIOCFSSetXattr, uintptr(unsafe.Pointer(&attr))); errno != 0 {
		t.Skipf("planting a foreign project needs CAP_FOWNER: %v", errno)
	}
}

func removeAll(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() { _ = os.RemoveAll(path) })
}

// TestProjectStatFSReportsTheVolumeNotTheCell settles what the old comment
// asserted. statfs on a PROJINHERIT directory of a mount with -o prjquota is
// answered by xfs_qm_statvfs with the project's own limits and usage, with no
// capability required: quotactl(2) needs CAP_SYS_ADMIN, statfs(2) on a
// project directory does not. A cell-wide figure here is what makes rsync
// --preallocate, an installer precheck or a database sizing decision start a
// write that dies partway through, and it leaks the cell's capacity and other
// tenants' usage.
func TestProjectStatFSReportsTheVolumeNotTheCell(t *testing.T) {
	v, _, _ := projectVolume(t)
	stat, err := v.StatFS()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Blocks == 0 || stat.Files == 0 || stat.BlocksAvailable > stat.Blocks || stat.FilesFree > stat.Files {
		t.Fatalf("invalid project statfs: %+v", stat)
	}
	cell := os.Getenv("PORTABLEFS_XFS_TEST_CELL")
	if cell == "" {
		t.Skip("PORTABLEFS_XFS_TEST_CELL is required to compare against the cell")
	}
	var cellStat unix.Statfs_t
	if err := unix.Statfs(cell, &cellStat); err != nil {
		t.Fatal(err)
	}
	if stat.Blocks >= cellStat.Blocks {
		t.Fatalf("volume reports %d blocks, the cell has %d: statfs is not "+
			"project-scoped, so every free-space precheck sees the cell",
			stat.Blocks, cellStat.Blocks)
	}
	if stat.Files >= cellStat.Files {
		t.Fatalf("volume reports %d inodes, the cell has %d", stat.Files, cellStat.Files)
	}
}

// TestProjectRefusesForeignProjectInode is the project-isolation defect: a
// descendant whose project does not match was fully writable, and its blocks
// were charged to another project or to none - unbounded usage against a quota
// that appears enforced.
func TestProjectRefusesForeignProjectInode(t *testing.T) {
	v, root, project := projectVolume(t)
	rootCap, _ := v.Root()
	removeAll(t, root+"/foreign-project")
	item, _, err := v.Create(rootCap, "foreign-project", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatalf("the volume's own file must be writable: %v", err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	setProject(t, root+"/foreign-project", project+1, false)

	if _, err := v.OpenFile(item, OpenFlags{Read: true, Write: true}); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("OpenFile on a foreign-project inode = %v, want ErrProjectIsolation", err)
	}
	if err := v.TruncateObject(item, 0); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("TruncateObject on a foreign-project inode = %v", err)
	}
	if err := v.SyncObject(item); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("SyncObject on a foreign-project inode = %v", err)
	}
	if _, err := v.ListXattr(item); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("ListXattr on a foreign-project inode = %v", err)
	}
}

// TestProjectRefusesCreationUnderAForeignProjectDirectory covers the other
// direction: a directory that belongs to another project makes every inode
// created in it inherit that project, so verifying the child verifies the
// parent it came from.
func TestProjectRefusesCreationUnderAForeignProjectDirectory(t *testing.T) {
	v, root, project := projectVolume(t)
	rootCap, _ := v.Root()
	removeAll(t, root+"/foreign-tree")
	dir, _, err := v.Mkdir(rootCap, "foreign-tree", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	setProject(t, root+"/foreign-tree", project+1, true)

	_, _, err = v.Create(dir, "child", 0o600, true)
	if !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("Create under a foreign-project directory = %v, want ErrProjectIsolation", err)
	}
	if !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatal("the inode was created before its project could be read, so the " +
			"outcome must be reported as uncertain")
	}
	if _, _, err := v.Mkdir(dir, "child-dir", 0o700); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("Mkdir under a foreign-project directory = %v, want ErrProjectIsolation", err)
	}
}

// TestProjectMkdirVerifiesInheritance keeps the check honest for a mode with
// no read bit: the directory is created owner-accessible, verified, and only
// then given the mode that was asked for. A check that could only run for
// convenient modes would not be a check.
func TestProjectMkdirVerifiesInheritance(t *testing.T) {
	v, root, _ := projectVolume(t)
	rootCap, _ := v.Root()
	removeAll(t, root+"/execute-only")
	item, attr, err := v.Mkdir(rootCap, "execute-only", 0o111)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o111 {
		t.Fatalf("mode = %v, want 111", attr.Mode.Perm())
	}
	fresh, err := v.Getattr(item)
	if err != nil || fresh.Mode.Perm() != 0o111 {
		t.Fatalf("mode after Mkdir = %v, %v", fresh.Mode, err)
	}
}

// TestProjectIoctlNeedsAnAccessDescriptor records the kernel constraint the
// whole design above follows from: FS_IOC_FSGETXATTR is rejected on an O_PATH
// descriptor, which is what every capability in this store holds, so a project
// can only be read where a descriptor was opened for access.
func TestProjectIoctlNeedsAnAccessDescriptor(t *testing.T) {
	v, root, project := projectVolume(t)
	rootCap, _ := v.Root()
	removeAll(t, root+"/ioctl-probe")
	if _, _, err := v.Create(rootCap, "ioctl-probe", 0o600, true); err != nil {
		t.Fatal(err)
	}
	// A looked-up capability holds the O_PATH descriptor every namespace entry
	// point produces; Create is the exception that keeps its access
	// descriptor.
	item, _, err := v.Lookup(rootCap, "ioctl-probe")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(item)
	v.mu.RLock()
	pathFD := v.objects[item].res.fd
	v.mu.RUnlock()
	if _, err := projectOf(pathFD); !errors.Is(err, unix.EBADF) {
		t.Fatalf("FS_IOC_FSGETXATTR on an O_PATH descriptor = %v, want EBADF", err)
	}
	accessFD, err := v.reopen(pathFD, unix.O_RDONLY, KindRegular)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(accessFD)
	attr, err := projectOf(accessFD)
	if err != nil {
		t.Fatal(err)
	}
	if attr.ProjectID != project {
		t.Fatalf("project = %d, want %d", attr.ProjectID, project)
	}
}
