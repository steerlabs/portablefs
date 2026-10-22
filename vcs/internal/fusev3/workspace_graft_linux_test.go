//go:build linux

package fusev3

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func workspaceBackingSnapshot(t *testing.T, root string) string {
	t.Helper()
	var out bytes.Buffer
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "%s %s %d\n", path, info.Mode(), info.Size())
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}
func TestWorkspaceEveryGraftBranchChecksEntry(t *testing.T) {
	for _, operation := range []string{"lookup", "getattr", "setattr", "open", "create", "tmpfile", "mknod", "mkdir", "unlink", "rmdir", "rename", "link", "symlink", "readlink", "read", "write", "opendir", "readdir", "readdirplus", "fsyncdir", "fsync", "statfs", "getlk", "setlk", "setlkw", "fallocate", "copy", "getxattr", "setxattr", "listxattr", "removexattr", "syncfs"} {
		t.Run(operation, func(t *testing.T) {
			f := newGraftFixture(t, mustRoutes(t, "node_modules/\n"), true)
			root := f.mkdir(t, 1, "node_modules")
			file := f.createFile(t, root.NodeId, "file", []byte("original"))
			var opened, directory fuse.OpenOut
			if s := testRawCall(t, f.raw, func(u uint64) fuse.Status {
				return testEntryFileSystem(f.raw).Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: file.NodeId}, Flags: syscall.O_RDWR}, &opened)
			}); s != fuse.OK {
				t.Fatal(s)
			}
			if s := testRawCall(t, f.raw, func(u uint64) fuse.Status {
				return testEntryFileSystem(f.raw).OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: root.NodeId}}, &directory)
			}); s != fuse.OK {
				t.Fatal(s)
			}
			g := bindWorkspaceTestGate(t, f.mount)
			g.Close(1)
			before, calls := workspaceBackingSnapshot(t, f.backing), f.calls()
			u := nextTestRequestUnique()
			fileHeader := fuse.InHeader{Unique: u, NodeId: file.NodeId}
			parentHeader := fuse.InHeader{Unique: u, NodeId: root.NodeId}
			lock := &fuse.LkIn{InHeader: fileHeader, Fh: opened.Fh, Lk: fuse.FileLock{Typ: syscall.F_WRLCK}}
			var s fuse.Status
			switch operation {
			case "lookup":
				s = testEntryFileSystem(f.raw).Lookup(nil, &parentHeader, "file", &fuse.EntryOut{})
			case "getattr":
				s = testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fileHeader}, &fuse.AttrOut{})
			case "setattr":
				s = testEntryFileSystem(f.raw).SetAttr(nil, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: fileHeader, Valid: fuse.FATTR_SIZE, Size: 1}}, &fuse.AttrOut{})
			case "open":
				s = testEntryFileSystem(f.raw).Open(nil, &fuse.OpenIn{InHeader: fileHeader, Flags: syscall.O_RDWR | syscall.O_TRUNC}, &fuse.OpenOut{})
			case "create":
				s = testEntryFileSystem(f.raw).Create(nil, &fuse.CreateIn{InHeader: parentHeader, Flags: syscall.O_RDWR, Mode: 0600}, "new", &fuse.CreateOut{})
			case "tmpfile":
				s = testEntryFileSystem(f.raw).Tmpfile(nil, &fuse.CreateIn{InHeader: parentHeader, Flags: syscall.O_RDWR, Mode: 0600}, "/", &fuse.CreateOut{})
			case "mknod":
				s = testEntryFileSystem(f.raw).Mknod(nil, &fuse.MknodIn{InHeader: parentHeader, Mode: syscall.S_IFREG | 0600}, "new", &fuse.EntryOut{})
			case "mkdir":
				s = testEntryFileSystem(f.raw).Mkdir(nil, &fuse.MkdirIn{InHeader: parentHeader, Mode: 0700}, "new", &fuse.EntryOut{})
			case "unlink":
				s = testEntryFileSystem(f.raw).Unlink(nil, &parentHeader, "file")
			case "rmdir":
				s = testEntryFileSystem(f.raw).Rmdir(nil, &parentHeader, "dir")
			case "rename":
				s = testEntryFileSystem(f.raw).Rename(nil, &fuse.RenameIn{InHeader: parentHeader, Newdir: root.NodeId}, "file", "renamed")
			case "link":
				s = testEntryFileSystem(f.raw).Link(nil, &fuse.LinkIn{InHeader: parentHeader, Oldnodeid: file.NodeId}, "linked", &fuse.EntryOut{})
			case "symlink":
				s = testEntryFileSystem(f.raw).Symlink(nil, &parentHeader, "file", "linked", &fuse.EntryOut{})
			case "readlink":
				_, s = testEntryFileSystem(f.raw).Readlink(nil, &fileHeader)
			case "read":
				_, s = testEntryFileSystem(f.raw).Read(nil, &fuse.ReadIn{InHeader: fileHeader, Fh: opened.Fh, Size: 4}, make([]byte, 4))
			case "write":
				_, s = testEntryFileSystem(f.raw).Write(nil, &fuse.WriteIn{InHeader: fileHeader, Fh: opened.Fh, Size: 4}, []byte("new!"))
			case "opendir":
				s = testEntryFileSystem(f.raw).OpenDir(nil, &fuse.OpenIn{InHeader: parentHeader}, &fuse.OpenOut{})
			case "readdir":
				s = testEntryFileSystem(f.raw).ReadDir(nil, &fuse.ReadIn{InHeader: parentHeader, Fh: directory.Fh}, fuse.NewDirEntryList(make([]byte, 4096), 0))
			case "readdirplus":
				s = testEntryFileSystem(f.raw).ReadDirPlus(nil, &fuse.ReadIn{InHeader: parentHeader, Fh: directory.Fh}, fuse.NewDirEntryList(make([]byte, 4096), 0))
			case "fsyncdir":
				s = testEntryFileSystem(f.raw).FsyncDir(nil, &fuse.FsyncIn{InHeader: parentHeader, Fh: directory.Fh})
			case "fsync":
				s = testEntryFileSystem(f.raw).Fsync(nil, &fuse.FsyncIn{InHeader: fileHeader, Fh: opened.Fh})
			case "statfs":
				s = testEntryFileSystem(f.raw).StatFs(nil, &fileHeader, &fuse.StatfsOut{})
			case "getlk":
				s = testEntryFileSystem(f.raw).GetLk(nil, lock, &fuse.LkOut{})
			case "setlk":
				s = testEntryFileSystem(f.raw).SetLk(nil, lock)
			case "setlkw":
				s = testEntryFileSystem(f.raw).SetLkw(nil, lock)
			case "fallocate":
				s = testEntryFileSystem(f.raw).Fallocate(nil, &fuse.FallocateIn{InHeader: fileHeader, Fh: opened.Fh, Length: 4096})
			case "copy":
				_, s = testEntryFileSystem(f.raw).CopyFileRange(nil, &fuse.CopyFileRangeIn{InHeader: fileHeader, FhIn: opened.Fh, FhOut: opened.Fh, NodeIdOut: file.NodeId, Len: 1, OffOut: 20})
			case "getxattr":
				_, s = testEntryFileSystem(f.raw).GetXAttr(nil, &fileHeader, "user.x", nil)
			case "setxattr":
				s = testEntryFileSystem(f.raw).SetXAttr(nil, &fuse.SetXAttrIn{InHeader: fileHeader}, "user.x", []byte("x"))
			case "listxattr":
				_, s = testEntryFileSystem(f.raw).ListXAttr(nil, &fileHeader, nil)
			case "removexattr":
				s = testEntryFileSystem(f.raw).RemoveXAttr(nil, &fileHeader, "user.x")
			case "syncfs":
				s = testEntryFileSystem(f.raw).SyncFS(nil, &fuse.SyncFSIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}})
			}
			want := fuse.EIO
			if operation == "readdirplus" {
				want = fuse.ENOSYS
			}
			if operation == "getxattr" || operation == "setxattr" || operation == "listxattr" || operation == "removexattr" {
				want = fuse.Status(graftXattrErrno)
			}
			if s != want || f.calls() != calls || workspaceBackingSnapshot(t, f.backing) != before || f.raw.ReplyWriteTracked(u) {
				t.Fatalf("closed %s escaped admission: status=%v authority calls=%d", operation, s, f.calls()-calls)
			}
			testEntryFileSystem(f.raw).Release(nil, &fuse.ReleaseIn{Fh: opened.Fh})
			testEntryFileSystem(f.raw).ReleaseDir(&fuse.ReleaseIn{Fh: directory.Fh})
		})
	}
}

func TestWorkspaceStaticRefusalsDoNotAcquireServingOwner(t *testing.T) {
	f := newGraftFixture(t, mustRoutes(t, "node_modules/\n"), true)
	root := f.mkdir(t, 1, "node_modules")
	g := bindWorkspaceTestGate(t, f.mount)
	g.Close(1)
	for _, mode := range []uint32{syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFCHR} {
		u := nextTestRequestUnique()
		want := fuse.Status(syscall.EOPNOTSUPP)
		if mode == syscall.S_IFCHR {
			want = fuse.EPERM
		}
		if status := testEntryFileSystem(f.raw).Mknod(nil, &fuse.MknodIn{InHeader: fuse.InHeader{Unique: u, NodeId: root.NodeId}, Mode: mode}, "unsupported", &fuse.EntryOut{}); status != want || f.raw.ReplyWriteTracked(u) {
			t.Fatal("static MKNOD changed admission/errno", status, want)
		}
	}
	u := nextTestRequestUnique()
	if status := testEntryFileSystem(f.raw).OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: root.NodeId}, Flags: syscall.O_RDWR}, &fuse.OpenOut{}); status != fuse.Status(syscall.EISDIR) || f.raw.ReplyWriteTracked(u) {
		t.Fatal("unsupported directory access needed serving", status)
	}
}
