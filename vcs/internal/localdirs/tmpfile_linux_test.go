//go:build linux

package localdirs

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"golang.org/x/sys/unix"
)

func kernelBeforeTmpfileLinkCredentialRelaxation(t *testing.T) (string, bool) {
	t.Helper()
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "unknown", false
	}
	release := string(bytes.TrimRight(name.Release[:], "\x00"))
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return release, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil {
		return release, false
	}
	return release, major < 6 || major == 6 && minor < 12
}

func newTmpfileGrafts(t *testing.T) *Grafts {
	t.Helper()
	base := os.Getenv("PFS_TMPFILE_TEST_ROOT")
	if base == "" {
		base = t.TempDir()
	} else {
		base = filepath.Join(base, t.Name())
		if err := os.RemoveAll(base); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	rules, err := localroutes.Parse([]byte("/node_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{BackingRoot: filepath.Join(base, "local", "sid"), Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func requireTmpfile(t *testing.T, g *Grafts, flags uint32, mode uint32) int {
	t.Helper()
	fd, errno := g.Tmpfile("node_modules", flags, mode)
	if errno == syscall.EOPNOTSUPP && os.Getenv("PFS_TMPFILE_TEST_ROOT") == "" {
		t.Skip("test filesystem does not support O_TMPFILE; the required tmpfs-backed suite exercises it")
	}
	if errno != 0 {
		t.Fatalf("Tmpfile: %v", errno)
	}
	return fd
}

func TestTmpfileIsConfinedUnnamedAndDescriptorRetained(t *testing.T) {
	g := newTmpfileGrafts(t)
	if errno := g.Mkdir("node_modules", 0o755); errno != 0 {
		t.Fatalf("mkdir graft: %v", errno)
	}
	fd := requireTmpfile(t, g, uint32(unix.O_RDWR|unix.O_EXCL), 0o640)
	defer unix.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 0 || st.Mode&0o777 != 0o640 {
		t.Fatalf("tmpfile stat mode=%#o nlink=%d", st.Mode, st.Nlink)
	}
	if n, err := unix.Write(fd, []byte("retained")); err != nil || n != len("retained") {
		t.Fatalf("write=(%d,%v)", n, err)
	}
	if errno := g.Remove("node_modules", true); errno != 0 {
		t.Fatalf("remove empty containing directory while tmpfile open: %v", errno)
	}
	buf := make([]byte, len("retained"))
	if n, err := unix.Pread(fd, buf, 0); err != nil || n != len(buf) || string(buf) != "retained" {
		t.Fatalf("retained descriptor read=(%d,%v,%q)", n, err, buf)
	}
}

func TestTmpfileHasNoPathEscapeFallback(t *testing.T) {
	g := newTmpfileGrafts(t)
	if errno := g.Mkdir("node_modules", 0o755); errno != 0 {
		t.Fatal(errno)
	}
	outside := t.TempDir()
	if errno := g.Symlink(outside, "node_modules/escape"); errno != 0 {
		t.Fatal(errno)
	}
	if fd, errno := g.Tmpfile("node_modules/escape", uint32(unix.O_RDWR), 0o600); errno == 0 {
		_ = unix.Close(fd)
		t.Fatal("Tmpfile followed an absolute symlink outside the pinned backing root")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: entries=%v err=%v", entries, err)
	}
	if fd, errno := g.Tmpfile("../outside", uint32(unix.O_RDWR), 0o600); errno == 0 {
		_ = unix.Close(fd)
		t.Fatal("Tmpfile accepted a parent escape")
	}
}

func TestTmpfileLinkabilityExactlyFollowsExclusive(t *testing.T) {
	g := newTmpfileGrafts(t)
	if errno := g.Mkdir("node_modules", 0o755); errno != 0 {
		t.Fatal(errno)
	}

	linkable := requireTmpfile(t, g, uint32(unix.O_RDWR), 0o600)
	defer unix.Close(linkable)
	if _, err := unix.Write(linkable, []byte("linked")); err != nil {
		t.Fatal(err)
	}
	if errno := g.LinkTmpfile("node_modules", linkable, "node_modules/result"); errno == syscall.ENOENT {
		if release, old := kernelBeforeTmpfileLinkCredentialRelaxation(t); old {
			t.Skipf("kernel %s lacks the >=6.12 unprivileged linkat(AT_EMPTY_PATH) open-credential relaxation required by PortableFS", release)
		}
		t.Fatalf("LinkTmpfile on supported kernel: %v", errno)
	} else if errno != 0 {
		t.Fatalf("LinkTmpfile: %v", errno)
	}
	linked, errno := g.Open("node_modules/result", uint32(unix.O_RDONLY))
	if errno != 0 {
		t.Fatalf("open linked tmpfile: %v", errno)
	}
	defer unix.Close(linked)
	var st syscall.Stat_t
	if err := syscall.Fstat(linked, &st); err != nil || st.Nlink != 1 {
		t.Fatalf("linked tmpfile stat=(%+v,%v)", st, err)
	}
	buffer := make([]byte, 6)
	if n, err := unix.Pread(linked, buffer, 0); err != nil || n != 6 || string(buffer) != "linked" {
		t.Fatalf("linked tmpfile=(%d,%v,%q)", n, err, buffer)
	}

	exclusive := requireTmpfile(t, g, uint32(unix.O_RDWR|unix.O_EXCL), 0o600)
	defer unix.Close(exclusive)
	if errno := g.LinkTmpfile("node_modules", exclusive, "node_modules/forbidden"); errno == 0 {
		t.Fatal("O_EXCL tmpfile became linkable")
	}
}
