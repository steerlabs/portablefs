package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// benchFS is the workload-facing filesystem surface. The local implementation
// wraps a directory (the baseline); the core implementation drives a clientcore
// volume the way the FUSE frontend does, one logical syscall per call.
type benchFS interface {
	Mkdir(path string) error
	// Create opens a new file for writing (create + open handle).
	Create(path string) (benchFile, error)
	// Open opens an existing file for reading.
	Open(path string) (benchFile, error)
	// Lstat stats a path; exists=false with err=nil is a clean ENOENT.
	Lstat(path string) (size int64, exists bool, err error)
	ReadDir(path string) ([]benchDirent, error)
	// SyncDurable blocks until every write so far is durable at the backing
	// store (authority WAL for core/fuse, fsync for local).
	SyncDurable() error
	// Fresh drops client-side caches (re-attach / remount) so the next reads
	// are cold from the client's perspective. No-op for local (page cache
	// cannot be dropped without privileges; documented caveat).
	Fresh() error
	// RPCCount reports cumulative authority round-trips (0 for local).
	RPCCount() int64
	// Root returns the OS-visible directory for dir-based transports
	// (local/fuse), or "" when the tree is only reachable via the API (core).
	Root() string
	Close() error
}

type benchFile interface {
	WriteAt(p []byte, off int64) error
	ReadAt(p []byte, off int64) (int, error)
	Close() error
}

type benchDirent struct {
	Name  string
	IsDir bool
}

// ---- local: a plain directory (the baseline) ----

type localFS struct {
	root  string
	mu    sync.Mutex
	dirty map[string]struct{} // files written since the last SyncDurable
}

func newLocalFS(root string) *localFS {
	return &localFS{root: root, dirty: map[string]struct{}{}}
}

func (l *localFS) abs(p string) string { return filepath.Join(l.root, filepath.FromSlash(p)) }

func (l *localFS) Mkdir(p string) error { return os.MkdirAll(l.abs(p), 0o755) }

func (l *localFS) Create(p string) (benchFile, error) {
	f, err := os.OpenFile(l.abs(p), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.dirty[l.abs(p)] = struct{}{}
	l.mu.Unlock()
	return localFile{f}, nil
}

func (l *localFS) Open(p string) (benchFile, error) {
	f, err := os.Open(l.abs(p))
	if err != nil {
		return nil, err
	}
	return localFile{f}, nil
}

func (l *localFS) Lstat(p string) (int64, bool, error) {
	fi, err := os.Lstat(l.abs(p))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return fi.Size(), true, nil
}

func (l *localFS) ReadDir(p string) ([]benchDirent, error) {
	ents, err := os.ReadDir(l.abs(p))
	if err != nil {
		return nil, err
	}
	out := make([]benchDirent, 0, len(ents))
	for _, e := range ents {
		out = append(out, benchDirent{Name: e.Name(), IsDir: e.IsDir()})
	}
	return out, nil
}

// SyncDurable fsyncs every file written since the last barrier. This is the
// closest local analogue to "all acked writes durable on the authority". Note
// macOS fsync does not force the platter cache (F_FULLFSYNC would); documented
// in docs/performance.md.
func (l *localFS) SyncDurable() error {
	l.mu.Lock()
	paths := make([]string, 0, len(l.dirty))
	for p := range l.dirty {
		paths = append(paths, p)
	}
	l.dirty = map[string]struct{}{}
	l.mu.Unlock()
	for _, p := range paths {
		f, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		serr := f.Sync()
		_ = f.Close()
		if serr != nil {
			return serr
		}
	}
	return nil
}

func (l *localFS) Fresh() error    { return nil }
func (l *localFS) RPCCount() int64 { return 0 }
func (l *localFS) Root() string    { return l.root }
func (l *localFS) Close() error    { return nil }

type localFile struct{ f *os.File }

func (lf localFile) WriteAt(p []byte, off int64) error {
	_, err := lf.f.WriteAt(p, off)
	return err
}
func (lf localFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := lf.f.ReadAt(p, off)
	if err == io.EOF {
		err = nil
	}
	return n, err
}
func (lf localFile) Close() error { return lf.f.Close() }

// ---- core: clientcore volume over loopback fsproto (no kernel) ----

// coreFS drives a clientcore.Volume with the same op sequence the FUSE
// frontend issues: Lookup for stat, Create+RegisterOpened for create, Open
// before reads, Write/Read with a NodeState, CloseHandle on close. Wall time
// therefore counts the same authority round-trips a mount would make, minus
// kernel/FUSE dispatch (documented).
type coreFS struct {
	addr string
	opts clientcore.Options

	mu     sync.Mutex
	vol    *clientcore.Volume
	cancel context.CancelFunc
}

func newCoreFS(addr string, opts clientcore.Options) (*coreFS, error) {
	c := &coreFS{addr: addr, opts: opts}
	if err := c.attach(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *coreFS) attach() error {
	opts := c.opts
	opts.Addr = c.addr
	if opts.Pool <= 0 {
		opts.Pool = 16
	}
	ctx, cancel := context.WithCancel(context.Background())
	vol, err := clientcore.Dial(ctx, opts)
	if err != nil {
		cancel()
		return err
	}
	go vol.StartInvalidations(ctx, false)
	c.mu.Lock()
	c.vol = vol
	c.cancel = cancel
	c.mu.Unlock()
	return nil
}

func (c *coreFS) volume() *clientcore.Volume {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vol
}

func (c *coreFS) Mkdir(p string) error {
	if _, st := c.volume().Mkdir(context.Background(), p, 0o755); st != fsproto.OK && st != fsproto.EEXIST {
		return fmt.Errorf("mkdir %s: status %d", p, st)
	}
	return nil
}

func (c *coreFS) Create(p string) (benchFile, error) {
	v := c.volume()
	ctx := context.Background()
	// The kernel LOOKUPs a name before issuing CREATE for it; mirror that so
	// negative-lookup caching influences creates exactly as it would via FUSE.
	if _, st := v.Lookup(ctx, p); st != fsproto.OK && st != fsproto.ENOENT {
		return nil, fmt.Errorf("pre-create lookup %s: status %d", p, st)
	}
	a, st := v.Create(ctx, p, 0o644)
	if st != fsproto.OK {
		return nil, fmt.Errorf("create %s: status %d", p, st)
	}
	n := clientcore.NewNodeState(nodeIno(p, a.Ino), a.Ino != 0)
	if st := v.RegisterOpened(ctx, p, n); st != fsproto.OK {
		return nil, fmt.Errorf("register-open %s: status %d", p, st)
	}
	return &coreFile{fs: c, path: p, n: n}, nil
}

func (c *coreFS) Open(p string) (benchFile, error) {
	v := c.volume()
	ctx := context.Background()
	a, st := v.Lookup(ctx, p)
	if st != fsproto.OK {
		return nil, fmt.Errorf("lookup %s: status %d", p, st)
	}
	n := clientcore.NewNodeState(nodeIno(p, a.Ino), a.Ino != 0)
	if st := v.Open(ctx, p, n, false); st != fsproto.OK {
		return nil, fmt.Errorf("open %s: status %d", p, st)
	}
	return &coreFile{fs: c, path: p, n: n}, nil
}

func (c *coreFS) Lstat(p string) (int64, bool, error) {
	a, st := c.volume().Lookup(context.Background(), p)
	switch st {
	case fsproto.OK:
		return a.Size, true, nil
	case fsproto.ENOENT:
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("lstat %s: status %d", p, st)
	}
}

func (c *coreFS) ReadDir(p string) ([]benchDirent, error) {
	ents, st := c.volume().Readdir(context.Background(), p)
	if st != fsproto.OK {
		return nil, fmt.Errorf("readdir %s: status %d", p, st)
	}
	out := make([]benchDirent, 0, len(ents))
	for _, e := range ents {
		out = append(out, benchDirent{Name: e.Name, IsDir: e.Attr.Kind == "directory"})
	}
	return out, nil
}

func (c *coreFS) SyncDurable() error {
	return c.volume().FlushToAuthority(context.Background())
}

// Fresh re-attaches: a clean Close (flush + checkin) then a new dial with cold
// attr/version/dir caches — the client-side equivalent of a fresh mount.
func (c *coreFS) Fresh() error {
	c.mu.Lock()
	vol, cancel := c.vol, c.cancel
	c.vol, c.cancel = nil, nil
	c.mu.Unlock()
	if vol != nil {
		cancel()
		if err := vol.Close(); err != nil {
			return err
		}
	}
	return c.attach()
}

func (c *coreFS) RPCCount() int64 {
	return c.volume().Metrics.Counter("authority_ops_total").Value()
}

func (c *coreFS) Root() string { return "" }

func (c *coreFS) Close() error {
	c.mu.Lock()
	vol, cancel := c.vol, c.cancel
	c.vol, c.cancel = nil, nil
	c.mu.Unlock()
	if vol == nil {
		return nil
	}
	cancel()
	return vol.Close()
}

func nodeIno(p string, ino uint64) uint64 {
	if ino != 0 {
		return ino
	}
	return clientcore.InoOf(p)
}

type coreFile struct {
	fs   *coreFS
	path string
	n    *clientcore.NodeState
}

func (cf *coreFile) WriteAt(p []byte, off int64) error {
	v := cf.fs.volume()
	// Mirror the kernel's MaxWrite: a large logical write arrives as <=1MiB ops.
	const chunk = 1 << 20
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		w, st := v.Write(context.Background(), cf.path, cf.n, off, p[:n])
		if st != fsproto.OK {
			return fmt.Errorf("write %s@%d: status %d", cf.path, off, st)
		}
		p = p[w:]
		off += int64(w)
	}
	return nil
}

func (cf *coreFile) ReadAt(p []byte, off int64) (int, error) {
	v := cf.fs.volume()
	const chunk = 1 << 20
	total := 0
	for total < len(p) {
		want := len(p) - total
		if want > chunk {
			want = chunk
		}
		data, st := v.Read(context.Background(), cf.path, cf.n, off+int64(total), want)
		if st != fsproto.OK {
			return total, fmt.Errorf("read %s@%d: status %d", cf.path, off+int64(total), st)
		}
		copy(p[total:], data)
		total += len(data)
		if len(data) < want {
			break // EOF
		}
	}
	return total, nil
}

func (cf *coreFile) Close() error {
	cf.fs.volume().CloseHandle(cf.path, cf.n)
	return nil
}
