// Package volfs presents a committed volume manifest as a read-only
// billy.Filesystem that go-nfs can serve. Reads are lazy and cached via the
// shared content package: a large chunked file only pulls the chunks read.
package volfs

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
)

// errReadOnly is returned for any mutating operation.
var errReadOnly = errors.New("vcs: read-only filesystem")

type node struct {
	name       string
	kind       string // "file" | "directory" | "symlink"
	mode       os.FileMode
	size       int64
	mtime      time.Time
	ctime      time.Time
	atime      time.Time
	uid        uint32
	gid        uint32
	linkTarget string
	blobDigest string
	chunks     []backend.Chunk
	children   map[string]*node
}

// FS is a read-only billy.Filesystem backed by a manifest + blob store.
type FS struct {
	root  *node
	blobs content.BlobReader
	cache content.Cache
}

var _ billy.Filesystem = (*FS)(nil)

// New builds an FS from manifest entries with a default in-memory cache.
func New(entries []backend.Entry, blobs content.BlobReader) *FS {
	return NewWithCache(entries, blobs, content.NewCache(256<<20)) // 256 MiB
}

// NewWithCache is New with a caller-provided content cache (e.g. a disk-backed
// tier).
func NewWithCache(entries []backend.Entry, blobs content.BlobReader, cache content.Cache) *FS {
	now := time.Now()
	fs := &FS{
		root:  &node{name: "", kind: "directory", mode: os.ModeDir | 0o755, mtime: now, ctime: now, atime: now, children: map[string]*node{}},
		blobs: blobs,
		cache: cache,
	}
	sorted := append([]backend.Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, e := range sorted {
		fs.insert(e)
	}
	return fs
}

func entryMode(e backend.Entry) os.FileMode {
	m := modebits.FromUnix(e.Mode)
	switch e.Kind {
	case "directory":
		m |= os.ModeDir
	case "symlink":
		m |= os.ModeSymlink
	}
	return m
}

func manifestTimes(mtimeMs, ctimeMs, atimeMs int64) (mtime, ctime, atime time.Time) {
	mtime = time.UnixMilli(mtimeMs)
	ctime = time.UnixMilli(ctimeMs)
	if ctimeMs == 0 {
		ctime = mtime
	}
	atime = time.UnixMilli(atimeMs)
	if atimeMs == 0 {
		atime = mtime
	}
	return
}

func (fs *FS) insert(e backend.Entry) {
	clean := strings.Trim(path.Clean("/"+e.Path), "/")
	if clean == "" {
		return
	}
	parts := strings.Split(clean, "/")
	cur := fs.root
	for i, part := range parts {
		if cur.children == nil {
			cur.children = map[string]*node{}
		}
		child, ok := cur.children[part]
		if !ok {
			child = &node{name: part, kind: "directory", mode: os.ModeDir | 0o755, children: map[string]*node{}}
			cur.children[part] = child
		}
		if i == len(parts)-1 {
			child.kind = e.Kind
			child.mode = entryMode(e)
			child.size = e.Size
			child.mtime, child.ctime, child.atime = manifestTimes(e.MtimeMs, e.CtimeMs, e.AtimeMs)
			child.uid = e.UID
			child.gid = e.GID
			child.linkTarget = e.LinkTarget
			child.blobDigest = e.BlobDigest
			child.chunks = e.Chunks
			if e.Kind == "directory" && child.children == nil {
				child.children = map[string]*node{}
			}
		}
		cur = child
	}
}

func cleanPath(name string) string {
	return strings.Trim(path.Clean("/"+name), "/")
}

func (fs *FS) resolve(name string) *node {
	clean := cleanPath(name)
	if clean == "" {
		return fs.root
	}
	cur := fs.root
	for _, part := range strings.Split(clean, "/") {
		next, ok := cur.children[part]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func (fs *FS) readRange(n *node, p []byte, off int64) (int, error) {
	if n.kind != "file" {
		return 0, io.EOF
	}
	return content.ReadAt(fs.blobs, fs.cache,
		content.Source{BlobDigest: n.blobDigest, Chunks: n.chunks, Size: n.size}, p, off)
}

// ---- os.FileInfo ----

type fileInfo struct{ n *node }

func (fi fileInfo) Name() string               { return fi.n.name }
func (fi fileInfo) Size() int64                { return fi.n.size }
func (fi fileInfo) Mode() os.FileMode          { return fi.n.mode }
func (fi fileInfo) ModTime() time.Time         { return fi.n.mtime }
func (fi fileInfo) IsDir() bool                { return fi.n.kind == "directory" }
func (fi fileInfo) ChangeTime() time.Time      { return fi.n.ctime }
func (fi fileInfo) AccessTime() time.Time      { return fi.n.atime }
func (fi fileInfo) OwnerIDs() (uint32, uint32) { return fi.n.uid, fi.n.gid }
func (fi fileInfo) Sys() any                   { return fi } // exposes OwnerIDs to the FUSE layer

// ---- billy.File ----

type file struct {
	fs   *FS
	n    *node
	name string
	pos  int64
}

func (f *file) Name() string { return f.name }

func (f *file) Read(p []byte) (int, error) {
	nr, err := f.fs.readRange(f.n, p, f.pos)
	f.pos += int64(nr)
	return nr, err
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	return f.fs.readRange(f.n, p, off)
}

func (f *file) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.pos = offset
	case io.SeekCurrent:
		f.pos += offset
	case io.SeekEnd:
		f.pos = f.n.size + offset
	default:
		return 0, os.ErrInvalid
	}
	if f.pos < 0 {
		f.pos = 0
	}
	return f.pos, nil
}

func (f *file) Write([]byte) (int, error) { return 0, errReadOnly }
func (f *file) Close() error              { return nil }
func (f *file) Lock() error               { return nil }
func (f *file) Unlock() error             { return nil }
func (f *file) Truncate(int64) error      { return errReadOnly }

// ---- billy.Filesystem (read-only) ----

func (fs *FS) Open(filename string) (billy.File, error) {
	return fs.OpenFile(filename, os.O_RDONLY, 0)
}

func (fs *FS) OpenFile(filename string, flag int, _ os.FileMode) (billy.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, errReadOnly
	}
	n := fs.resolve(filename)
	if n == nil {
		return nil, os.ErrNotExist
	}
	return &file{fs: fs, n: n, name: filename}, nil
}

func (fs *FS) Stat(filename string) (os.FileInfo, error) { return fs.Lstat(filename) }

func (fs *FS) Lstat(filename string) (os.FileInfo, error) {
	n := fs.resolve(filename)
	if n == nil {
		return nil, os.ErrNotExist
	}
	return fileInfo{n}, nil
}

func (fs *FS) ReadDir(p string) ([]os.FileInfo, error) {
	n := fs.resolve(p)
	if n == nil {
		return nil, os.ErrNotExist
	}
	if n.kind != "directory" {
		return nil, errors.New("vcs: not a directory")
	}
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]os.FileInfo, 0, len(names))
	for _, name := range names {
		out = append(out, fileInfo{n.children[name]})
	}
	return out, nil
}

func (fs *FS) Readlink(link string) (string, error) {
	n := fs.resolve(link)
	if n == nil {
		return "", os.ErrNotExist
	}
	if n.kind != "symlink" {
		return "", errors.New("vcs: not a symlink")
	}
	return n.linkTarget, nil
}

func (fs *FS) Join(elem ...string) string { return path.Join(elem...) }
func (fs *FS) Root() string               { return "/" }

func (fs *FS) Chroot(p string) (billy.Filesystem, error) {
	n := fs.resolve(p)
	if n == nil {
		return nil, os.ErrNotExist
	}
	if n.kind != "directory" {
		return nil, errors.New("vcs: not a directory")
	}
	return &FS{root: n, blobs: fs.blobs, cache: fs.cache}, nil
}

func (fs *FS) Capabilities() billy.Capability {
	return billy.ReadCapability | billy.SeekCapability
}

// Mutating operations — unsupported (read-only).
func (fs *FS) Create(string) (billy.File, error)           { return nil, errReadOnly }
func (fs *FS) Rename(string, string) error                 { return errReadOnly }
func (fs *FS) Remove(string) error                         { return errReadOnly }
func (fs *FS) TempFile(string, string) (billy.File, error) { return nil, errReadOnly }
func (fs *FS) MkdirAll(string, os.FileMode) error          { return errReadOnly }
func (fs *FS) Symlink(string, string) error                { return errReadOnly }
