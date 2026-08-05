package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// An actor performs POSIX operations against one mount of the volume under
// test. Every case in the matrix is written against this interface alone, so
// exactly the same case body runs when both mounts are on this machine (two
// FUSE mounts of one authority, or two FSKit mounts of one volume) and when the
// second mount lives on another machine reached over ssh. That is what makes a
// Linux result and a macOS result directly comparable rather than two
// independently written suites that happen to share vocabulary.
type actor interface {
	name() string
	exec(request) (response, error)
	close() error
}

// request and response are the complete operation vocabulary. They are JSON so
// the remote actor is the same program in --agent mode on the far side of an
// ssh pipe, executing byte-identical code paths to the local actor.
type request struct {
	Op string `json:"op"`
	// Path is always relative to the actor's mount root. An absolute path or
	// any component that escapes the root is refused by the agent, because a
	// harness that can write outside the volume can report a pass it did not
	// earn.
	Path    string   `json:"path,omitempty"`
	To      string   `json:"to,omitempty"`
	Data    []byte   `json:"data,omitempty"`
	Off     int64    `json:"off,omitempty"`
	Len     int      `json:"len,omitempty"`
	Size    int64    `json:"size,omitempty"`
	Mode    uint32   `json:"mode,omitempty"`
	Flags   []string `json:"flags,omitempty"`
	Handle  int      `json:"handle,omitempty"`
	UID     int      `json:"uid,omitempty"`
	GID     int      `json:"gid,omitempty"`
	AtimeNs int64    `json:"atime_ns,omitempty"`
	MtimeNs int64    `json:"mtime_ns,omitempty"`
	Count   int      `json:"count,omitempty"`
	Tag     string   `json:"tag,omitempty"`
	Fill    byte     `json:"fill,omitempty"`
}

type response struct {
	Err    string    `json:"err,omitempty"`
	Errno  int       `json:"errno,omitempty"`
	Data   []byte    `json:"data,omitempty"`
	Names  []string  `json:"names,omitempty"`
	Stat   *statInfo `json:"stat,omitempty"`
	Handle int       `json:"handle,omitempty"`
	N      int       `json:"n,omitempty"`
	Str    string    `json:"str,omitempty"`
}

type statInfo struct {
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	Perm    uint32 `json:"perm"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Ino     uint64 `json:"ino"`
	Nlink   uint64 `json:"nlink"`
	MtimeNs int64  `json:"mtime_ns"`
	AtimeNs int64  `json:"atime_ns"`
	IsDir   bool   `json:"is_dir"`
	IsLink  bool   `json:"is_link"`
}

func (s *statInfo) String() string {
	return fmt.Sprintf("{ino=%d size=%d perm=%04o nlink=%d uid=%d gid=%d mtime=%d dir=%t link=%t}",
		s.Ino, s.Size, s.Perm, s.Nlink, s.UID, s.GID, s.MtimeNs, s.IsDir, s.IsLink)
}

// ---------------------------------------------------------------------------
// local actor
// ---------------------------------------------------------------------------

type localActor struct {
	label   string
	root    string
	mu      sync.Mutex
	handles map[int]*os.File
	nextID  int
}

func newLocalActor(label, root string) (*localActor, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("mount root %s: %w", absolute, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("mount root %s is not a directory", absolute)
	}
	return &localActor{label: label, root: absolute, handles: map[int]*os.File{}, nextID: 1}, nil
}

func (a *localActor) name() string { return a.label }

func (a *localActor) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, file := range a.handles {
		_ = file.Close()
		delete(a.handles, id)
	}
	return nil
}

func (a *localActor) resolve(relative string) (string, error) {
	if relative == "" {
		return a.root, nil
	}
	if filepath.IsAbs(relative) {
		return "", fmt.Errorf("path %q must be relative to the mount root", relative)
	}
	joined := filepath.Join(a.root, relative)
	if joined != a.root && !strings.HasPrefix(joined, a.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the mount root", relative)
	}
	return joined, nil
}

func (a *localActor) exec(req request) (response, error) {
	out, err := a.execute(req)
	if err != nil {
		return response{Err: err.Error(), Errno: errnoOf(err)}, nil
	}
	return out, nil
}

func (a *localActor) put(file *os.File) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := a.nextID
	a.nextID++
	a.handles[id] = file
	return id
}

func (a *localActor) get(id int) (*os.File, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	file, ok := a.handles[id]
	if !ok {
		return nil, fmt.Errorf("unknown handle %d", id)
	}
	return file, nil
}

func (a *localActor) drop(id int) (*os.File, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	file, ok := a.handles[id]
	if !ok {
		return nil, fmt.Errorf("unknown handle %d", id)
	}
	delete(a.handles, id)
	return file, nil
}

const recordSize = 64

// record is the fixed-width unit used by every concurrency case. Fixed width is
// what lets an append case assert that each record survived intact and exactly
// once instead of merely checking a final size.
func record(tag string, index int) []byte {
	line := fmt.Sprintf("%s-%08d", tag, index)
	if len(line) > recordSize-1 {
		line = line[:recordSize-1]
	}
	buffer := make([]byte, recordSize)
	copy(buffer, line)
	for i := len(line); i < recordSize-1; i++ {
		buffer[i] = '.'
	}
	buffer[recordSize-1] = '\n'
	return buffer
}

func (a *localActor) execute(req request) (response, error) {
	path, err := a.resolve(req.Path)
	if err != nil {
		return response{}, err
	}
	switch req.Op {
	case "ping":
		return response{Str: a.root}, nil
	case "mkdirall":
		return response{}, os.MkdirAll(path, os.FileMode(req.Mode))
	case "mkdir":
		return response{}, os.Mkdir(path, os.FileMode(req.Mode))
	case "removeall":
		return response{}, os.RemoveAll(path)
	case "remove":
		return response{}, os.Remove(path)
	case "writefile":
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(req.Mode))
		if err != nil {
			return response{}, err
		}
		if _, err := file.Write(req.Data); err != nil {
			_ = file.Close()
			return response{}, err
		}
		return response{}, file.Close()
	case "readfile":
		// Deliberately read through an open descriptor to EOF rather than
		// os.ReadFile, so the assertion is on bytes the kernel actually
		// returned and never on a size stat.
		file, err := os.Open(path)
		if err != nil {
			return response{}, err
		}
		data, err := readToEOF(file)
		closeErr := file.Close()
		if err != nil {
			return response{}, err
		}
		return response{Data: data}, closeErr
	case "stat":
		info, err := os.Stat(path)
		if err != nil {
			return response{}, err
		}
		return response{Stat: describe(info)}, nil
	case "lstat":
		info, err := os.Lstat(path)
		if err != nil {
			return response{}, err
		}
		return response{Stat: describe(info)}, nil
	case "readdir":
		entries, err := os.ReadDir(path)
		if err != nil {
			return response{}, err
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return response{Names: names}, nil
	case "rename":
		to, err := a.resolve(req.To)
		if err != nil {
			return response{}, err
		}
		return response{}, os.Rename(path, to)
	case "chmod":
		return response{}, os.Chmod(path, os.FileMode(req.Mode))
	case "chown":
		return response{}, os.Chown(path, req.UID, req.GID)
	case "utimes":
		return response{}, os.Chtimes(path, time.Unix(0, req.AtimeNs), time.Unix(0, req.MtimeNs))
	case "truncate":
		return response{}, os.Truncate(path, req.Size)
	case "symlink":
		return response{}, os.Symlink(req.To, path)
	case "readlink":
		target, err := os.Readlink(path)
		if err != nil {
			return response{}, err
		}
		return response{Str: target}, nil
	case "link":
		to, err := a.resolve(req.To)
		if err != nil {
			return response{}, err
		}
		return response{}, os.Link(path, to)
	case "open":
		flags, err := openFlags(req.Flags)
		if err != nil {
			return response{}, err
		}
		file, err := os.OpenFile(path, flags, os.FileMode(req.Mode))
		if err != nil {
			return response{}, err
		}
		return response{Handle: a.put(file)}, nil
	case "pread":
		file, err := a.get(req.Handle)
		if err != nil {
			return response{}, err
		}
		buffer := make([]byte, req.Len)
		n, err := file.ReadAt(buffer, req.Off)
		if err != nil && !errors.Is(err, io.EOF) {
			return response{}, err
		}
		return response{Data: buffer[:n], N: n}, nil
	case "readall":
		// The single most important primitive in this harness: how many bytes
		// are actually readable, independent of what stat reports.
		file, err := a.get(req.Handle)
		if err != nil {
			return response{}, err
		}
		data, err := readToEOF(file)
		if err != nil {
			return response{}, err
		}
		return response{Data: data, N: len(data)}, nil
	case "pwrite":
		file, err := a.get(req.Handle)
		if err != nil {
			return response{}, err
		}
		n, err := file.WriteAt(req.Data, req.Off)
		return response{N: n}, err
	case "fstat":
		file, err := a.get(req.Handle)
		if err != nil {
			return response{}, err
		}
		info, err := file.Stat()
		if err != nil {
			return response{}, err
		}
		return response{Stat: describe(info)}, nil
	case "fsync":
		file, err := a.get(req.Handle)
		if err != nil {
			return response{}, err
		}
		return response{}, file.Sync()
	case "closehandle":
		file, err := a.drop(req.Handle)
		if err != nil {
			return response{}, err
		}
		return response{}, file.Close()
	case "burst_create":
		for i := range req.Count {
			target := filepath.Join(path, fmt.Sprintf("%s-%08d", req.Tag, i))
			if err := os.WriteFile(target, record(req.Tag, i), 0o644); err != nil {
				return response{N: i}, err
			}
		}
		return response{N: req.Count}, nil
	case "burst_churn":
		// One mount's half of a same-directory mutation storm: every iteration
		// creates a name, renames it within the SAME directory, and unlinks half
		// of what it renamed. Create/rename/unlink in one directory is exactly
		// what contends the directory inode lock, so this is the operation that
		// makes a cross-mount i_rwsem deadlock reproducible instead of theoretical.
		//
		// The surviving set is deterministic - the even-numbered renamed names -
		// so the case can assert the exact entries both mounts enumerate
		// afterwards rather than merely that nothing crashed.
		upper := strings.ToUpper(req.Tag)
		for i := range req.Count {
			created := filepath.Join(path, fmt.Sprintf("%s-%08d", req.Tag, i))
			renamed := filepath.Join(path, fmt.Sprintf("%s-%08d", upper, i))
			if err := os.WriteFile(created, record(req.Tag, i), 0o644); err != nil {
				return response{N: i}, err
			}
			if err := os.Rename(created, renamed); err != nil {
				return response{N: i}, err
			}
			if i%2 == 1 {
				if err := os.Remove(renamed); err != nil {
					return response{N: i}, err
				}
			}
		}
		return response{N: req.Count}, nil
	case "burst_append":
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return response{}, err
		}
		for i := range req.Count {
			if _, err := file.Write(record(req.Tag, i)); err != nil {
				_ = file.Close()
				return response{N: i}, err
			}
		}
		return response{N: req.Count}, file.Close()
	case "burst_overwrite":
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return response{}, err
		}
		payload := make([]byte, req.Size)
		for i := range payload {
			payload[i] = req.Fill
		}
		for range req.Count {
			if _, err := file.WriteAt(payload, 0); err != nil {
				_ = file.Close()
				return response{}, err
			}
		}
		return response{N: req.Count}, file.Close()
	case "atomic_replace":
		// create temp -> write -> fsync -> rename over the target. This is the
		// exact sequence editors, compilers and package managers use, and the
		// one that failed 0/20 on the hand-run macOS matrix.
		temp := path + ".tmp"
		file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(req.Mode))
		if err != nil {
			return response{}, err
		}
		if _, err := file.Write(req.Data); err != nil {
			_ = file.Close()
			return response{}, err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return response{}, err
		}
		if err := file.Close(); err != nil {
			return response{}, err
		}
		if err := os.Rename(temp, path); err != nil {
			return response{}, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return response{}, err
		}
		return response{Stat: describe(info)}, nil
	case "run":
		// Used only by the harness itself (for example to fence a mount).
		command := exec.Command("/bin/sh", "-c", req.Tag)
		output, err := command.CombinedOutput()
		return response{Str: string(output)}, err
	default:
		return response{}, fmt.Errorf("unknown op %q", req.Op)
	}
}

// readToEOF reads a descriptor from offset 0 to end of file. It never consults
// stat: the returned length is the readable EOF, which has been observed to
// disagree with a cached size.
func readToEOF(file *os.File) ([]byte, error) {
	var (
		out    []byte
		buffer = make([]byte, 1<<16)
		offset int64
	)
	for {
		n, err := file.ReadAt(buffer, offset)
		out = append(out, buffer[:n]...)
		offset += int64(n)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if n == 0 {
			return out, nil
		}
	}
}

func openFlags(names []string) (int, error) {
	flags := 0
	mode := 0
	sawMode := false
	for _, name := range names {
		switch name {
		case "rdonly":
			mode, sawMode = os.O_RDONLY, true
		case "wronly":
			mode, sawMode = os.O_WRONLY, true
		case "rdwr":
			mode, sawMode = os.O_RDWR, true
		case "create":
			flags |= os.O_CREATE
		case "excl":
			flags |= os.O_EXCL
		case "trunc":
			flags |= os.O_TRUNC
		case "append":
			flags |= os.O_APPEND
		default:
			return 0, fmt.Errorf("unknown open flag %q", name)
		}
	}
	if !sawMode {
		mode = os.O_RDONLY
	}
	return mode | flags, nil
}

func errnoOf(err error) int {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}

// ---------------------------------------------------------------------------
// remote actor
// ---------------------------------------------------------------------------

// remoteActor drives this same program running as --agent on another host,
// reached over ssh. The case bodies cannot tell the difference, which is the
// point: a two-machine run and a one-machine run execute the same assertions.
type remoteActor struct {
	label   string
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	mu      sync.Mutex
}

func newRemoteActor(label, sshTarget, remoteBinary, root string, sshOptions []string) (*remoteActor, error) {
	arguments := append([]string{}, sshOptions...)
	arguments = append(arguments, sshTarget, remoteBinary, "--agent", "--root", root)
	command := exec.Command("ssh", arguments...)
	command.Stderr = os.Stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	actor := &remoteActor{label: label, command: command, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<20)}
	pong, err := actor.exec(request{Op: "ping"})
	if err != nil {
		return nil, fmt.Errorf("remote agent handshake: %w", err)
	}
	if pong.Err != "" {
		return nil, fmt.Errorf("remote agent handshake: %s", pong.Err)
	}
	return actor, nil
}

func (a *remoteActor) name() string { return a.label }

func (a *remoteActor) exec(req request) (response, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	encoded, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if _, err := a.stdin.Write(append(encoded, '\n')); err != nil {
		return response{}, err
	}
	line, err := a.stdout.ReadBytes('\n')
	if err != nil {
		return response{}, fmt.Errorf("remote agent ended: %w", err)
	}
	var out response
	if err := json.Unmarshal(line, &out); err != nil {
		return response{}, fmt.Errorf("remote agent reply: %w", err)
	}
	return out, nil
}

func (a *remoteActor) close() error {
	_ = a.stdin.Close()
	return a.command.Wait()
}

// runAgent serves the operation vocabulary on stdin/stdout for a remote driver.
func runAgent(root string) error {
	local, err := newLocalActor("agent", root)
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	writer := bufio.NewWriterSize(os.Stdout, 1<<20)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && errors.Is(err, io.EOF) {
			return writer.Flush()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		var req request
		var out response
		if decodeErr := json.Unmarshal(line, &req); decodeErr != nil {
			out = response{Err: decodeErr.Error()}
		} else {
			out, _ = local.exec(req)
		}
		encoded, encodeErr := json.Marshal(out)
		if encodeErr != nil {
			encoded, _ = json.Marshal(response{Err: encodeErr.Error()})
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}
