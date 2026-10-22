//go:build linux

// Package workspaceadmission owns the supervisor's synchronous serving cut.
// A close prevents new admissions; joining already admitted work belongs to the
// frontend lifecycle owner. The shared page never substitutes for that join.
package workspaceadmission

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"golang.org/x/sys/unix"
)

const Format = 8
const wordOffset = 128
const requiredSeals = unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_SEAL

var ErrClosed = errors.New("workspace admission: closed or obsolete permit")

// Binding is immutable for one child. Service IDs and incarnation are the exact
// 128-bit identities used by paired workspace control, never filesystem names.
type Binding struct {
	Boot, HostService, GuestService, Incarnation [16]byte
	SupervisorPID                                int32
	SupervisorStart                              uint64
}

func (b Binding) header() ([]byte, error) {
	if b.Boot == [16]byte{} || b.HostService == [16]byte{} || b.GuestService == [16]byte{} || b.Incarnation == [16]byte{} || b.SupervisorPID <= 0 || b.SupervisorStart == 0 {
		return nil, errors.New("workspace admission: incomplete binding")
	}
	h := make([]byte, wordOffset)
	copy(h, "PFS-GATE")
	binary.LittleEndian.PutUint32(h[8:], Format)
	binary.LittleEndian.PutUint32(h[12:], uint32(os.Getpagesize()))
	copy(h[16:], b.Boot[:])
	copy(h[32:], b.HostService[:])
	copy(h[48:], b.GuestService[:])
	copy(h[64:], b.Incarnation[:])
	binary.LittleEndian.PutUint32(h[80:], uint32(b.SupervisorPID))
	binary.LittleEndian.PutUint64(h[88:], b.SupervisorStart)
	return h, nil
}

type Supervisor struct {
	mu                   sync.Mutex
	binding              Binding
	page                 []byte
	word                 *atomic.Uint64
	file, reader, writer *os.File
	generation           uint64
	prepared             *RecoveryPermit
	exhausted            bool
	finalSerial          uint64
}

// New is root-only. All descriptors start CLOEXEC. ChildFiles transfers only a
// separate read-only open description and the lifetime reader to an exec owner.
func New(binding Binding) (_ *Supervisor, err error) {
	h, err := binding.header()
	if err != nil {
		return nil, err
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil || binding.SupervisorPID != int32(os.Getpid()) || binding.SupervisorStart != start || os.Geteuid() != 0 {
		return nil, errors.New("workspace admission: exact root supervisor required")
	}
	fd, err := unix.MemfdCreate("portablefs-workspace-gate", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("create admission page: %w", err)
	}
	g := &Supervisor{binding: binding, file: os.NewFile(uintptr(fd), "workspace-gate")}
	defer func() {
		if err != nil {
			_ = g.Dispose()
		}
	}()
	if err = unix.Fchmod(fd, 0400); err != nil {
		return nil, fmt.Errorf("restrict admission inode: %w", err)
	}
	if err = unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		return nil, fmt.Errorf("size admission inode: %w", err)
	}
	if g.page, err = unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
		return nil, fmt.Errorf("map supervisor admission word: %w", err)
	}
	copy(g.page, h)
	g.word = (*atomic.Uint64)(unsafe.Pointer(&g.page[wordOffset]))
	// Zero is the initial closed serial. The only writable mapping predates the
	// seals; all subsequent write syscalls and writable mappings are refused.
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, requiredSeals); err != nil {
		return nil, fmt.Errorf("seal admission page: %w", err)
	}
	if g.reader, g.writer, err = os.Pipe(); err != nil {
		return nil, fmt.Errorf("create supervisor lifetime: %w", err)
	}
	return g, nil
}

func (g *Supervisor) ChildFiles() (_ [2]*os.File, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reader == nil || g.file == nil {
		return [2]*os.File{}, errors.New("workspace admission: handoff already consumed")
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", g.file.Fd()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return [2]*os.File{}, fmt.Errorf("open read-only gate: %w", err)
	}
	files := [2]*os.File{os.NewFile(uintptr(fd), "workspace-gate-reader"), g.reader}
	g.reader = nil
	return files, nil
}

// Close's store is the linearization point. It has no I/O, joins or child
// dependencies, including when the child is stopped in a physical reply.
func (g *Supervisor) Close(generation uint64) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.word == nil {
		return g.finalSerial
	}
	g.generation = max(g.generation, generation)
	g.prepared = nil
	serial := g.word.Load() >> 1
	if serial == math.MaxUint64>>1 {
		g.exhausted = true
	} else {
		serial++
	}
	// The last closed word is terminal in both processes. Reserving it prevents
	// another Close from matching an earlier recovery permit at exhaustion.
	if serial == math.MaxUint64>>1 {
		g.exhausted = true
	}
	g.word.Store(serial << 1)
	return serial
}

// RecoveryPermit is a closed-start authorization, not serving permission.
// Fields are private so callers cannot invent proofs or change their binding.
type RecoveryPermit struct {
	binding          Binding
	word, generation uint64
}

func (p RecoveryPermit) Serial() uint64     { return p.word >> 1 }
func (p RecoveryPermit) Generation() uint64 { return p.generation }
func (g *Supervisor) Recovery(generation uint64) (RecoveryPermit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.word == nil {
		return RecoveryPermit{}, ErrClosed
	}
	word := g.word.Load()
	if g.exhausted || word>>1 == math.MaxUint64>>1 || word&1 != 0 || generation == 0 || generation < g.generation {
		return RecoveryPermit{}, ErrClosed
	}
	g.generation = generation
	return RecoveryPermit{g.binding, word, generation}, nil
}

// Prepared retains only the current proof after the caller has established real
// readiness. This primitive supplies no synthetic readiness or mount driver.
func (g *Supervisor) Prepared(p RecoveryPermit) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.word == nil || g.exhausted || p.binding != g.binding || p.generation != g.generation || p.word != g.word.Load() || p.word&1 != 0 {
		return ErrClosed
	}
	g.prepared = &p
	return nil
}
func (g *Supervisor) Open(generation, serial uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.prepared
	if g.word == nil || g.exhausted || p == nil || p.generation != generation || p.generation != g.generation || p.Serial() != serial || !g.word.CompareAndSwap(p.word, p.word|1) {
		return ErrClosed
	}
	g.prepared = nil
	return nil
}

// Dispose retires the parent mapping and sole pipe writer. Call after the root
// no longer needs to close admission; EOF can be observed later by a descheduled
// child and is deliberately not claimed as an instantaneous death barrier.
func (g *Supervisor) Dispose() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.word != nil {
		serial := g.word.Load() >> 1
		if serial < math.MaxUint64>>1 {
			serial++
		}
		g.word.Store(serial << 1)
		g.finalSerial = serial
		g.word = nil
	}
	g.exhausted = true
	g.prepared = nil
	var errs []error
	if g.page != nil {
		errs = append(errs, unix.Munmap(g.page))
		g.page = nil
	}
	for _, f := range []*os.File{g.file, g.reader, g.writer} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	g.file, g.reader, g.writer = nil, nil, nil
	return errors.Join(errs...)
}

type Reader struct {
	binding Binding
	page    []byte
	word    *atomic.Uint64
	dead    atomic.Bool
	owner   *os.File
	done    chan struct{}
}
type ServingPermit struct {
	reader *Reader
	word   uint64
}

func (p ServingPermit) Check() error {
	if p.reader == nil || p.word>>1 == math.MaxUint64>>1 || p.word&1 == 0 || p.reader.dead.Load() || p.reader.word.Load() != p.word {
		return ErrClosed
	}
	return nil
}

// Adopt takes both descriptors on every outcome. EOF permanently latches this
// child closed before invoking teardown, independently of any command lane.
func Adopt(gate, owner *os.File, binding Binding, teardown func()) (_ *Reader, err error) {
	if gate == nil || owner == nil {
		if gate != nil {
			_ = gate.Close()
		}
		if owner != nil {
			_ = owner.Close()
		}
		return nil, errors.New("workspace admission: both descriptors required")
	}
	defer gate.Close()
	defer func() {
		if err != nil {
			_ = owner.Close()
		}
	}()
	h, err := binding.header()
	if err != nil {
		return nil, err
	}
	start, err := mountcontrol.ProcessStart(binding.SupervisorPID)
	var supervisor unix.Stat_t
	if err != nil || start != binding.SupervisorStart || unix.Stat(fmt.Sprintf("/proc/%d", binding.SupervisorPID), &supervisor) != nil || supervisor.Uid != 0 {
		return nil, errors.New("workspace admission: obsolete supervisor identity")
	}
	fd := int(gate.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("workspace admission: writable gate descriptor refused")
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals != requiredSeals {
		return nil, errors.New("workspace admission: incomplete descriptor seals")
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Size != int64(os.Getpagesize()) || st.Uid != 0 || st.Mode&0777 != 0400 {
		return nil, errors.New("workspace admission: invalid gate size/owner/mode")
	}
	var pipe unix.Stat_t
	if err = unix.Fstat(int(owner.Fd()), &pipe); err != nil {
		return nil, err
	}
	mode, err := unix.FcntlInt(owner.Fd(), unix.F_GETFL, 0)
	if err != nil || pipe.Mode&unix.S_IFMT != unix.S_IFIFO || mode&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("workspace admission: owner must be a pipe reader")
	}
	unix.CloseOnExec(fd)
	// Inherited descriptors may be in blocking mode. Construct the File only
	// after O_NONBLOCK is set so Go registers the pipe with its poller; Close
	// must interrupt this reader even while the live supervisor retains a writer.
	pipeFD, err := unix.FcntlInt(owner.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate lifetime reader: %w", err)
	}
	if err = unix.SetNonblock(pipeFD, true); err != nil {
		_ = unix.Close(pipeFD)
		return nil, fmt.Errorf("make lifetime reader pollable: %w", err)
	}
	_ = owner.Close()
	owner = os.NewFile(uintptr(pipeFD), "workspace-owner-reader")
	page, err := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(page[:wordOffset], h) {
		_ = unix.Munmap(page)
		return nil, errors.New("workspace admission: header binding mismatch")
	}
	r := &Reader{binding: binding, page: page, word: (*atomic.Uint64)(unsafe.Pointer(&page[wordOffset])), owner: owner, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		var b [1]byte
		// No valid owner writes data. Data, read failure and EOF all take terminal
		// cleanup; no control handler or later supervisor can unlatch this reader.
		_, _ = owner.Read(b[:])
		r.dead.Store(true)
		if teardown != nil {
			teardown()
		}
	}()
	return r, nil
}
func (r *Reader) Check() (ServingPermit, error) {
	if r.dead.Load() {
		return ServingPermit{}, ErrClosed
	}
	word := r.word.Load()
	p := ServingPermit{r, word}
	return p, p.Check()
}
func (r *Reader) Recover(p RecoveryPermit) error {
	if r.dead.Load() || p.Serial() == math.MaxUint64>>1 || p.binding != r.binding || p.generation == 0 || p.word&1 != 0 || r.word.Load() != p.word {
		return ErrClosed
	}
	return nil
}
func (r *Reader) Done() <-chan struct{} { return r.done }

// Retire joins the independent watcher before unmapping. Frontend owners must
// join their readers before calling this; permissions never outlive the mapping.
func (r *Reader) Retire() error {
	err := r.owner.Close()
	<-r.done
	return errors.Join(err, unix.Munmap(r.page))
}

// Recovery names the authenticated control request's exact closed serial. The
// child cannot turn it into serving permission or publish the shared word.
func (r *Reader) Recovery(generation, serial uint64) (RecoveryPermit, error) {
	p := RecoveryPermit{binding: r.binding, word: serial << 1, generation: generation}
	if serial > math.MaxUint64>>1 {
		return RecoveryPermit{}, ErrClosed
	}
	return p, r.Recover(p)
}

// Installed requires the prepared serial in its serving state. Matching only
// the serial would also license the closed state and is never sufficient.
func (r *Reader) Installed(p RecoveryPermit) bool {
	return !r.dead.Load() && p.Serial() != math.MaxUint64>>1 && p.binding == r.binding && p.generation != 0 && p.word&1 == 0 && r.word.Load() == p.word|1
}

// MountInstanceID is the exact CLI/kernel source identity encoded in the header.
func (r *Reader) MountInstanceID() string {
	return "mnt_" + base64.RawURLEncoding.EncodeToString(r.binding.Incarnation[:])
}
