package portablefsd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The mount-root handoff socket.
//
// The macOS app sandbox hides an FSKit extension's own kernel mount from the
// extension: getfsstat inside the extension enumerates every volume on the
// machine EXCEPT the one the extension is serving, so the extension can never
// locate — let alone open — its own mount root, and the synchronous VFS
// repair actuator has nothing to actuate through. The first live peer repair
// proved this: the locator scanned fifteen mounts, none of them `pfs`, and
// the mount was fenced.
//
// portablefsd is not sandboxed. It can see the mount table, it already knows
// each attach's exact mount path, and it shares a unix-socket directory the
// sandboxed extension is allowed to connect into. So the daemon opens the
// mount root and passes the DESCRIPTOR to the extension over this socket via
// SCM_RIGHTS — descriptors cross sandbox boundaries by design, which is the
// entire point of fd passing. The protocol is deliberately outside the
// pfslocal framing: ancillary data cannot ride the dispatch_io pipeline the
// ordinary frontend connection uses, and one four-byte exchange does not
// deserve a protobuf.
//
// Wire form: the client sends the attach ref followed by '\n'; the daemon
// answers one status byte — 1 with the O_DIRECTORY root descriptor attached
// as SCM_RIGHTS, 0 with nothing — and closes. The daemon verifies, via
// fstatfs on the descriptor it just opened, that the filesystem's mount
// source names exactly the requested attach, so a racing remount of some
// other volume at the same path can never leak a foreign directory into the
// extension.
const mountRootSocketName = "pfs-root.sock"

func (s *Server) mountRootSocketPath() string {
	return filepath.Join(filepath.Dir(s.cfg.FrontendSocket), mountRootSocketName)
}

func (s *Server) ServeMountRootHandoff(ctx context.Context) error {
	path := s.mountRootSocketPath()
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleMountRootHandoff(conn)
	}
}

func (s *Server) handleMountRootHandoff(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(conn, 64*1024)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = line[:len(line)-1]

	// Two verbs share this socket. A bare attach ref is the mount-root fd
	// handoff. "actuate <ref>" followed by one JSON plan line performs the
	// repair actuation the sandboxed extension cannot: the macOS sandbox
	// denies the extension write-class VFS operations on its own mount even
	// through a handed descriptor (the first live peer repair's scratch
	// create came back EPERM from the kernel, with no gate refusal logged),
	// so the daemon — the mount's unsandboxed owner — issues the syscalls.
	// The resulting kernel upcalls arrive at the extension as reserved-name
	// callbacks and are validated by its HMAC-armed registry exactly as if
	// the extension had issued the syscalls itself; the operand
	// authentication was designed for callbacks with no in-process
	// provenance, which is precisely what these are.
	if ref, ok := strings.CutPrefix(line, "actuate "); ok {
		s.handleRepairActuation(conn, reader, ref)
		return
	}
	ref := line
	refuse := func(why string) {
		log.Printf("portablefsd: mount-root handoff refused for %q: %s", ref, why)
		_, _, _ = conn.WriteMsgUnix([]byte{0}, nil, nil)
	}
	a := s.registry.get(ref)
	if a == nil {
		refuse("unknown attach")
		return
	}
	fd, err := a.mountRootDescriptor()
	if err != nil {
		refuse(err.Error())
		return
	}
	if _, _, err := conn.WriteMsgUnix([]byte{1}, mountRootRights(fd), nil); err != nil {
		log.Printf("portablefsd: mount-root handoff send for %q: %v", ref, err)
	}
}

// repairActuationPlan is the wire form of one macOS 26 repair actuation. All
// names are base64 because filesystem names are bytes, not text.
type repairActuationPlan struct {
	// Kind is "scratch", "evict", or "invalidate".
	Kind string `json:"kind"`
	// Parent is the repair target's parent directory as path components
	// relative to the mount root.
	Parent []string `json:"parent"`
	// Name is the user-visible child name (empty for scratch).
	Name string `json:"name,omitempty"`
	// Operand is the HMAC-authenticated reserved name.
	Operand string `json:"operand"`
	// ExpectedFileID attests the isolated file's identity before truncation.
	ExpectedFileID uint64 `json:"expectedFileId,omitempty"`
	// AuthoritativeSize is the post-repair EOF for "invalidate".
	AuthoritativeSize uint64 `json:"authoritativeSize,omitempty"`
}

func (s *Server) handleRepairActuation(conn *net.UnixConn, reader *bufio.Reader, ref string) {
	answer := func(status byte, errnoValue byte) {
		_, _ = conn.Write([]byte{status, errnoValue})
	}
	refuse := func(why string) {
		log.Printf("portablefsd: repair actuation refused for %q: %s", ref, why)
		answer(0, 0)
	}
	a := s.registry.get(ref)
	if a == nil {
		refuse("unknown attach")
		return
	}
	planLine, err := reader.ReadString('\n')
	if err != nil {
		refuse("plan not received")
		return
	}
	var plan repairActuationPlan
	if err := json.Unmarshal([]byte(planLine), &plan); err != nil {
		refuse("plan does not parse")
		return
	}
	// The bound descriptor, never a fresh path-based open: opening the mount
	// root during a barrier deadlocks against the extension serving it.
	rootFD, err := a.mountRootDescriptor()
	if err != nil {
		refuse(err.Error())
		return
	}
	if errnoValue, err := actuateRepair(rootFD, plan); err != nil {
		log.Printf("portablefsd: repair actuation for %q failed: %v", ref, err)
		answer(0, errnoValue)
		return
	}
	answer(1, 0)
}

// bindMountRoot opens this attach's kernel mount root and keeps it for the
// attach's lifetime. It must run while the mount is proven healthy — see the
// bind-root control endpoint for why re-deriving it later cannot work.
func (a *attach) bindMountRoot() error {
	a.mu.RLock()
	mountPath, ref := a.mountPath, a.ref
	a.mu.RUnlock()
	if mountPath == "" {
		return errors.New("attach has no mount path")
	}
	fd, err := openVerifiedMountRoot(mountPath, ref)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.mountRootFD > 0 {
		previous := a.mountRootFD
		a.mountRootFD = fd
		a.mu.Unlock()
		closeMountRootFD(previous)
		return nil
	}
	a.mountRootFD = fd
	a.mu.Unlock()
	return nil
}

func (a *attach) mountRootDescriptor() (int, error) {
	a.mu.RLock()
	fd := a.mountRootFD
	a.mu.RUnlock()
	if fd <= 0 {
		return 0, errors.New("mount root is not bound; the mount was never proven healthy")
	}
	return fd, nil
}
