package portablefsd

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(conn, 256).ReadString('\n')
	if err != nil {
		return
	}
	ref := line[:len(line)-1]
	refuse := func(why string) {
		log.Printf("portablefsd: mount-root handoff refused for %q: %s", ref, why)
		_, _, _ = conn.WriteMsgUnix([]byte{0}, nil, nil)
	}
	a := s.registry.get(ref)
	if a == nil {
		refuse("unknown attach")
		return
	}
	a.mu.RLock()
	mountPath := a.mountPath
	a.mu.RUnlock()
	if mountPath == "" {
		refuse("attach has no mount path")
		return
	}
	fd, err := openVerifiedMountRoot(mountPath, ref)
	if err != nil {
		refuse(err.Error())
		return
	}
	defer closeMountRootFD(fd)
	if _, _, err := conn.WriteMsgUnix([]byte{1}, mountRootRights(fd), nil); err != nil {
		log.Printf("portablefsd: mount-root handoff send for %q: %v", ref, err)
	}
}
