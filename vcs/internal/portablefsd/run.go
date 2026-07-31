package portablefsd

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

func (s *Server) Run(ctx context.Context) error {
	stateSingleton, err := acquireStateSingleton(s.cfg.StateDir)
	if err != nil {
		return err
	}
	defer releaseSingleton(stateSingleton)
	socketSingleton, err := acquireSingleton(s.cfg.ControlSocket)
	if err != nil {
		return err
	}
	defer releaseSingleton(socketSingleton)

	// Registry construction is intentionally behind BOTH singleton locks.
	// It opens local backing roots, replays the binding journal, stamps legacy
	// WAL identity, sweeps WAL state, and starts a persister. A daemon that
	// loses either lock must perform none of those operations.
	if err := stateSingleton.validate(); err != nil {
		return fmt.Errorf("revalidate portablefsd state singleton: %w", err)
	}
	if err := socketSingleton.validate(); err != nil {
		return fmt.Errorf("revalidate portablefsd socket singleton: %w", err)
	}
	// A Unix socket pathname survives an unclean process exit and a machine
	// reboot even though no listener survives with it. Reclaim only the two
	// canonical sockets after this process owns BOTH singleton locks. A live
	// PortableFS daemon cannot reach this point concurrently, and the pinned
	// directory/inode checks below refuse every non-socket or replaced entry.
	// This is normal daemon restart, not an ownership fallback.
	if filepath.Dir(s.cfg.FrontendSocket) != socketSingleton.dirPath ||
		filepath.Dir(s.cfg.ControlSocket) != socketSingleton.dirPath ||
		s.cfg.FrontendSocket == s.cfg.ControlSocket {
		return errors.New("portablefsd frontend and control sockets must be distinct entries in the singleton socket directory")
	}
	for _, socketPath := range []string{s.cfg.FrontendSocket, s.cfg.ControlSocket} {
		if err := reclaimStaleUnixSocket(socketSingleton, socketPath); err != nil {
			return err
		}
	}
	s.registry = newRegistry(s.cfg.StateDir)
	if s.registry.loadErr != nil {
		return fmt.Errorf("strict persisted attach inventory: %w", s.registry.loadErr)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.ServeFrontend(ctx); err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := s.ServeControl(ctx); err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case <-s.stopCh:
		cancel()
	case err := <-errs:
		cancel()
		serveErr = err
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	shutErr := s.registry.closeAll(shutCtx)
	shutCancel()
	wg.Wait()
	if shutErr != nil {
		shutErr = fmt.Errorf("cooperative shutdown refused: %w", shutErr)
	}
	return errors.Join(serveErr, shutErr)
}

// reclaimStaleUnixSocket removes one dead daemon socket while the caller owns
// the socket-directory singleton. It never removes a listening socket, a
// non-socket entry, an entry owned by another uid, a permissive entry, or a
// replacement published at the canonical pathname while it was inspected.
func reclaimStaleUnixSocket(lock *singletonLock, socketPath string) error {
	return reclaimStaleUnixSocketWith(lock, socketPath, nil)
}

func reclaimStaleUnixSocketWith(lock *singletonLock, socketPath string, beforeQuarantine func()) error {
	if lock == nil || lock.dir == nil || filepath.Dir(socketPath) != lock.dirPath {
		return fmt.Errorf("refuse stale socket reclamation outside the pinned singleton directory: %s", socketPath)
	}
	if err := lock.validate(); err != nil {
		return fmt.Errorf("validate socket singleton before reclaiming %s: %w", socketPath, err)
	}
	name := filepath.Base(socketPath)
	var inspected unix.Stat_t
	if err := unix.Fstatat(int(lock.dir.Fd()), name, &inspected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			if validateErr := lock.validate(); validateErr != nil {
				return fmt.Errorf("revalidate absent Unix socket %s: %w", socketPath, validateErr)
			}
			return nil
		}
		return fmt.Errorf("inspect existing Unix socket %s through pinned directory: %w", socketPath, err)
	}
	if inspected.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		inspected.Mode&0o777 != 0o600 ||
		inspected.Uid != uint32(os.Geteuid()) ||
		inspected.Nlink != 1 {
		return fmt.Errorf(
			"refusing to reclaim unsafe existing Unix socket entry %s (mode %#o uid %d links %d)",
			socketPath,
			inspected.Mode,
			inspected.Uid,
			inspected.Nlink,
		)
	}
	conn, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("refusing to reclaim listening Unix socket %s", socketPath)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		return fmt.Errorf("could not prove existing Unix socket %s is stale: %w", socketPath, dialErr)
	}
	if beforeQuarantine != nil {
		beforeQuarantine()
	}
	quarantineName, err := unusedSocketQuarantineName(lock)
	if err != nil {
		return fmt.Errorf("allocate stale Unix socket quarantine for %s: %w", socketPath, err)
	}
	dirFD := int(lock.dir.Fd())
	if err := renameSocketNoReplace(dirFD, name, dirFD, quarantineName); err != nil {
		if errors.Is(err, unix.ENOENT) {
			if validateErr := lock.validate(); validateErr != nil {
				return fmt.Errorf("revalidate disappeared Unix socket %s: %w", socketPath, validateErr)
			}
			return nil
		}
		return fmt.Errorf("atomically quarantine stale Unix socket %s: %w", socketPath, err)
	}
	var quarantined unix.Stat_t
	if err := unix.Fstatat(dirFD, quarantineName, &quarantined, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("inspect quarantined Unix socket %s: %w", socketPath, err)
	}
	if !sameSafeSocketIdentity(inspected, quarantined) {
		if restoreErr := renameSocketNoReplace(dirFD, quarantineName, dirFD, name); restoreErr != nil {
			return fmt.Errorf(
				"refusing to reclaim Unix socket %s because its identity changed; preserve the changed entry at %s after canonical-name restoration failed: %w",
				socketPath,
				filepath.Join(lock.dirPath, quarantineName),
				restoreErr,
			)
		}
		return fmt.Errorf("refusing to reclaim Unix socket %s because its identity changed; the changed entry was restored", socketPath)
	}
	if err := lock.validate(); err != nil {
		return fmt.Errorf(
			"revalidate socket singleton before retiring quarantined %s at %s: %w",
			socketPath,
			filepath.Join(lock.dirPath, quarantineName),
			err,
		)
	}
	if err := unix.Unlinkat(dirFD, quarantineName, 0); err != nil {
		return fmt.Errorf("retire quarantined stale Unix socket %s: %w", socketPath, err)
	}
	if err := lock.dir.Sync(); err != nil {
		return fmt.Errorf("sync reclaimed Unix socket directory %s: %w", lock.dirPath, err)
	}
	return nil
}

func sameSafeSocketIdentity(a, b unix.Stat_t) bool {
	return uint64(b.Dev) == uint64(a.Dev) &&
		b.Ino == a.Ino &&
		b.Mode&unix.S_IFMT == unix.S_IFSOCK &&
		b.Mode&0o777 == 0o600 &&
		b.Uid == uint32(os.Geteuid()) &&
		b.Nlink == 1
}

func unusedSocketQuarantineName(lock *singletonLock) (string, error) {
	var suffix [16]byte
	for attempt := 0; attempt < 64; attempt++ {
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", err
		}
		name := fmt.Sprintf(".portablefsd-stale-%x", suffix)
		var st unix.Stat_t
		err := unix.Fstatat(int(lock.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return name, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique socket quarantine name")
}

type singletonLock struct {
	dirPath string
	name    string
	dir     *os.File
	file    *os.File
}

func (l *singletonLock) validate() error {
	if l == nil || l.dir == nil || l.file == nil {
		return errors.New("portablefsd singleton is not open")
	}
	// Reopen the directory through the canonical no-symlink traversal and
	// prove the retained descriptor is still the inode named by dirPath.
	// Otherwise two daemons could coordinate on lock files in split directory
	// inodes after a rename/replacement race.
	namedDir, err := privatepath.OpenExistingDir(l.dirPath)
	if err != nil {
		return fmt.Errorf("revalidate singleton directory %s: %w", l.dirPath, err)
	}
	openedInfo, openedErr := l.dir.Stat()
	namedInfo, namedErr := namedDir.Stat()
	closeErr := namedDir.Close()
	if openedErr != nil {
		return fmt.Errorf("inspect pinned singleton directory %s: %w", l.dirPath, openedErr)
	}
	if namedErr != nil {
		return fmt.Errorf("inspect named singleton directory %s: %w", l.dirPath, namedErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close revalidated singleton directory %s: %w", l.dirPath, closeErr)
	}
	if !os.SameFile(openedInfo, namedInfo) {
		return fmt.Errorf("portablefsd singleton directory %s changed after it was pinned", l.dirPath)
	}
	if err := privatepath.ValidateOpenFile(l.dir, l.dirPath, l.name, l.file); err != nil {
		return err
	}
	return nil
}

func releaseSingleton(lock *singletonLock) {
	if lock == nil {
		return
	}
	if lock.file != nil {
		_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		_ = lock.file.Close()
		lock.file = nil
	}
	if lock.dir != nil {
		_ = lock.dir.Close()
		lock.dir = nil
	}
}

func acquireStateSingleton(stateDir string) (*singletonLock, error) {
	if stateDir == "" {
		return nil, errors.New("portablefsd state directory is required")
	}
	return acquireLock(stateDir, ".portablefsd-state.lock", stateDir)
}

func acquireSingleton(controlSocket string) (*singletonLock, error) {
	if controlSocket == "" {
		return nil, errors.New("portablefsd control socket is required")
	}
	dir := filepath.Dir(controlSocket)
	return acquireLock(dir, ".portablefsd.lock", dir)
}

func acquireLock(dirPath, name, owner string) (*singletonLock, error) {
	dir, err := privatepath.OpenDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("open portablefsd singleton directory: %w", err)
	}
	lock, err := privatepath.OpenLockFile(dir, dirPath, name)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("open portablefsd singleton lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("another portablefsd owns %s: %w", owner, err)
	}
	guard := &singletonLock{dirPath: dirPath, name: name, dir: dir, file: lock}
	if err := guard.validate(); err != nil {
		releaseSingleton(guard)
		return nil, fmt.Errorf("validate portablefsd singleton lock: %w", err)
	}
	return guard, nil
}

func Main(version string) int {
	cfg, showVersion, showIdentity := ParseFlags(version)
	if showVersion {
		os.Stdout.WriteString(version + "\n")
		return 0
	}
	if showIdentity {
		_ = json.NewEncoder(os.Stdout).Encode(fskitidentity.Current())
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := NewServer(cfg)
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("portablefsd: %v", err)
		return 1
	}
	return 0
}
