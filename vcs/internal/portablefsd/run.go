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
	frontendSingleton, err := acquireFrontendSingleton(s.cfg.FrontendSocket)
	if err != nil {
		return err
	}
	defer releaseSingleton(frontendSingleton)

	// Registry construction is intentionally behind every singleton lock.
	// It opens local backing roots, replays the binding journal, stamps legacy
	// WAL identity, sweeps WAL state, and starts a persister. A daemon that
	// loses either lock must perform none of those operations.
	if err := stateSingleton.validate(); err != nil {
		return fmt.Errorf("revalidate portablefsd state singleton: %w", err)
	}
	if err := socketSingleton.validate(); err != nil {
		return fmt.Errorf("revalidate portablefsd socket singleton: %w", err)
	}
	if err := frontendSingleton.validate(); err != nil {
		return fmt.Errorf("revalidate portablefsd frontend singleton: %w", err)
	}
	// A Unix socket pathname survives an unclean process exit and a machine
	// reboot even though no listener survives with it. Reclaim only the three
	// canonical sockets after this process owns every singleton lock. A live
	// PortableFS daemon cannot reach this point concurrently, and the pinned
	// directory/inode checks below refuse every non-socket or replaced entry.
	// This is normal daemon restart, not an ownership fallback.
	if filepath.Dir(s.cfg.ControlSocket) != socketSingleton.dirPath ||
		filepath.Dir(s.cfg.FrontendSocket) != frontendSingleton.dirPath ||
		s.cfg.FrontendSocket == s.cfg.ControlSocket {
		return errors.New("portablefsd frontend and control sockets must be distinct entries under their pinned exact roots")
	}
	if err := reclaimStaleUnixSocket(socketSingleton, s.cfg.ControlSocket); err != nil {
		return err
	}
	for _, socketPath := range []string{s.cfg.FrontendSocket, s.mountRootSocketPath()} {
		if err := reclaimStaleUnixSocket(frontendSingleton, socketPath); err != nil {
			return err
		}
	}
	if err := privatepath.EnsureDir(s.cfg.MountLogDir); err != nil {
		return fmt.Errorf("validate per-mount log directory: %w", err)
	}
	s.registry = newRegistryWithMountLogDir(s.cfg.StateDir, s.cfg.MountLogDir)
	if s.registry.loadErr != nil {
		return fmt.Errorf("strict persisted attach inventory: %w", s.registry.loadErr)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	wg.Add(3)
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
	go func() {
		defer wg.Done()
		if err := s.ServeMountRootHandoff(ctx); err != nil && ctx.Err() == nil {
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
	// TERMINATION IS NOT ALLOWED TO DEPEND ON COOPERATION.
	//
	// closeAll runs every attach's authority drain barrier, and an attach whose
	// authority has stopped answering can hold that barrier open indefinitely
	// (registry.detach does not honour the shutdown context). Waiting on it
	// turned SIGTERM into "portablefsd never exits", which is the observable
	// front half of the unkillable-daemon incident.
	//
	// The shutdown transaction still runs to completion on its own goroutine —
	// nothing durable is abandoned — but this function stops waiting at the
	// budget and returns a definite verdict, so the process exits and its
	// singleton lock is released. Everything the barrier had not shipped is
	// already durable in the write-back WAL and replays on the next attach.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), daemonShutdownBudget)
	defer shutCancel()
	shutDone := make(chan error, 1)
	go func() { shutDone <- s.registry.closeAll(shutCtx) }()
	var shutErr error
	select {
	case shutErr = <-shutDone:
		if shutErr != nil {
			shutErr = fmt.Errorf("cooperative shutdown refused: %w", shutErr)
		}
		waitBounded(&wg, daemonShutdownBudget)
	case <-shutCtx.Done():
		shutErr = fmt.Errorf(
			"cooperative shutdown did not complete within %s; portablefsd is exiting anyway "+
				"so its singleton lock is released — every unshipped write-back record stays "+
				"durable locally and replays on the next attach",
			daemonShutdownBudget,
		)
	}
	return errors.Join(serveErr, shutErr)
}

// daemonShutdownBudget bounds the cooperative half of termination. A var so
// tests compress it; production never changes it.
var daemonShutdownBudget = 30 * time.Second

// waitBounded waits for wg, but never past budget. A serving goroutine that
// cannot return must not be able to keep the process alive.
func waitBounded(wg *sync.WaitGroup, budget time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
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

func acquireFrontendSingleton(frontendSocket string) (*singletonLock, error) {
	if frontendSocket == "" {
		return nil, errors.New("portablefsd frontend socket is required")
	}
	dir := filepath.Dir(frontendSocket)
	return acquireLock(dir, ".portablefsd-frontend.lock", dir)
}

func acquireLock(dirPath, name, owner string) (*singletonLock, error) {
	guard, err := tryAcquireLock(dirPath, name, owner)
	if err == nil {
		return guard, nil
	}
	if !errors.Is(err, errSingletonHeld) {
		return nil, err
	}
	// The lock is held. It is held either by a daemon that is alive — in which
	// case this one must not start — or by a process the kernel has already
	// finished with, whose descriptors will never be closed. Only the second
	// case is recoverable, and only with proof.
	//
	// THE PROOF COMES BEFORE ANY WRITE. A daemon that loses the singleton race
	// must leave the shared state directory byte-for-byte untouched, so the
	// classification reads the existing lock file and creates nothing.
	if !singletonHolderIsProvablyGone(dirPath, name) {
		return nil, err
	}
	taken, takeoverErr := takeOverDeadSingleton(dirPath, name, owner)
	if takeoverErr != nil {
		return nil, errors.Join(err, takeoverErr)
	}
	if taken == nil {
		return nil, err
	}
	return taken, nil
}

// errSingletonHeld distinguishes "another process holds this lock" from every
// other acquisition failure, so only that case reaches the takeover policy.
var errSingletonHeld = errors.New("portablefsd singleton is held")

func tryAcquireLock(dirPath, name, owner string) (*singletonLock, error) {
	dir, err := privatepath.OpenDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("open portablefsd singleton directory: %w", err)
	}
	lock, err := privatepath.OpenLockFile(dir, dirPath, name)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("open portablefsd singleton lock: %w", err)
	}
	if flockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr != nil {
		held := errors.Is(flockErr, syscall.EWOULDBLOCK) || errors.Is(flockErr, syscall.EAGAIN)
		detail := describeSingletonHolder(lock)
		_ = lock.Close()
		_ = dir.Close()
		wrapped := fmt.Errorf("another portablefsd owns %s: %w%s", owner, flockErr, detail)
		if held {
			return nil, errors.Join(wrapped, errSingletonHeld)
		}
		return nil, wrapped
	}
	guard := &singletonLock{dirPath: dirPath, name: name, dir: dir, file: lock}
	if err := guard.validate(); err != nil {
		releaseSingleton(guard)
		return nil, fmt.Errorf("validate portablefsd singleton lock: %w", err)
	}
	if err := publishSingletonOwner(guard, "", owner); err != nil {
		releaseSingleton(guard)
		return nil, err
	}
	return guard, nil
}

// describeSingletonHolder names WHO holds a refused lock. An operator reading
// "resource temporarily unavailable" has nothing to act on; an operator reading
// the holder's pid and state does.
func describeSingletonHolder(lock *os.File) string {
	record, err := readSingletonOwner(lock)
	if err != nil || record == nil {
		// A lock written by a build that predates owner records. There is no
		// way to prove its holder departed, so takeover is refused — but the
		// operator must still be told how to find and end it, because "resource
		// temporarily unavailable" on its own is what made the live incident
		// look like it required a reboot.
		return fmt.Sprintf(
			" (the lock carries no owner record, so its holder cannot be proven departed;"+
				" find it with `lsof %s` and terminate it)",
			lock.Name(),
		)
	}
	verdict, why := classifySingletonHolder(record)
	suffix := ""
	if verdict == holderLive {
		suffix = fmt.Sprintf("; stop it with `kill %d` if it is not serving a mount", record.PID)
	}
	return fmt.Sprintf(" (held by pid %d, %s: %s%s)", record.PID, verdict, why, suffix)
}

// singletonHolderIsProvablyGone classifies the holder of an existing lock file
// WITHOUT creating, renaming or writing anything. It answers false for every
// ambiguity: a missing lock, an unreadable one, no owner record, an unprovable
// platform, or a live holder.
func singletonHolderIsProvablyGone(dirPath, name string) bool {
	dir, err := privatepath.OpenDir(dirPath)
	if err != nil {
		return false
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dirPath, name))
	if file == nil {
		_ = unix.Close(fd)
		return false
	}
	defer file.Close()
	record, err := readSingletonOwner(file)
	if err != nil || record == nil {
		return false
	}
	verdict, _ := classifySingletonHolder(record)
	return verdict == holderGone
}

// takeOverDeadSingleton replaces a lock inode whose recorded owner is PROVEN
// unable to act again. It returns (nil, nil) when the holder is live or cannot
// be proven dead — the only safe default, and the one that keeps a merely slow
// daemon from being displaced.
func takeOverDeadSingleton(dirPath, name, owner string) (*singletonLock, error) {
	dir, err := privatepath.OpenDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("open portablefsd singleton directory for takeover: %w", err)
	}
	defer dir.Close()

	// Serialize takeovers through a lock the stuck holder has never opened.
	// Without it two contenders could each install a fresh inode and both
	// believe they are the singleton.
	takeoverLock, err := privatepath.OpenLockFile(dir, dirPath, name+".takeover")
	if err != nil {
		return nil, fmt.Errorf("open portablefsd singleton takeover lock: %w", err)
	}
	defer takeoverLock.Close()
	if err := syscall.Flock(int(takeoverLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Another contender is performing the takeover right now. Not an error:
		// this daemon simply loses the race and reports the held lock.
		return nil, nil
	}
	defer syscall.Flock(int(takeoverLock.Fd()), syscall.LOCK_UN)

	current, err := privatepath.OpenLockFile(dir, dirPath, name)
	if err != nil {
		return nil, fmt.Errorf("reopen portablefsd singleton lock for takeover: %w", err)
	}
	// Re-prove the lock is still held under the takeover lock: the holder may
	// have exited between the refusal and here, in which case the plain path
	// must be used and no inode replaced.
	if flockErr := syscall.Flock(int(current.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr == nil {
		_ = syscall.Flock(int(current.Fd()), syscall.LOCK_UN)
		_ = current.Close()
		return tryAcquireLock(dirPath, name, owner)
	}
	record, readErr := readSingletonOwner(current)
	_ = current.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read portablefsd singleton owner record: %w", readErr)
	}
	verdict, why := classifySingletonHolder(record)
	if verdict != holderGone {
		return nil, nil
	}

	// Install a fresh lock inode. The stuck holder keeps its exclusive lock on
	// the now-unlinked old inode, which nothing will open again.
	replacement := name + ".replacement"
	_ = unix.Unlinkat(int(dir.Fd()), replacement, 0)
	fresh, err := privatepath.OpenLockFile(dir, dirPath, replacement)
	if err != nil {
		return nil, fmt.Errorf("create replacement portablefsd singleton lock: %w", err)
	}
	if err := syscall.Flock(int(fresh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = fresh.Close()
		return nil, fmt.Errorf("lock replacement portablefsd singleton lock: %w", err)
	}
	if err := unix.Renameat(int(dir.Fd()), replacement, int(dir.Fd()), name); err != nil {
		_ = syscall.Flock(int(fresh.Fd()), syscall.LOCK_UN)
		_ = fresh.Close()
		return nil, fmt.Errorf("install replacement portablefsd singleton lock: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = syscall.Flock(int(fresh.Fd()), syscall.LOCK_UN)
		_ = fresh.Close()
		return nil, fmt.Errorf("sync replaced portablefsd singleton lock directory %s: %w", dirPath, err)
	}
	guard := &singletonLock{dirPath: dirPath, name: name, dir: nil, file: fresh}
	// Re-pin the directory through the canonical traversal so validate() holds
	// the same invariants as a normal acquisition.
	pinned, err := privatepath.OpenDir(dirPath)
	if err != nil {
		releaseSingleton(guard)
		return nil, fmt.Errorf("re-pin portablefsd singleton directory after takeover: %w", err)
	}
	guard.dir = pinned
	if err := guard.validate(); err != nil {
		releaseSingleton(guard)
		return nil, fmt.Errorf("validate portablefsd singleton lock after takeover: %w", err)
	}
	if err := publishSingletonOwner(guard, "", owner); err != nil {
		releaseSingleton(guard)
		return nil, err
	}
	log.Printf(
		"portablefsd: took over the %s singleton lock from a provably departed holder (%s)",
		owner, why,
	)
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
	if err := prepareRuntimeConfig(&cfg); err != nil {
		log.Printf("portablefsd: %v", err)
		return 1
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
