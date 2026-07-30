package portablefsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
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
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			SchemaVersion int    `json:"schemaVersion"`
			AppGroup      string `json:"appGroup"`
		}{SchemaVersion: 1, AppGroup: fskitidentity.AppGroup})
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
