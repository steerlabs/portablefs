package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
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
	select {
	case <-ctx.Done():
	case <-s.stopCh:
		cancel()
	case err := <-errs:
		cancel()
		wg.Wait()
		return err
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	shutErr := s.registry.closeAll(shutCtx)
	shutCancel()
	wg.Wait()
	if shutErr != nil {
		return fmt.Errorf("cooperative shutdown refused: %w", shutErr)
	}
	return nil
}

func releaseSingleton(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func acquireStateSingleton(stateDir string) (*os.File, error) {
	if stateDir == "" {
		return nil, errors.New("portablefsd state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create portablefsd state directory: %w", err)
	}
	return acquireLock(filepath.Join(stateDir, ".portablefsd-state.lock"), stateDir)
}

func acquireSingleton(controlSocket string) (*os.File, error) {
	if controlSocket == "" {
		return nil, errors.New("portablefsd control socket is required")
	}
	dir := filepath.Dir(controlSocket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create portablefsd socket directory: %w", err)
	}
	return acquireLock(filepath.Join(dir, ".portablefsd.lock"), dir)
}

func acquireLock(path, owner string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open portablefsd singleton lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("another portablefsd owns %s: %w", owner, err)
	}
	return lock, nil
}

func Main(version string) int {
	cfg, showVersion := ParseFlags(version)
	if showVersion {
		os.Stdout.WriteString(version + "\n")
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
