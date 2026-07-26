package portablefsd

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func (s *Server) Run(ctx context.Context) error {
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
	case err := <-errs:
		cancel()
		wg.Wait()
		return err
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.registry.closeAll(shutCtx)
	shutCancel()
	wg.Wait()
	return nil
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
