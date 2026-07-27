// Command history-worker is PortableFS's one direct HistoryCut worker. It
// owns a restricted pgx pool and exact-key object-store clients; all durable
// claims, leases, fences, receipts, and publication state remain in
// PostgreSQL. It has no local durable spool and no live-filesystem data path.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/histworker"
)

type outcome struct {
	component string
	err       error
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := histworker.FromEnv(os.LookupEnv)
	if err != nil {
		log.Error("history worker configuration rejected", "error", err.Error())
		os.Exit(1)
	}
	log.Info("history worker starting", "config", cfg.Redacted())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	repo, err := histworker.OpenRepository(ctx, cfg.DSN, cfg.DatabaseMaxConns)
	if err != nil {
		log.Error("history worker database rejected", "error", err.Error())
		os.Exit(1)
	}
	defer repo.Close()
	stores, err := histworker.OpenStores(cfg.Stores)
	if err != nil {
		log.Error("history worker stores rejected", "error", err.Error())
		os.Exit(1)
	}
	defer stores.Close()
	worker, err := histworker.New(cfg, repo, stores, os.Stderr)
	if err != nil {
		log.Error("history worker wiring rejected", "error", err.Error())
		os.Exit(1)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan outcome, 2)
	components := 1
	go func() { results <- outcome{component: "worker", err: worker.Run(runCtx)} }()
	if cfg.ListenAddr != "" {
		components++
		go func() {
			results <- outcome{component: "health", err: worker.ServeHealth(runCtx, cfg.ListenAddr, nil)}
		}()
	}

	first := <-results
	cancel()
	var failure error
	if first.err != nil && !errors.Is(first.err, context.Canceled) {
		failure = errors.New(first.component + ": " + first.err.Error())
	}
	for i := 1; i < components; i++ {
		result := <-results
		if result.err != nil && !errors.Is(result.err, context.Canceled) && failure == nil {
			failure = errors.New(result.component + ": " + result.err.Error())
		}
	}
	if failure != nil {
		log.Error("history worker failed", "error", failure.Error())
		os.Exit(2)
	}
	log.Info("history worker stopped cleanly")
}
