package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger := log.New(os.Stdout, "[warp] ", log.LstdFlags|log.Lmicroseconds)

	runtimeCfg, err := LoadRuntimeConfig()
	if err != nil {
		logger.Fatal(err)
	}

	if err := EnsureRulesDB(runtimeCfg.Paths.ConfigDir, logger); err != nil {
		logger.Fatal(err)
	}
	if err := GenerateAllRules(runtimeCfg.Paths.ConfigDir, logger); err != nil {
		logger.Fatal(err)
	}

	if err := PrepareAlertDBPath(&runtimeCfg, logger); err != nil {
		logger.Fatal(err)
	}

	alertStore := NewAlertStore(runtimeCfg.Paths.AlertDBPath, logger)
	if err := alertStore.Init(); err != nil {
		logger.Fatal(err)
	}
	defer alertStore.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	broker := NewAlertBroker()
	snortRunner := NewSnortRunner(runtimeCfg, alertStore, broker, logger)

	errCh := make(chan error, 1)
	go func() {
		errCh <- snortRunner.Run(ctx)
	}()

	server := NewAPIServer(runtimeCfg, alertStore, broker, snortRunner, logger)
	go func() {
		if err := server.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("http server stopped: %v", err)
			cancel()
		}
	}()

	go func() {
		select {
		case sig := <-sigCh:
			logger.Printf("received signal: %v", sig)
			if err := snortRunner.Stop(sig); err != nil {
				logger.Printf("forward signal to snort failed: %v", err)
			}
			cancel()
		case <-ctx.Done():
		}
	}()

	err = <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("snort stopped with error: %v", err)
	} else {
		logger.Printf("snort exited")
	}
	cancel()
}
