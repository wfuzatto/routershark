package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"routershark/backend/internal/api"
	"routershark/backend/internal/capture"
	"routershark/backend/internal/config"
	"routershark/backend/internal/db"
)

func main() {
	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Pool.Close()
	if err := store.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	srv := api.New(store, cfg.APIToken)
	collector := &capture.Collector{Addr: cfg.UDPAddr, Allowlist: cfg.Allowlist, Store: store, BatchSize: cfg.BatchSize, BatchInterval: time.Duration(cfg.BatchIntervalMs) * time.Millisecond, Broadcast: srv.Broadcast}
	if cfg.RetentionDays > 0 {
		go func() {
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					before := time.Now().UTC().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour)
					if n, err := store.DeleteBefore(ctx, before); err != nil {
						log.Printf("retention cleanup: %v", err)
					} else if n > 0 {
						log.Printf("retention cleanup removed %d packets", n)
					}
				}
			}
		}()
	}
	go func() {
		if err := collector.Run(ctx); err != nil {
			log.Printf("collector stopped: %v", err)
			cancel()
		}
	}()
	hs := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("HTTP API listening on %s", cfg.HTTPAddr)
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http: %v", err)
			cancel()
		}
	}()
	<-ctx.Done()
	shutdown, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_ = hs.Shutdown(shutdown)
}
