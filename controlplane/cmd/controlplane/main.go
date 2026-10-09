// Command controlplane runs the Go control plane: host registry, event ingest, admin
// API, and the embedded React UI. See docs/protocol.md §4 and docs/deployment.md.
package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/api"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/config"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/otlp"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/registry"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/spa"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if cfg.AdminToken == "" || cfg.HostToken == "" {
		log.Warn("SBX_ADMIN_TOKEN or SBX_HOST_TOKEN unset; every authenticated request will be rejected")
	}
	if cfg.TokenSecret == "" {
		log.Warn("SBX_TOKEN_SECRET unset; defaulting to SBX_HOST_TOKEN (set SBX_TOKEN_SECRET explicitly before going live)")
		cfg.TokenSecret = cfg.HostToken
	}

	if err := registry.ConfigureTLS(cfg.CAFile, cfg.TLSInsecure, log); err != nil {
		log.Error("tls", "err", err)
		os.Exit(1)
	}

	s, err := store.Open(cfg.DB)
	if err != nil {
		log.Error("store.Open", "err", err)
		os.Exit(1)
	}
	defer s.Close()

	hub := events.NewHub()
	a := api.New(s, hub, cfg.AdminToken, cfg.HostToken, cfg.TokenSecret, log)
	a.SetSizes(cfg.Sizes, cfg.OvercommitCPU, cfg.OvercommitMem)

	dist, err := fs.Sub(web.Dist, web.DistDir)
	if err != nil {
		log.Error("web.Dist", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/", spa.Handler(dist))
	a.Routes(mux)

	srv := &http.Server{
		Addr: cfg.Listen,
		// v4: HTTPMiddleware records sbxcp_http_requests_total/_duration_ms for GET
		// /metrics; it wraps mux rather than replacing it, so route matching (including
		// the SPA fallback and websocket/SSE upgrades) is unchanged.
		Handler:           a.HTTPMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// v2: retention sweeper.
	if cfg.RetentionDays > 0 {
		go func() {
			t := time.NewTicker(1 * time.Hour)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					n, err := s.SweepRetention(ctx, cfg.RetentionDays)
					if err != nil {
						log.Warn("retention sweep", "err", err)
					} else if n > 0 {
						log.Info("retention sweep", "deleted", n)
					}
				}
			}
		}()
	}

	// v4: SBX_OTLP_URL/SBX_OTLP_HEADERS seed the observability settings row on first boot
	// only (docs/protocol.md §4 v4); after that the UI owns it.
	if err := s.SeedObservabilitySettingsFromEnv(context.Background(), cfg.OTLPURL, cfg.OTLPHeaders); err != nil {
		log.Warn("seed observability settings", "err", err)
	}
	// v4: the pusher is always constructed and run now, not only when SBX_OTLP_URL is
	// set, so enabling push from the UI takes effect without a restart — it re-reads the
	// stored settings every batch and no-ops while enabled=false.
	pusher := otlp.NewPusher(func() store.ObservabilitySettings {
		settings, err := s.GetObservabilitySettings(context.Background())
		if err != nil {
			log.Warn("load observability settings", "err", err)
			return store.ObservabilitySettings{}
		}
		return settings
	}, s, log)
	a.SetPusher(pusher)
	go pusher.Run(ctx, 5*time.Second)

	go func() {
		log.Info("listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "")
		serve := srv.ListenAndServe
		if cfg.TLSCert != "" {
			serve = func() error { return srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }
		}
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("ListenAndServe", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("Shutdown", "err", err)
	}
}
