package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/db"
)

type Config struct {
	Port           string
	DBPath         string
	DefaultBaseURL string
}

func RunServer(cfg Config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "relay.db"
	}
	if cfg.DefaultBaseURL == "" {
		cfg.DefaultBaseURL = fmt.Sprintf("http://localhost:%s", cfg.Port)
	}

	repo, err := db.NewSQLiteRepository(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("init db repository: %w", err)
	}
	defer repo.Close()

	memCache := cache.NewMemoryCache()
	analyticsWorker := analytics.NewAsyncBuffer(repo, 5000, 50, 1*time.Second, logger)
	defer analyticsWorker.Close()

	linkService := services.NewLinkService(repo, memCache, analyticsWorker, cfg.DefaultBaseURL)
	apiHandler := handlers.NewAPIHandler(linkService)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Health probes
	r.Get("/health/live", apiHandler.HealthLive)
	r.Get("/health/ready", apiHandler.HealthReady)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/links", apiHandler.CreateLink)
	})

	// Redirect slug fast path (root level /{slug})
	r.Get("/{slug}", apiHandler.RedirectHandler)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Relay server starting", "addr", srv.Addr, "db", cfg.DBPath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-stop:
		logger.Info("shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
