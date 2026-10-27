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
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/http/middleware"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/db"
	"github.com/relay/relay/internal/platform/storage"
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

	policyService := services.NewPolicyService(repo, nil)
	linkService := services.NewLinkService(repo, policyService, memCache, analyticsWorker, cfg.DefaultBaseURL)
	pasteService := services.NewPasteService(repo, cfg.DefaultBaseURL)
	secretService := services.NewSecretService(repo, cfg.DefaultBaseURL)
	authService := services.NewAuthService(repo)
	auditService := services.NewAuditService(repo)

	diskStore, err := storage.NewLocalDiskStore("data/storage")
	if err != nil {
		return fmt.Errorf("init disk store: %w", err)
	}
	fileService := services.NewFileService(repo, diskStore, cfg.DefaultBaseURL)
	requestService := services.NewRequestService(repo, cfg.DefaultBaseURL)
	webhookDispatcher := services.NewWebhookDispatcher(repo)

	authMw := middleware.NewAuthMiddleware(authService)
	apiHandler := handlers.NewAPIHandler(
		linkService, pasteService, secretService, policyService,
		fileService, requestService, webhookDispatcher,
		authService, auditService,
	)

	r := chi.NewRouter()
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)

	// Health probes
	r.Get("/health/live", apiHandler.HealthLive)
	r.Get("/health/ready", apiHandler.HealthReady)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public or API-key authenticated link creation
		r.With(authMw.OptionalAuth).Post("/links", apiHandler.CreateLink)

		// Paste creation
		r.With(authMw.OptionalAuth).Post("/pastes", apiHandler.CreatePaste)

		// Zero-knowledge secret creation & payload burn
		r.With(authMw.OptionalAuth).Post("/secrets", apiHandler.CreateSecret)
		r.With(authMw.OptionalAuth).Get("/secrets/{slug}", apiHandler.GetSecretPayload)

		// Encrypted Files & Asymmetric Requests
		r.With(authMw.OptionalAuth).Post("/files", apiHandler.UploadFile)
		r.With(authMw.OptionalAuth).Post("/requests", apiHandler.CreateRequestPortal)
		r.Post("/requests/{slug}/fulfill", apiHandler.FulfillRequest)

		// Access Policies & Webhooks
		r.With(authMw.RequireScope("policy:write")).Post("/policies", apiHandler.CreatePolicy)
		r.With(authMw.RequireScope("policy:read")).Get("/policies", apiHandler.ListPolicies)
		r.With(authMw.RequireScope("webhook:write")).Post("/webhooks", apiHandler.CreateWebhook)

		// API Keys management
		r.Post("/api-keys", apiHandler.CreateAPIKey)

		// Audit logs
		r.With(authMw.RequireScope("audit:read")).Get("/audit", apiHandler.ListAuditLogs)
	})

	// Download encrypted file stream
	r.Get("/f/{slug}", apiHandler.DownloadFile)

	// Paste viewer & raw export
	r.Get("/p/{slug}", apiHandler.GetPasteHandler)
	r.Get("/p/{slug}/raw", apiHandler.GetPasteHandler)

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
