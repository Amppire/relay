package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/http/middleware"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/db"
)

func setupTestRouter(t *testing.T, dbPath string) (http.Handler, *db.SQLiteRepository, func()) {
	_ = os.Remove(dbPath)

	repo, err := db.NewSQLiteRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite repository: %v", err)
	}

	memCache := cache.NewMemoryCache()
	analyticsWorker := analytics.NewAsyncBuffer(repo, 100, 10, 50*time.Millisecond, nil)

	linkService := services.NewLinkService(repo, memCache, analyticsWorker, "http://localhost:8080")
	pasteService := services.NewPasteService(repo, "http://localhost:8080")
	authService := services.NewAuthService(repo)
	auditService := services.NewAuditService(repo)

	authMw := middleware.NewAuthMiddleware(authService)
	apiHandler := handlers.NewAPIHandler(linkService, pasteService, authService, auditService)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.With(authMw.OptionalAuth).Post("/links", apiHandler.CreateLink)
		r.With(authMw.OptionalAuth).Post("/pastes", apiHandler.CreatePaste)
		r.Post("/api-keys", apiHandler.CreateAPIKey)
		r.With(authMw.RequireScope("audit:read")).Get("/audit", apiHandler.ListAuditLogs)
	})
	r.Get("/p/{slug}", apiHandler.GetPasteHandler)
	r.Get("/p/{slug}/raw", apiHandler.GetPasteHandler)
	r.Get("/{slug}", apiHandler.RedirectHandler)

	cleanup := func() {
		analyticsWorker.Close()
		repo.Close()
		_ = os.Remove(dbPath)
	}

	return r, repo, cleanup
}

func TestEndToEndRedirectPipeline(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_redirect.db")
	defer cleanup()

	// 1. Create short link via POST /api/v1/links
	reqBody := services.CreateLinkRequest{
		DestinationURL: "https://openai.com",
		Slug:           "test-slug",
		PreserveQuery:  true,
	}
	payloadBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/links", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var createResp services.CreateLinkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to unmarshal create response: %v", err)
	}

	if createResp.Slug != "test-slug" {
		t.Errorf("expected slug 'test-slug', got '%s'", createResp.Slug)
	}

	// 2. Resolve short link via GET /test-slug?utm_source=chat
	getReq := httptest.NewRequest(http.MethodGet, "/test-slug?utm_source=chat", nil)
	getReq.Host = "localhost"
	getRec := httptest.NewRecorder()

	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", getRec.Code)
	}

	location := getRec.Header().Get("Location")
	expectedLocation := "https://openai.com?utm_source=chat"
	if location != expectedLocation {
		t.Errorf("expected Location '%s', got '%s'", expectedLocation, location)
	}
}

func TestAPIKeysAndAuditLogs(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_auth_audit.db")
	defer cleanup()

	// 1. Create API key with scope "audit:read"
	keyReq := services.CreateAPIKeyRequest{
		Name:   "auditor-key",
		Scopes: []string{"audit:read"},
	}
	keyBody, _ := json.Marshal(keyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(keyBody))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for api key, got %d", rec.Code)
	}

	var keyResp services.CreateAPIKeyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &keyResp)
	if !strings.HasPrefix(keyResp.Token, "rly_live_") {
		t.Fatalf("expected rly_live_ prefix, got %s", keyResp.Token)
	}

	// 2. Access /api/v1/audit without token -> 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	recUnauth := httptest.NewRecorder()
	router.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", recUnauth.Code)
	}

	// 3. Access /api/v1/audit with token -> 200 OK
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+keyResp.Token)
	recAuth := httptest.NewRecorder()
	router.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid api key, got %d", recAuth.Code)
	}

	var auditData map[string][]map[string]any
	_ = json.Unmarshal(recAuth.Body.Bytes(), &auditData)
	if len(auditData["events"]) == 0 {
		t.Errorf("expected audit events to be present")
	}
}

func TestPasteResourceFlow(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_pastes.db")
	defer cleanup()

	pasteReq := services.CreatePasteRequest{
		Content:  "package main\n\nfunc main() {}\n",
		Title:    "Go Entrypoint",
		Format:   "code",
		Language: "go",
		Slug:     "go-main",
	}
	body, _ := json.Marshal(pasteReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pastes", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for paste, got %d: %s", rec.Code, rec.Body.String())
	}

	// Fetch formatted view
	reqView := httptest.NewRequest(http.MethodGet, "/p/go-main", nil)
	recView := httptest.NewRecorder()
	router.ServeHTTP(recView, reqView)

	if recView.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for paste view, got %d", recView.Code)
	}
	if !strings.Contains(recView.Body.String(), "func main()") {
		t.Errorf("expected HTML body to contain paste content")
	}

	// Fetch raw view via /p/go-main/raw
	reqRaw := httptest.NewRequest(http.MethodGet, "/p/go-main/raw", nil)
	recRaw := httptest.NewRecorder()
	router.ServeHTTP(recRaw, reqRaw)

	if recRaw.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for raw paste, got %d", recRaw.Code)
	}
	if recRaw.Body.String() != pasteReq.Content {
		t.Errorf("expected exact raw content, got '%s'", recRaw.Body.String())
	}
}
