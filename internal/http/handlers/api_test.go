package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/db"
)

func TestEndToEndRedirectPipeline(t *testing.T) {
	testDB := "test_relay.db"
	_ = os.Remove(testDB)
	defer os.Remove(testDB)

	repo, err := db.NewSQLiteRepository(testDB)
	if err != nil {
		t.Fatalf("failed to create sqlite repo: %v", err)
	}
	defer repo.Close()

	memCache := cache.NewMemoryCache()
	analyticsWorker := analytics.NewAsyncBuffer(repo, 100, 10, 50*time.Millisecond, nil)
	defer analyticsWorker.Close()

	linkService := services.NewLinkService(repo, memCache, analyticsWorker, "http://localhost:8080")
	apiHandler := handlers.NewAPIHandler(linkService)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/links", apiHandler.CreateLink)
	})
	r.Get("/{slug}", apiHandler.RedirectHandler)

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

	r.ServeHTTP(rec, req)

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
	if createResp.DestinationURL != "https://openai.com" {
		t.Errorf("expected destination 'https://openai.com', got '%s'", createResp.DestinationURL)
	}

	// 2. Resolve short link via GET /test-slug?utm_source=chat
	getReq := httptest.NewRequest(http.MethodGet, "/test-slug?utm_source=chat", nil)
	getReq.Host = "localhost"
	getRec := httptest.NewRecorder()

	r.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", getRec.Code)
	}

	location := getRec.Header().Get("Location")
	expectedLocation := "https://openai.com?utm_source=chat"
	if location != expectedLocation {
		t.Errorf("expected Location '%s', got '%s'", expectedLocation, location)
	}

	// 3. Verify non-existent slug returns 404
	badReq := httptest.NewRequest(http.MethodGet, "/non-existent", nil)
	badRec := httptest.NewRecorder()
	r.ServeHTTP(badRec, badReq)

	if badRec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 Not Found for non-existent slug, got %d", badRec.Code)
	}
}

func TestMaxAccessExceeded(t *testing.T) {
	testDB := "test_max_access.db"
	_ = os.Remove(testDB)
	defer os.Remove(testDB)

	repo, err := db.NewSQLiteRepository(testDB)
	if err != nil {
		t.Fatalf("failed to create sqlite repo: %v", err)
	}
	defer repo.Close()

	linkService := services.NewLinkService(repo, nil, nil, "http://localhost:8080")
	apiHandler := handlers.NewAPIHandler(linkService)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/links", apiHandler.CreateLink)
	})
	r.Get("/{slug}", apiHandler.RedirectHandler)

	maxOne := int64(1)
	reqBody := services.CreateLinkRequest{
		DestinationURL: "https://example.com/one-time",
		Slug:           "once-only",
		MaxAccesses:    &maxOne,
	}
	payloadBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/links", bytes.NewReader(payloadBytes))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	// First access -> 302
	req1 := httptest.NewRequest(http.MethodGet, "/once-only", nil)
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusFound {
		t.Errorf("expected 302 Found on first access, got %d", rec1.Code)
	}

	// Second access -> 404 (MaxAccessCount reached)
	req2 := httptest.NewRequest(http.MethodGet, "/once-only", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found on second access, got %d", rec2.Code)
	}
}
