package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/middleware"
)

type APIHandler struct {
	linkService  *services.LinkService
	pasteService *services.PasteService
	authService  *services.AuthService
	auditService *services.AuditService
}

func NewAPIHandler(linkService *services.LinkService, pasteService *services.PasteService, authService *services.AuthService, auditService *services.AuditService) *APIHandler {
	return &APIHandler{
		linkService:  linkService,
		pasteService: pasteService,
		authService:  authService,
		auditService: auditService,
	}
}

// POST /api/v1/links
func (h *APIHandler) CreateLink(w http.ResponseWriter, r *http.Request) {
	var req services.CreateLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	resp, err := h.linkService.CreateRedirect(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrAlreadyExists) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slug already in use"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// POST /api/v1/pastes
func (h *APIHandler) CreatePaste(w http.ResponseWriter, r *http.Request) {
	var req services.CreatePasteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	var actorID *uuid.UUID
	actorType := "anonymous"

	if apiKey := middleware.GetAPIKeyFromContext(r.Context()); apiKey != nil {
		actorID = &apiKey.ID
		actorType = "api_key"
	}

	resp, err := h.pasteService.CreatePaste(r.Context(), req, actorID, actorType)
	if err != nil {
		if errors.Is(err, domain.ErrEmptyPasteContent) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, domain.ErrAlreadyExists) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slug already in use"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// GET /p/{slug} and GET /p/{slug}/raw
func (h *APIHandler) GetPasteHandler(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	hostname := r.Host
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}

	resolved, err := h.pasteService.GetPaste(r.Context(), hostname, slug)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrExpired) || errors.Is(err, domain.ErrMaxAccessCount) || errors.Is(err, domain.ErrRevoked) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Check if raw output requested via URL path, query (?raw=true), or Accept header
	isRawPath := strings.HasSuffix(r.URL.Path, "/raw")
	isRawQuery := r.URL.Query().Get("raw") == "true"
	isRawHeader := strings.Contains(r.Header.Get("Accept"), "text/plain")

	if isRawPath || isRawQuery || isRawHeader {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resolved.Paste.Content))
		return
	}

	// Clean, lightweight human-readable HTML representation
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title := resolved.Resource.Name
	if title == "" {
		title = fmt.Sprintf("Paste %s", slug)
	}

	escapedContent := html.EscapeString(resolved.Paste.Content)
	langLabel := string(resolved.Paste.Format)
	if resolved.Paste.Language != "" {
		langLabel = resolved.Paste.Language
	}

	htmlPage := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s - Relay</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
  .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
  .header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; background: #1e293b; border-bottom: 1px solid #334155; }
  .badge { background: #3b82f6; color: white; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
  .raw-link { color: #38bdf8; text-decoration: none; font-size: 0.875rem; font-weight: 500; }
  .raw-link:hover { text-decoration: underline; }
  pre { margin: 0; padding: 1.5rem; overflow-x: auto; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.95rem; line-height: 1.5; color: #e2e8f0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div><strong>%s</strong> &nbsp;<span class="badge">%s</span></div>
    <div><a class="raw-link" href="/p/%s/raw">Raw text</a></div>
  </div>
  <pre><code>%s</code></pre>
</div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(langLabel), slug, escapedContent)

	_, _ = w.Write([]byte(htmlPage))
}

// POST /api/v1/api-keys
func (h *APIHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req services.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	var actorID *uuid.UUID
	if apiKey := middleware.GetAPIKeyFromContext(r.Context()); apiKey != nil {
		actorID = &apiKey.ID
	}

	resp, err := h.authService.GenerateAPIKey(r.Context(), req, actorID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// GET /api/v1/audit
func (h *APIHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	events, err := h.auditService.ListEvents(r.Context(), uuid.Nil, 50)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
}

// Root redirect handler (GET /{slug})
func (h *APIHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	hostname := r.Host
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}

	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.Split(fwd, ",")[0]
	}

	userAgent := r.UserAgent()
	referer := r.Referer()
	queryString := r.URL.RawQuery

	dest, code, err := h.linkService.ResolveAndTrack(r.Context(), hostname, slug, clientIP, userAgent, referer, queryString)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrExpired) || errors.Is(err, domain.ErrMaxAccessCount) || errors.Is(err, domain.ErrRevoked) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, dest, code)
}

func (h *APIHandler) HealthLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"live"}`))
}

func (h *APIHandler) HealthReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}
