package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/services"
)

type APIHandler struct {
	linkService *services.LinkService
}

func NewAPIHandler(linkService *services.LinkService) *APIHandler {
	return &APIHandler{linkService: linkService}
}

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

func (h *APIHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	// Host without port
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
