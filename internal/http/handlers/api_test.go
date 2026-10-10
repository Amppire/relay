package handlers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/http/middleware"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/crypto"
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
	secretService := services.NewSecretService(repo, "http://localhost:8080")
	authService := services.NewAuthService(repo)
	auditService := services.NewAuditService(repo)

	authMw := middleware.NewAuthMiddleware(authService)
	apiHandler := handlers.NewAPIHandler(linkService, pasteService, secretService, authService, auditService)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.With(authMw.OptionalAuth).Post("/links", apiHandler.CreateLink)
		r.With(authMw.OptionalAuth).Post("/pastes", apiHandler.CreatePaste)
		r.With(authMw.OptionalAuth).Post("/secrets", apiHandler.CreateSecret)
		r.With(authMw.OptionalAuth).Get("/secrets/{slug}", apiHandler.GetSecretPayload)
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

func TestZeroKnowledgeSecretBurnAfterRead(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_secrets.db")
	defer cleanup()

	// 1. Client-side encryption of secret
	plaintext := "my-database-root-password-9988"
	aad := crypto.BuildAAD("", "secret", crypto.CurrentCipherVersion)
	ciphertext, nonce, dek, err := crypto.EncryptPayload([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("client encryption failed: %v", err)
	}

	createReq := services.CreateSecretRequest{
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		DestroyAfterRead: true, // One-time burn
		Slug:             "db-pass-burn",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for secret, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. First Retrieval (Should succeed and consume secret)
	getReq1 := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db-pass-burn", nil)
	getRec1 := httptest.NewRecorder()
	router.ServeHTTP(getRec1, getReq1)

	if getRec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first secret read, got %d", getRec1.Code)
	}

	var payload services.SecretPayloadResponse
	_ = json.Unmarshal(getRec1.Body.Bytes(), &payload)

	cipherBytes, _ := base64.StdEncoding.DecodeString(payload.Ciphertext)
	nonceBytes, _ := base64.StdEncoding.DecodeString(payload.Nonce)

	decryptedPlaintext, err := crypto.DecryptPayload(cipherBytes, nonceBytes, dek, aad)
	if err != nil {
		t.Fatalf("failed to decrypt returned ciphertext: %v", err)
	}
	if string(decryptedPlaintext) != plaintext {
		t.Errorf("decrypted text mismatch, expected %s, got %s", plaintext, string(decryptedPlaintext))
	}

	// 3. Second Retrieval (Must return HTTP 410 Gone - burned)
	getReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db-pass-burn", nil)
	getRec2 := httptest.NewRecorder()
	router.ServeHTTP(getRec2, getReq2)

	if getRec2.Code != http.StatusGone {
		t.Errorf("expected 410 Gone on second read, got %d", getRec2.Code)
	}
}

func TestPasswordProtectedSecret(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_pwd_secrets.db")
	defer cleanup()

	plaintext := "confidential-report-content"
	password := "correct-horse-battery-staple"

	// Encrypt payload with random DEK
	aad := crypto.BuildAAD("", "secret", crypto.CurrentCipherVersion)
	ciphertext, nonce, dek, err := crypto.EncryptPayload([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Wrap DEK with password via Argon2id
	wrapped, salt, wrapNonce, paramsJSON, err := crypto.WrapKey(dek, password)
	if err != nil {
		t.Fatalf("wrap key failed: %v", err)
	}

	createReq := services.CreateSecretRequest{
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		WrappedDEK:       base64.StdEncoding.EncodeToString(append(wrapNonce, wrapped...)),
		Salt:             base64.StdEncoding.EncodeToString(salt),
		KDFParams:        paramsJSON,
		DestroyAfterRead: false,
		Slug:             "pwd-report",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	// Fetch payload
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/pwd-report", nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	var payload services.SecretPayloadResponse
	_ = json.Unmarshal(getRec.Body.Bytes(), &payload)

	wrappedData, _ := base64.StdEncoding.DecodeString(payload.WrappedDEK)
	saltData, _ := base64.StdEncoding.DecodeString(payload.Salt)
	wNonce := wrappedData[:crypto.NonceSize]
	wCipher := wrappedData[crypto.NonceSize:]

	// 1. Unwrap with incorrect password -> should error
	_, errBadPwd := crypto.UnwrapKey(wCipher, saltData, wNonce, "wrong-password", payload.KDFParams)
	if errBadPwd == nil {
		t.Errorf("expected failure with wrong password, but succeeded")
	}

	// 2. Unwrap with correct password -> should succeed
	unwrappedDEK, errGoodPwd := crypto.UnwrapKey(wCipher, saltData, wNonce, password, payload.KDFParams)
	if errGoodPwd != nil {
		t.Fatalf("unwrap failed with correct password: %v", errGoodPwd)
	}

	cBytes, _ := base64.StdEncoding.DecodeString(payload.Ciphertext)
	nBytes, _ := base64.StdEncoding.DecodeString(payload.Nonce)
	decrypted, err := crypto.DecryptPayload(cBytes, nBytes, unwrappedDEK, aad)
	if err != nil {
		t.Fatalf("payload decryption failed: %v", err)
	}
	if string(decrypted) != plaintext {
		t.Errorf("expected %s, got %s", plaintext, string(decrypted))
	}
}

func TestEndToEndRedirectPipeline(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_redirect.db")
	defer cleanup()

	reqBody := services.CreateLinkRequest{
		DestinationURL: "https://openai.com",
		Slug:           "test-slug",
		PreserveQuery:  true,
	}
	payloadBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/links", bytes.NewReader(payloadBytes))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d", rec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/test-slug?utm_source=chat", nil)
	getReq.Host = "localhost"
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", getRec.Code)
	}
}

func TestAPIKeysAndAuditLogs(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_auth_audit.db")
	defer cleanup()

	keyReq := services.CreateAPIKeyRequest{
		Name:   "auditor-key",
		Scopes: []string{"audit:read"},
	}
	keyBody, _ := json.Marshal(keyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(keyBody))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var keyResp services.CreateAPIKeyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &keyResp)

	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+keyResp.Token)
	recAuth := httptest.NewRecorder()
	router.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", recAuth.Code)
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

	reqRaw := httptest.NewRequest(http.MethodGet, "/p/go-main/raw", nil)
	recRaw := httptest.NewRecorder()
	router.ServeHTTP(recRaw, reqRaw)

	if recRaw.Code != http.StatusOK || recRaw.Body.String() != pasteReq.Content {
		t.Errorf("expected exact raw content")
	}
}
