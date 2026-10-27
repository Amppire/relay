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
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/http/handlers"
	"github.com/relay/relay/internal/http/middleware"
	"github.com/relay/relay/internal/platform/analytics"
	"github.com/relay/relay/internal/platform/cache"
	"github.com/relay/relay/internal/platform/crypto"
	"github.com/relay/relay/internal/platform/db"
	"github.com/relay/relay/internal/platform/storage"
)

func setupTestRouter(t *testing.T, dbPath string) (http.Handler, *db.SQLiteRepository, func()) {
	_ = os.Remove(dbPath)

	repo, err := db.NewSQLiteRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite repository: %v", err)
	}

	memCache := cache.NewMemoryCache()
	analyticsWorker := analytics.NewAsyncBuffer(repo, 100, 10, 50*time.Millisecond, nil)

	policyService := services.NewPolicyService(repo, nil)
	linkService := services.NewLinkService(repo, policyService, memCache, analyticsWorker, "http://localhost:8080")
	pasteService := services.NewPasteService(repo, "http://localhost:8080")
	secretService := services.NewSecretService(repo, "http://localhost:8080")
	authService := services.NewAuthService(repo)
	auditService := services.NewAuditService(repo)

	diskStore, _ := storage.NewLocalDiskStore("test_data/storage")
	fileService := services.NewFileService(repo, diskStore, "http://localhost:8080")
	requestService := services.NewRequestService(repo, "http://localhost:8080")
	webhookDispatcher := services.NewWebhookDispatcher(repo)

	authMw := middleware.NewAuthMiddleware(authService)
	apiHandler := handlers.NewAPIHandler(
		linkService, pasteService, secretService, policyService,
		fileService, requestService, webhookDispatcher,
		authService, auditService,
	)

	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.With(authMw.OptionalAuth).Post("/links", apiHandler.CreateLink)
		r.With(authMw.OptionalAuth).Post("/pastes", apiHandler.CreatePaste)
		r.With(authMw.OptionalAuth).Post("/secrets", apiHandler.CreateSecret)
		r.With(authMw.OptionalAuth).Get("/secrets/{slug}", apiHandler.GetSecretPayload)
		r.With(authMw.OptionalAuth).Post("/files", apiHandler.UploadFile)
		r.With(authMw.OptionalAuth).Post("/requests", apiHandler.CreateRequestPortal)
		r.Post("/requests/{slug}/fulfill", apiHandler.FulfillRequest)
		r.With(authMw.RequireScope("policy:write")).Post("/policies", apiHandler.CreatePolicy)
		r.With(authMw.RequireScope("policy:read")).Get("/policies", apiHandler.ListPolicies)
		r.With(authMw.RequireScope("webhook:write")).Post("/webhooks", apiHandler.CreateWebhook)
		r.Post("/api-keys", apiHandler.CreateAPIKey)
		r.With(authMw.RequireScope("audit:read")).Get("/audit", apiHandler.ListAuditLogs)
	})
	r.Get("/f/{slug}", apiHandler.DownloadFile)
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


func TestStructuredPolicyEnforcement(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_policies.db")
	defer cleanup()

	// 1. Create API key with policy:write and link:create scopes
	keyReq := services.CreateAPIKeyRequest{
		Name:   "admin-key",
		Scopes: []string{"*"},
	}
	keyBody, _ := json.Marshal(keyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(keyBody))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var keyResp services.CreateAPIKeyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &keyResp)
	token := keyResp.Token

	// 2. Create IP/CIDR restricted policy (Allow only 10.0.0.0/8)
	policyReq := services.CreatePolicyRequest{
		Name: "Internal Network Only",
		Rules: domain.PolicyRule{
			Allow: domain.RuleDefinition{
				AllowedCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}
	pBody, _ := json.Marshal(policyReq)
	pReq := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(pBody))
	pReq.Header.Set("Authorization", "Bearer "+token)
	pRec := httptest.NewRecorder()
	router.ServeHTTP(pRec, pReq)

	if pRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for policy, got %d: %s", pRec.Code, pRec.Body.String())
	}

	var createdPolicy domain.Policy
	_ = json.Unmarshal(pRec.Body.Bytes(), &createdPolicy)

	// 3. Create short link bound to this policy
	linkReq := services.CreateLinkRequest{
		DestinationURL: "https://internal.corp/admin",
		Slug:           "corp-admin",
		PolicyID:       &createdPolicy.ID,
	}
	lBody, _ := json.Marshal(linkReq)
	lReq := httptest.NewRequest(http.MethodPost, "/api/v1/links", bytes.NewReader(lBody))
	lReq.Header.Set("Authorization", "Bearer "+token)
	lRec := httptest.NewRecorder()
	router.ServeHTTP(lRec, lReq)

	if lRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for link, got %d: %s", lRec.Code, lRec.Body.String())
	}

	// 4. Access from outside IP (e.g. 203.0.113.19) -> 403 Forbidden
	deniedReq := httptest.NewRequest(http.MethodGet, "/corp-admin", nil)
	deniedReq.RemoteAddr = "203.0.113.19:1234"
	deniedRec := httptest.NewRecorder()
	router.ServeHTTP(deniedRec, deniedReq)

	if deniedRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unauthorized IP, got %d", deniedRec.Code)
	}

	// 5. Access from allowed CIDR (e.g. 10.20.30.40) -> 302 Found
	allowedReq := httptest.NewRequest(http.MethodGet, "/corp-admin", nil)
	allowedReq.RemoteAddr = "10.20.30.40:1234"
	allowedRec := httptest.NewRecorder()
	router.ServeHTTP(allowedRec, allowedReq)

	if allowedRec.Code != http.StatusFound {
		t.Errorf("expected 302 Found for authorized IP within 10.0.0.0/8, got %d", allowedRec.Code)
	}
}


func TestEncryptedFileUploadAndDownload(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_files.db")
	defer func() {
		cleanup()
		_ = os.RemoveAll("test_data")
	}()

	fileContent := []byte("confidential backup data 1234567890")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", bytes.NewReader(fileContent))
	req.Header.Set("X-Relay-Filename", "backup.sql.enc")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for file upload, got %d: %s", rec.Code, rec.Body.String())
	}

	var uploadResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &uploadResp)
	slug := uploadResp["slug"].(string)

	// Download file
	downReq := httptest.NewRequest(http.MethodGet, "/f/"+slug, nil)
	downRec := httptest.NewRecorder()
	router.ServeHTTP(downRec, downReq)

	if downRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for file download, got %d", downRec.Code)
	}

	if !bytes.Equal(downRec.Body.Bytes(), fileContent) {
		t.Errorf("downloaded bytes mismatch with uploaded bytes")
	}
}

func TestAsymmetricRequestPortal(t *testing.T) {
	router, _, cleanup := setupTestRouter(t, "test_requests.db")
	defer cleanup()

	// 1. Requester generates X25519 keypair
	privKey, pubKey, err := crypto.GenerateAsymmetricKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	_ = privKey

	// 2. Create collection portal
	pReqBody, _ := json.Marshal(services.CreateRequestPortalInput{
		PublicKey: pubKey,
		Title:     "API Keys Request",
		Slug:      "drop-keys",
	})
	pReq := httptest.NewRequest(http.MethodPost, "/api/v1/requests", bytes.NewReader(pReqBody))
	pRec := httptest.NewRecorder()
	router.ServeHTTP(pRec, pReq)

	if pRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for request portal, got %d: %s", pRec.Code, pRec.Body.String())
	}

	// 3. Sender drops secret into portal
	dropBody, _ := json.Marshal(map[string]string{
		"payload":       base64.StdEncoding.EncodeToString([]byte("cipher-credentials")),
		"encrypted_key": base64.StdEncoding.EncodeToString([]byte("wrapped-key")),
		"nonce":         base64.StdEncoding.EncodeToString([]byte("nonce1234567")),
	})
	dropReq := httptest.NewRequest(http.MethodPost, "/api/v1/requests/drop-keys/fulfill", bytes.NewReader(dropBody))
	dropRec := httptest.NewRecorder()
	router.ServeHTTP(dropRec, dropReq)

	if dropRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for fulfill, got %d: %s", dropRec.Code, dropRec.Body.String())
	}

	// 4. Second fulfill must be rejected (409 Conflict - single-use portal)
	dropRec2 := httptest.NewRecorder()
	dropReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/requests/drop-keys/fulfill", bytes.NewReader(dropBody))
	router.ServeHTTP(dropRec2, dropReq2)

	if dropRec2.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict on duplicate fulfill, got %d", dropRec2.Code)
	}
}
