package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
	"github.com/relay/relay/internal/platform/crypto"
)

type CreateSecretRequest struct {
	Ciphertext        string     `json:"ciphertext"` // Base64 encoded
	Nonce             string     `json:"nonce"`      // Base64 encoded
	Cipher            string     `json:"cipher,omitempty"`
	CipherVersion     int        `json:"cipher_version,omitempty"`
	WrappedDEK        string     `json:"wrapped_dek,omitempty"` // Base64 encoded if password protected
	Salt              string     `json:"salt,omitempty"`
	KDFParams         string     `json:"kdf_params,omitempty"`
	EncryptedMetadata string     `json:"encrypted_metadata,omitempty"`
	DestroyAfterRead  bool       `json:"destroy_after_read"`
	Title             string     `json:"title,omitempty"`
	Slug              string     `json:"slug,omitempty"`
	Hostname          string     `json:"hostname,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

type CreateSecretResponse struct {
	LinkID     uuid.UUID  `json:"link_id"`
	ResourceID uuid.UUID  `json:"resource_id"`
	Slug       string     `json:"slug"`
	URL        string     `json:"url"` // Client appends #fragment DEK
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type SecretPayloadResponse struct {
	ResourceID        uuid.UUID  `json:"resource_id"`
	Ciphertext        string     `json:"ciphertext"`
	Cipher            string     `json:"cipher"`
	CipherVersion     int        `json:"cipher_version"`
	Nonce             string     `json:"nonce"`
	WrappedDEK        string     `json:"wrapped_dek,omitempty"`
	Salt              string     `json:"salt,omitempty"`
	KDFParams         string     `json:"kdf_params,omitempty"`
	EncryptedMetadata string     `json:"encrypted_metadata,omitempty"`
	DestroyAfterRead  bool       `json:"destroy_after_read"`
	ConsumedAt        *time.Time `json:"consumed_at,omitempty"`
}

type SecretService struct {
	repo           ports.Repository
	defaultBaseURL string
}

func NewSecretService(repo ports.Repository, defaultBaseURL string) *SecretService {
	return &SecretService{
		repo:           repo,
		defaultBaseURL: strings.TrimRight(defaultBaseURL, "/"),
	}
}

func (s *SecretService) CreateSecret(ctx context.Context, req CreateSecretRequest, actorID *uuid.UUID, actorType string) (*CreateSecretResponse, error) {
	if req.Ciphertext == "" || req.Nonce == "" {
		return nil, domain.ErrInvalidSecretPayload
	}

	rawCiphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	rawNonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	var rawWrappedDEK, rawSalt, rawEncMeta []byte
	if req.WrappedDEK != "" {
		rawWrappedDEK, _ = base64.StdEncoding.DecodeString(req.WrappedDEK)
	}
	if req.Salt != "" {
		rawSalt, _ = base64.StdEncoding.DecodeString(req.Salt)
	}
	if req.EncryptedMetadata != "" {
		rawEncMeta, _ = base64.StdEncoding.DecodeString(req.EncryptedMetadata)
	}

	cipherName := req.Cipher
	if cipherName == "" {
		cipherName = crypto.CipherSuiteAESGCM
	}
	cipherVer := req.CipherVersion
	if cipherVer == 0 {
		cipherVer = crypto.CurrentCipherVersion
	}

	ws, defaultDomain, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}

	domainID := defaultDomain.ID
	if req.Hostname != "" && req.Hostname != defaultDomain.Hostname {
		d, err := s.repo.GetDomainByHostname(ctx, req.Hostname)
		if err != nil {
			return nil, fmt.Errorf("domain: %w", err)
		}
		domainID = d.ID
	}

	slug := strings.TrimSpace(req.Slug)
	if slug == "" {
		slug = generateRandomSlug(8)
	}

	now := time.Now().UTC()
	resourceID := uuid.New()
	linkID := uuid.New()

	var maxAccesses *int64
	if req.DestroyAfterRead {
		one := int64(1)
		maxAccesses = &one
	}

	res := &domain.Resource{
		ID:          resourceID,
		WorkspaceID: ws.ID,
		CreatedBy:   actorID,
		Type:        domain.ResourceTypeSecret,
		Name:        req.Title,
		Status:      domain.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   req.ExpiresAt,
		MaxAccesses: maxAccesses,
		AccessCount: 0,
	}

	link := &domain.ResourceLink{
		ID:         linkID,
		ResourceID: resourceID,
		DomainID:   domainID,
		Slug:       slug,
		Enabled:    true,
		CreatedAt:  now,
	}

	secret := &domain.SecretResource{
		ResourceID:        resourceID,
		Ciphertext:        rawCiphertext,
		Cipher:            cipherName,
		CipherVersion:     cipherVer,
		Nonce:             rawNonce,
		WrappedDEK:        rawWrappedDEK,
		Salt:              rawSalt,
		KDFParams:         req.KDFParams,
		EncryptedMetadata: rawEncMeta,
		DestroyAfterRead:  req.DestroyAfterRead,
	}

	if err := s.repo.CreateSecretLink(ctx, res, link, secret); err != nil {
		return nil, err
	}

	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: ws.ID,
		ActorID:     actorID,
		ActorType:   actorType,
		Action:      "secret.create",
		ResourceID:  &resourceID,
		Metadata: map[string]any{
			"slug":               slug,
			"destroy_after_read": req.DestroyAfterRead,
		},
		CreatedAt: now,
	})

	fullURL := fmt.Sprintf("%s/s/%s", s.defaultBaseURL, slug)

	return &CreateSecretResponse{
		LinkID:     linkID,
		ResourceID: resourceID,
		Slug:       slug,
		URL:        fullURL,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  now,
	}, nil
}

// FetchAndBurn retrieves and immediately destroys single-use secrets atomically.
func (s *SecretService) FetchAndBurn(ctx context.Context, hostname, slug string, actorID *uuid.UUID, actorType string) (*SecretPayloadResponse, error) {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return nil, domain.ErrNotFound
		}
		d = def
	}

	resolved, err := s.repo.ResolveSecret(ctx, d.ID, slug)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if err := resolved.Resource.IsAccessible(now); err != nil {
		return nil, err
	}

	var secret *domain.SecretResource
	if resolved.Secret.DestroyAfterRead {
		// Strict atomic conditional burn
		secret, err = s.repo.ConsumeSecret(ctx, resolved.Resource.ID)
		if err != nil {
			return nil, err
		}
		_ = s.repo.IncrementAccessCount(ctx, resolved.Resource.ID)
	} else {
		secret = resolved.Secret
		_ = s.repo.IncrementAccessCount(ctx, resolved.Resource.ID)
	}

	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: resolved.Resource.WorkspaceID,
		ActorID:     actorID,
		ActorType:   actorType,
		Action:      "secret.read",
		ResourceID:  &resolved.Resource.ID,
		CreatedAt:   now,
	})

	var wrappedStr, saltStr, metaStr string
	if len(secret.WrappedDEK) > 0 {
		wrappedStr = base64.StdEncoding.EncodeToString(secret.WrappedDEK)
	}
	if len(secret.Salt) > 0 {
		saltStr = base64.StdEncoding.EncodeToString(secret.Salt)
	}
	if len(secret.EncryptedMetadata) > 0 {
		metaStr = base64.StdEncoding.EncodeToString(secret.EncryptedMetadata)
	}

	return &SecretPayloadResponse{
		ResourceID:        secret.ResourceID,
		Ciphertext:        base64.StdEncoding.EncodeToString(secret.Ciphertext),
		Cipher:            secret.Cipher,
		CipherVersion:     secret.CipherVersion,
		Nonce:             base64.StdEncoding.EncodeToString(secret.Nonce),
		WrappedDEK:        wrappedStr,
		Salt:              saltStr,
		KDFParams:         secret.KDFParams,
		EncryptedMetadata: metaStr,
		DestroyAfterRead:  secret.DestroyAfterRead,
		ConsumedAt:        secret.ConsumedAt,
	}, nil
}
