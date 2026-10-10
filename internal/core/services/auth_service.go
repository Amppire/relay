package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type CreateAPIKeyRequest struct {
	WorkspaceID uuid.UUID  `json:"workspace_id,omitempty"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Token     string     `json:"token"` // The raw secret token, returned ONLY ONCE
	KeyPrefix string     `json:"key_prefix"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type AuthService struct {
	repo ports.Repository
}

func NewAuthService(repo ports.Repository) *AuthService {
	return &AuthService{repo: repo}
}

// GenerateAPIKey creates an opaque token with format: rly_live_<base64url_32bytes>
func (s *AuthService) GenerateAPIKey(ctx context.Context, req CreateAPIKeyRequest, actorID *uuid.UUID) (*CreateAPIKeyResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("api key name cannot be empty")
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"*"}
	}

	wsID := req.WorkspaceID
	if wsID == uuid.Nil {
		ws, _, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if err != nil {
			return nil, fmt.Errorf("default workspace: %w", err)
		}
		wsID = ws.ID
	}

	rawRandom := make([]byte, 24)
	if _, err := rand.Read(rawRandom); err != nil {
		return nil, fmt.Errorf("entropy source: %w", err)
	}

	tokenSecret := base64.RawURLEncoding.EncodeToString(rawRandom)
	rawToken := fmt.Sprintf("rly_live_%s", tokenSecret)
	prefix := rawToken[:12] // "rly_live_XXXX"
	tokenHash := domain.HashToken(rawToken)

	now := time.Now().UTC()
	keyID := uuid.New()

	key := &domain.APIKey{
		ID:          keyID,
		WorkspaceID: wsID,
		Name:        name,
		KeyPrefix:   prefix,
		KeyHash:     tokenHash,
		Scopes:      req.Scopes,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   now,
	}

	if err := s.repo.CreateAPIKey(ctx, key); err != nil {
		return nil, fmt.Errorf("save api key: %w", err)
	}

	// Audit trail
	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		ActorID:     actorID,
		ActorType:   "user",
		Action:      "api_key.create",
		Metadata: map[string]any{
			"key_id":     keyID.String(),
			"key_name":   name,
			"key_prefix": prefix,
			"scopes":     req.Scopes,
		},
		CreatedAt: now,
	})

	return &CreateAPIKeyResponse{
		ID:        keyID,
		Name:      name,
		Token:     rawToken,
		KeyPrefix: prefix,
		Scopes:    req.Scopes,
		ExpiresAt: req.ExpiresAt,
		CreatedAt: now,
	}, nil
}

// Authenticate validates a bearer token and returns the corresponding APIKey record.
func (s *AuthService) Authenticate(ctx context.Context, rawToken string) (*domain.APIKey, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, domain.ErrInvalidAPIKey
	}

	hash := domain.HashToken(rawToken)
	key, err := s.repo.GetAPIKeyByHash(ctx, hash)
	if err != nil {
		return nil, domain.ErrInvalidAPIKey
	}

	if !key.IsActive(time.Now().UTC()) {
		return nil, domain.ErrInvalidAPIKey
	}

	return key, nil
}

func (s *AuthService) RevokeAPIKey(ctx context.Context, workspaceID, keyID uuid.UUID, actorID *uuid.UUID) error {
	if err := s.repo.RevokeAPIKey(ctx, workspaceID, keyID); err != nil {
		return err
	}

	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		ActorID:     actorID,
		ActorType:   "user",
		Action:      "api_key.revoke",
		Metadata: map[string]any{
			"key_id": keyID.String(),
		},
		CreatedAt: time.Now().UTC(),
	})

	return nil
}

func (s *AuthService) ListAPIKeys(ctx context.Context, workspaceID uuid.UUID) ([]domain.APIKey, error) {
	return s.repo.ListAPIKeys(ctx, workspaceID)
}
