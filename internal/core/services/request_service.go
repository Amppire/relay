package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type CreateRequestPortalInput struct {
	PublicKey string     `json:"public_key"` // Base64 X25519 public key
	Title     string     `json:"title,omitempty"`
	Slug      string     `json:"slug,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type RequestService struct {
	repo           ports.Repository
	defaultBaseURL string
}

func NewRequestService(repo ports.Repository, defaultBaseURL string) *RequestService {
	return &RequestService{
		repo:           repo,
		defaultBaseURL: strings.TrimRight(defaultBaseURL, "/"),
	}
}

func (s *RequestService) CreatePortal(ctx context.Context, input CreateRequestPortalInput, actorID *uuid.UUID) (string, error) {
	if input.PublicKey == "" {
		return "", fmt.Errorf("public_key cannot be empty")
	}

	ws, defDomain, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
	if err != nil {
		return "", err
	}

	slug := input.Slug
	if slug == "" {
		slug = generateRandomSlug(8)
	}

	resID := uuid.New()
	linkID := uuid.New()
	now := time.Now().UTC()

	res := &domain.Resource{
		ID:          resID,
		WorkspaceID: ws.ID,
		CreatedBy:   actorID,
		Type:        domain.ResourceTypeRequest,
		Name:        input.Title,
		Status:      domain.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   input.ExpiresAt,
	}

	link := &domain.ResourceLink{
		ID:         linkID,
		ResourceID: resID,
		DomainID:   defDomain.ID,
		Slug:       slug,
		Enabled:    true,
		CreatedAt:  now,
	}

	reqRes := &domain.RequestResource{
		ResourceID: resID,
		PublicKey:  input.PublicKey,
	}

	if err := s.repo.CreateRequestPortal(ctx, res, link, reqRes); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/r/%s", s.defaultBaseURL, slug), nil
}

func (s *RequestService) SubmitSecretToPortal(ctx context.Context, hostname, slug string, payload, encKey, nonce []byte) error {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return domain.ErrNotFound
		}
		d = def
	}

	res, _, reqRes, err := s.repo.ResolveRequest(ctx, d.ID, slug)
	if err != nil {
		return err
	}

	if err := res.IsAccessible(time.Now().UTC()); err != nil {
		return err
	}

	if reqRes.IsFulfilled() {
		return domain.ErrRequestAlreadyFulfilled
	}

	return s.repo.FulfillRequest(ctx, res.ID, payload, encKey, nonce)
}

func (s *RequestService) GetFulfilledData(ctx context.Context, hostname, slug string) (*domain.RequestResource, error) {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return nil, domain.ErrNotFound
		}
		d = def
	}

	_, _, reqRes, err := s.repo.ResolveRequest(ctx, d.ID, slug)
	if err != nil {
		return nil, err
	}

	if !reqRes.IsFulfilled() {
		return nil, domain.ErrRequestPending
	}

	return reqRes, nil
}
