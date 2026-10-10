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

type CreatePasteRequest struct {
	Content        string             `json:"content"`
	Format         domain.PasteFormat `json:"format,omitempty"` // plaintext, markdown, code
	Language       string             `json:"language,omitempty"`
	Title          string             `json:"title,omitempty"`
	Slug           string             `json:"slug,omitempty"`
	Hostname       string             `json:"hostname,omitempty"`
	ExpiresAt      *time.Time         `json:"expires_at,omitempty"`
	MaxAccesses    *int64             `json:"max_accesses,omitempty"`
	LineNumbers    bool               `json:"line_numbers"`
	RawEnabled     bool               `json:"raw_enabled"`
}

type CreatePasteResponse struct {
	LinkID      uuid.UUID          `json:"link_id"`
	ResourceID  uuid.UUID          `json:"resource_id"`
	Slug        string             `json:"slug"`
	URL         string             `json:"url"`
	RawURL      string             `json:"raw_url"`
	Format      domain.PasteFormat `json:"format"`
	Language    string             `json:"language,omitempty"`
	ExpiresAt   *time.Time         `json:"expires_at,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
}

type PasteService struct {
	repo           ports.Repository
	defaultBaseURL string
}

func NewPasteService(repo ports.Repository, defaultBaseURL string) *PasteService {
	return &PasteService{
		repo:           repo,
		defaultBaseURL: strings.TrimRight(defaultBaseURL, "/"),
	}
}

func (s *PasteService) CreatePaste(ctx context.Context, req CreatePasteRequest, actorID *uuid.UUID, actorType string) (*CreatePasteResponse, error) {
	if strings.TrimSpace(req.Content) == "" {
		return nil, domain.ErrEmptyPasteContent
	}

	ws, defaultDomain, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}

	domainID := defaultDomain.ID
	if req.Hostname != "" && req.Hostname != defaultDomain.Hostname {
		d, err := s.repo.GetDomainByHostname(ctx, req.Hostname)
		if err != nil {
			return nil, fmt.Errorf("invalid hostname: %w", err)
		}
		domainID = d.ID
	}

	slug := strings.TrimSpace(req.Slug)
	if slug == "" {
		slug = generateRandomSlug(6)
	}

	format := req.Format
	if format == "" {
		format = domain.FormatPlaintext
	}

	now := time.Now().UTC()
	resourceID := uuid.New()
	linkID := uuid.New()

	res := &domain.Resource{
		ID:          resourceID,
		WorkspaceID: ws.ID,
		CreatedBy:   actorID,
		Type:        domain.ResourceTypePaste,
		Name:        req.Title,
		Status:      domain.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   req.ExpiresAt,
		MaxAccesses: req.MaxAccesses,
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

	paste := &domain.PasteResource{
		ResourceID:  resourceID,
		Content:     req.Content,
		Format:      format,
		Language:    req.Language,
		LineNumbers: req.LineNumbers,
		RawEnabled:  req.RawEnabled,
	}

	if err := s.repo.CreatePasteLink(ctx, res, link, paste); err != nil {
		return nil, err
	}

	// Record audit event
	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: ws.ID,
		ActorID:     actorID,
		ActorType:   actorType,
		Action:      "paste.create",
		ResourceID:  &resourceID,
		Metadata: map[string]any{
			"slug":   slug,
			"format": string(format),
			"lang":   req.Language,
		},
		CreatedAt: now,
	})

	fullURL := fmt.Sprintf("%s/p/%s", s.defaultBaseURL, slug)
	rawURL := fmt.Sprintf("%s/p/%s/raw", s.defaultBaseURL, slug)

	return &CreatePasteResponse{
		LinkID:     linkID,
		ResourceID: resourceID,
		Slug:       slug,
		URL:        fullURL,
		RawURL:     rawURL,
		Format:     format,
		Language:   req.Language,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  now,
	}, nil
}

func (s *PasteService) GetPaste(ctx context.Context, hostname, slug string) (*ports.ResolvedPaste, error) {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return nil, domain.ErrNotFound
		}
		d = def
	}

	resolved, err := s.repo.ResolvePaste(ctx, d.ID, slug)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if err := resolved.Resource.IsAccessible(now); err != nil {
		return nil, err
	}

	_ = s.repo.IncrementAccessCount(ctx, resolved.Resource.ID)

	return resolved, nil
}
