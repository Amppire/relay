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

type CreateLinkRequest struct {
	DestinationURL string     `json:"destination_url"`
	Slug           string     `json:"slug,omitempty"`
	Hostname       string     `json:"hostname,omitempty"`
	RedirectCode   int        `json:"redirect_code,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	MaxAccesses    *int64     `json:"max_accesses,omitempty"`
	FallbackURL    *string    `json:"fallback_url,omitempty"`
	PreserveQuery  bool       `json:"preserve_query"`
}

type CreateLinkResponse struct {
	LinkID         uuid.UUID  `json:"link_id"`
	ResourceID     uuid.UUID  `json:"resource_id"`
	Slug           string     `json:"slug"`
	URL            string     `json:"url"`
	DestinationURL string     `json:"destination_url"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type LinkService struct {
	repo            ports.Repository
	cache           ports.Cache
	analyticsBuffer ports.AnalyticsBuffer
	defaultBaseURL  string
}

func NewLinkService(repo ports.Repository, cache ports.Cache, analytics ports.AnalyticsBuffer, defaultBaseURL string) *LinkService {
	return &LinkService{
		repo:            repo,
		cache:           cache,
		analyticsBuffer: analytics,
		defaultBaseURL:  strings.TrimRight(defaultBaseURL, "/"),
	}
}

func (s *LinkService) CreateRedirect(ctx context.Context, req CreateLinkRequest) (*CreateLinkResponse, error) {
	if req.DestinationURL == "" {
		return nil, fmt.Errorf("destination_url cannot be empty")
	}

	ws, defaultDomain, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}

	domainID := defaultDomain.ID
	domainHost := defaultDomain.Hostname

	if req.Hostname != "" && req.Hostname != domainHost {
		d, err := s.repo.GetDomainByHostname(ctx, req.Hostname)
		if err != nil {
			return nil, fmt.Errorf("invalid hostname: %w", err)
		}
		domainID = d.ID
		domainHost = d.Hostname
	}

	slug := strings.TrimSpace(req.Slug)
	if slug == "" {
		slug = generateRandomSlug(6)
	}

	redirCode := req.RedirectCode
	if redirCode == 0 {
		redirCode = 302
	}

	now := time.Now().UTC()
	resourceID := uuid.New()
	linkID := uuid.New()

	res := &domain.Resource{
		ID:          resourceID,
		WorkspaceID: ws.ID,
		Type:        domain.ResourceTypeRedirect,
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

	redir := &domain.RedirectResource{
		ResourceID:    resourceID,
		DestinationURL: req.DestinationURL,
		RedirectCode:  redirCode,
		PreserveQuery: req.PreserveQuery,
		FallbackURL:   req.FallbackURL,
	}

	if err := s.repo.CreateRedirectLink(ctx, res, link, redir); err != nil {
		return nil, err
	}

	// Warm cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("%s:%s", domainID.String(), slug)
		s.cache.Set(ctx, cacheKey, &ports.ResolvedRedirect{
			Resource: res,
			Link:     link,
			Redirect: redir,
		})
	}

	fullURL := fmt.Sprintf("%s/%s", s.defaultBaseURL, slug)

	return &CreateLinkResponse{
		LinkID:         linkID,
		ResourceID:     resourceID,
		Slug:           slug,
		URL:            fullURL,
		DestinationURL: req.DestinationURL,
		ExpiresAt:      req.ExpiresAt,
		CreatedAt:      now,
	}, nil
}

func (s *LinkService) ResolveAndTrack(ctx context.Context, hostname, slug string, clientIP, userAgent, referer, queryParams string) (string, int, error) {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return "", 0, domain.ErrNotFound
		}
		d = def
	}

	cacheKey := fmt.Sprintf("%s:%s", d.ID.String(), slug)
	var resolved *ports.ResolvedRedirect
	var hit bool

	if s.cache != nil {
		resolved, hit = s.cache.Get(ctx, cacheKey)
	}

	if !hit {
		resolved, err = s.repo.ResolveLink(ctx, d.ID, slug)
		if err != nil {
			return "", 0, err
		}
		if s.cache != nil {
			s.cache.Set(ctx, cacheKey, resolved)
		}
	}

	now := time.Now().UTC()
	if err := resolved.Resource.IsAccessible(now); err != nil {
		if resolved.Redirect.FallbackURL != nil {
			return *resolved.Redirect.FallbackURL, 302, nil
		}
		return "", 0, err
	}

	// Increment access count asynchronously or atomically
	_ = s.repo.IncrementAccessCount(ctx, resolved.Resource.ID)

	// Async analytics
	if s.analyticsBuffer != nil {
		s.analyticsBuffer.Enqueue(domain.AnalyticsEvent{
			ID:         uuid.New(),
			LinkID:     resolved.Link.ID,
			ResourceID: resolved.Resource.ID,
			Timestamp:  now,
			IP:         anonymizeIP(clientIP),
			UserAgent:  userAgent,
			Referer:    referer,
		})
	}

	dest := resolved.Redirect.DestinationURL
	if resolved.Redirect.PreserveQuery && queryParams != "" {
		if strings.Contains(dest, "?") {
			dest = dest + "&" + queryParams
		} else {
			dest = dest + "?" + queryParams
		}
	}

	return dest, resolved.Redirect.RedirectCode, nil
}

func generateRandomSlug(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func anonymizeIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0", parts[0], parts[1], parts[2])
	}
	return "0.0.0.0"
}
