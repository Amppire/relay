package domain

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound       = errors.New("resource not found")
	ErrExpired        = errors.New("resource has expired")
	ErrMaxAccessCount = errors.New("maximum access count reached")
	ErrRevoked        = errors.New("resource has been revoked")
	ErrInactive       = errors.New("resource is not active")
	ErrAlreadyExists  = errors.New("slug already in use")
)

type ResourceType string

const (
	ResourceTypeRedirect ResourceType = "redirect"
	ResourceTypePaste    ResourceType = "paste"
	ResourceTypeSecret   ResourceType = "secret"
	ResourceTypeFile     ResourceType = "file"
	ResourceTypePayload  ResourceType = "payload"
	ResourceTypeRequest  ResourceType = "request"
)

type ResourceStatus string

const (
	StatusActive   ResourceStatus = "active"
	StatusExpired  ResourceStatus = "expired"
	StatusConsumed ResourceStatus = "consumed"
	StatusRevoked  ResourceStatus = "revoked"
)

// Resource is the universal root entity for all shareable objects.
type Resource struct {
	ID          uuid.UUID       `json:"id"`
	WorkspaceID uuid.UUID       `json:"workspace_id"`
	CreatedBy   *uuid.UUID      `json:"created_by,omitempty"`
	PolicyID    *uuid.UUID      `json:"policy_id,omitempty"`
	Type        ResourceType    `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Status      ResourceStatus  `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ActivatedAt *time.Time      `json:"activated_at,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	RevokedAt   *time.Time      `json:"revoked_at,omitempty"`
	MaxAccesses *int64          `json:"max_accesses,omitempty"`
	AccessCount int64           `json:"access_count"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

func (r *Resource) IsAccessible(now time.Time) error {
	if r.Status != StatusActive {
		return ErrInactive
	}
	if r.RevokedAt != nil && !r.RevokedAt.After(now) {
		return ErrRevoked
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
		return ErrExpired
	}
	if r.MaxAccesses != nil && r.AccessCount >= *r.MaxAccesses {
		return ErrMaxAccessCount
	}
	return nil
}

// ResourceLink is a routable handle (domain + slug) mapped to a Resource.
type ResourceLink struct {
	ID         uuid.UUID `json:"id"`
	ResourceID uuid.UUID `json:"resource_id"`
	DomainID   uuid.UUID `json:"domain_id"`
	Slug       string    `json:"slug"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// RedirectResource holds the destination specifics for redirect type.
type RedirectResource struct {
	ResourceID    uuid.UUID `json:"resource_id"`
	DestinationURL string    `json:"destination_url"`
	RedirectCode  int       `json:"redirect_code"` // 301, 302, 307, 308 (default 302)
	PreserveQuery bool      `json:"preserve_query"`
	FallbackURL   *string   `json:"fallback_url,omitempty"`
}

// Workspace groups resources and domain links.
type Workspace struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Domain defines a custom host for slugs (e.g. go.company.com).
type Domain struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	Hostname    string    `json:"hostname"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
}
