package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
)

// ResolvedRedirect is returned by the redirect resolver.
type ResolvedRedirect struct {
	Resource *domain.Resource
	Link     *domain.ResourceLink
	Redirect *domain.RedirectResource
}

// ResolvedPaste is returned by the paste resolver.
type ResolvedPaste struct {
	Resource *domain.Resource
	Link     *domain.ResourceLink
	Paste    *domain.PasteResource
}

// ResolvedSecret is returned by the secret resolver.
type ResolvedSecret struct {
	Resource *domain.Resource
	Link     *domain.ResourceLink
	Secret   *domain.SecretResource
}

type Repository interface {
	// Workspace & Domain
	GetOrCreateDefaultWorkspace(ctx context.Context) (*domain.Workspace, *domain.Domain, error)
	GetDomainByHostname(ctx context.Context, hostname string) (*domain.Domain, error)

	// Resource & Links
	CreateRedirectLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, redir *domain.RedirectResource) error
	CreatePasteLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, paste *domain.PasteResource) error
	CreateSecretLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, secret *domain.SecretResource) error
	ResolveLink(ctx context.Context, domainID uuid.UUID, slug string) (*ResolvedRedirect, error)
	ResolvePaste(ctx context.Context, domainID uuid.UUID, slug string) (*ResolvedPaste, error)
	ResolveSecret(ctx context.Context, domainID uuid.UUID, slug string) (*ResolvedSecret, error)
	ConsumeSecret(ctx context.Context, resourceID uuid.UUID) (*domain.SecretResource, error)
	GetResourceByID(ctx context.Context, id uuid.UUID) (*domain.Resource, error)
	IncrementAccessCount(ctx context.Context, resourceID uuid.UUID) error
	DeleteLink(ctx context.Context, id uuid.UUID) error

	// Policies
	CreatePolicy(ctx context.Context, policy *domain.Policy) error
	GetPolicyByID(ctx context.Context, id uuid.UUID) (*domain.Policy, error)
	ListPolicies(ctx context.Context, workspaceID uuid.UUID) ([]domain.Policy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error

	// API Keys
	CreateAPIKey(ctx context.Context, key *domain.APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error)
	ListAPIKeys(ctx context.Context, workspaceID uuid.UUID) ([]domain.APIKey, error)
	RevokeAPIKey(ctx context.Context, workspaceID, id uuid.UUID) error

	// Audit Logs
	RecordAuditEvent(ctx context.Context, event *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, workspaceID uuid.UUID, limit int) ([]domain.AuditEvent, error)

	// Analytics
	RecordAnalyticsEvents(ctx context.Context, events []domain.AnalyticsEvent) error
}

type Cache interface {
	Get(ctx context.Context, key string) (*ResolvedRedirect, bool)
	Set(ctx context.Context, key string, val *ResolvedRedirect)
	Delete(ctx context.Context, key string)
}

type AnalyticsBuffer interface {
	Enqueue(event domain.AnalyticsEvent)
	Flush(ctx context.Context) error
	Close() error
}
