package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidAPIKey = errors.New("invalid or revoked API key")
	ErrInsufficientScope = errors.New("insufficient API key scope")
)

type Role string

const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleEditor  Role = "editor"
	RoleViewer  Role = "viewer"
	RoleAuditor Role = "auditor"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WorkspaceMember struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	UserID      uuid.UUID `json:"user_id"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

type APIKey struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"key_prefix"`
	KeyHash     string     `json:"-"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func HashToken(rawToken string) string {
	digest := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(digest[:])
}

func (k *APIKey) HasScope(requiredScope string) bool {
	for _, s := range k.Scopes {
		if s == "*" || s == requiredScope {
			return true
		}
		// e.g. "link:*" matches "link:create"
		if strings.HasSuffix(s, ":*") && strings.HasPrefix(requiredScope, strings.TrimSuffix(s, "*")) {
			return true
		}
	}
	return false
}

func (k *APIKey) IsActive(now time.Time) bool {
	if k.RevokedAt != nil && !k.RevokedAt.After(now) {
		return false
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
		return false
	}
	return true
}

type AuditEvent struct {
	ID          uuid.UUID         `json:"id"`
	WorkspaceID uuid.UUID         `json:"workspace_id"`
	ActorID     *uuid.UUID        `json:"actor_id,omitempty"`
	ActorType   string            `json:"actor_type"` // "user", "api_key", "system"
	Action      string            `json:"action"`     // "link.create", "paste.create", etc.
	ResourceID  *uuid.UUID        `json:"resource_id,omitempty"`
	IP          string            `json:"ip,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}
