package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type AuditService struct {
	repo ports.Repository
}

func NewAuditService(repo ports.Repository) *AuditService {
	return &AuditService{repo: repo}
}

func (s *AuditService) ListEvents(ctx context.Context, workspaceID uuid.UUID, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if workspaceID == uuid.Nil {
		ws, _, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if err != nil {
			return nil, err
		}
		workspaceID = ws.ID
	}
	return s.repo.ListAuditEvents(ctx, workspaceID, limit)
}
