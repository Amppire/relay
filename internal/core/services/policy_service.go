package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type CreatePolicyRequest struct {
	WorkspaceID *uuid.UUID        `json:"workspace_id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Rules       domain.PolicyRule `json:"rules"`
}

type PolicyService struct {
	repo      ports.Repository
	evaluator domain.Evaluator
}

func NewPolicyService(repo ports.Repository, evaluator domain.Evaluator) *PolicyService {
	if evaluator == nil {
		evaluator = domain.NewNativeEvaluator()
	}
	return &PolicyService{
		repo:      repo,
		evaluator: evaluator,
	}
}

func (s *PolicyService) CreatePolicy(ctx context.Context, req CreatePolicyRequest, actorID *uuid.UUID) (*domain.Policy, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}

	wsID := uuid.Nil
	if req.WorkspaceID != nil {
		wsID = *req.WorkspaceID
	}
	if wsID == uuid.Nil {
		ws, _, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if err != nil {
			return nil, err
		}
		wsID = ws.ID
	}

	now := time.Now().UTC()
	policy := &domain.Policy{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		Name:        req.Name,
		Description: req.Description,
		Version:     1,
		Rules:       req.Rules,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreatePolicy(ctx, policy); err != nil {
		return nil, err
	}

	_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		ActorID:     actorID,
		ActorType:   "user",
		Action:      "policy.create",
		ResourceID:  &policy.ID,
		Metadata: map[string]any{
			"policy_name": policy.Name,
		},
		CreatedAt: now,
	})

	return policy, nil
}

func (s *PolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.Policy, error) {
	return s.repo.GetPolicyByID(ctx, id)
}

func (s *PolicyService) ListPolicies(ctx context.Context, workspaceID uuid.UUID) ([]domain.Policy, error) {
	if workspaceID == uuid.Nil {
		ws, _, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if err != nil {
			return nil, err
		}
		workspaceID = ws.ID
	}
	return s.repo.ListPolicies(ctx, workspaceID)
}

// EvaluateAccess evaluates an access attempt against a resource's policy
func (s *PolicyService) EvaluateAccess(ctx context.Context, resource *domain.Resource, evalCtx domain.EvaluationContext) (bool, string, error) {
	if resource.PolicyID == nil {
		// No policy explicitly bound -> Allowed
		return true, "no policy bound", nil
	}

	policy, err := s.repo.GetPolicyByID(ctx, *resource.PolicyID)
	if err != nil {
		return false, "policy not found", err
	}

	decision, reason, err := s.evaluator.Evaluate(evalCtx, policy)
	if err != nil {
		return false, reason, err
	}

	if decision == domain.DecisionDeny {
		// Log policy denial
		_ = s.repo.RecordAuditEvent(ctx, &domain.AuditEvent{
			ID:          uuid.New(),
			WorkspaceID: resource.WorkspaceID,
			ActorID:     evalCtx.ActorID,
			ActorType:   "anonymous",
			Action:      "policy.denied",
			ResourceID:  &resource.ID,
			IP:          evalCtx.ClientIP,
			Metadata: map[string]any{
				"reason": reason,
			},
			CreatedAt: time.Now().UTC(),
		})
		return false, reason, domain.ErrPolicyDenied
	}

	return true, reason, nil
}
