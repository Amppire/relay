package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
)

type CreateWebhookRequest struct {
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty"`
	URL         string     `json:"url"`
	Secret      string     `json:"secret,omitempty"`
	Events      []string   `json:"events"`
}

type WebhookDispatcher struct {
	repo   ports.Repository
	client *http.Client
}

func NewWebhookDispatcher(repo ports.Repository) *WebhookDispatcher {
	return &WebhookDispatcher{
		repo: repo,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (d *WebhookDispatcher) RegisterWebhook(ctx context.Context, req CreateWebhookRequest) (*domain.Webhook, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("url cannot be empty")
	}

	wsID := uuid.Nil
	if req.WorkspaceID != nil {
		wsID = *req.WorkspaceID
	}
	if wsID == uuid.Nil {
		ws, _, err := d.repo.GetOrCreateDefaultWorkspace(ctx)
		if err != nil {
			return nil, err
		}
		wsID = ws.ID
	}

	secret := req.Secret
	if secret == "" {
		secret = generateRandomSlug(24)
	}

	wh := &domain.Webhook{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		URL:         req.URL,
		Secret:      secret,
		Events:      req.Events,
		Active:      true,
		CreatedAt:   time.Now().UTC(),
	}

	if err := d.repo.CreateWebhook(ctx, wh); err != nil {
		return nil, err
	}

	return wh, nil
}

// DispatchEvent asynchronously fires signed webhooks matching the event
func (d *WebhookDispatcher) DispatchEvent(workspaceID uuid.UUID, eventName string, payload any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		hooks, err := d.repo.ListWebhooks(ctx, workspaceID)
		if err != nil || len(hooks) == 0 {
			return
		}

		bodyBytes, err := json.Marshal(map[string]any{
			"event":     eventName,
			"timestamp": time.Now().UTC().Unix(),
			"payload":   payload,
		})
		if err != nil {
			return
		}

		now := time.Now().UTC().Unix()
		for _, hook := range hooks {
			if hook.MatchesEvent(eventName) {
				sig := domain.SignWebhookPayload(hook.Secret, now, bodyBytes)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(bodyBytes))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Relay-Signature", sig)
				req.Header.Set("X-Relay-Event", eventName)

				resp, err := d.client.Do(req)
				if err == nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()
}
