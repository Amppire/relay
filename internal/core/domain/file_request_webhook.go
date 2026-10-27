package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRequestAlreadyFulfilled = errors.New("request portal has already been fulfilled")
	ErrRequestPending          = errors.New("request portal has not yet received a response")
)

type FileResource struct {
	ResourceID    uuid.UUID `json:"resource_id"`
	StorageKey    string    `json:"storage_key"`
	Filename      string    `json:"filename"`
	SizeBytes     int64     `json:"size_bytes"`
	ContentType   string    `json:"content_type"`
	Cipher        string    `json:"cipher"`
	CipherVersion int       `json:"cipher_version"`
	Nonce         []byte    `json:"nonce"`
	SHA256Hash    string    `json:"sha256_hash"`
}

type RequestResource struct {
	ResourceID       uuid.UUID  `json:"resource_id"`
	PublicKey        string     `json:"public_key"` // Base64 X25519
	SubmittedAt      *time.Time `json:"submitted_at,omitempty"`
	EncryptedPayload []byte     `json:"encrypted_payload,omitempty"`
	EncryptedKey     []byte     `json:"encrypted_key,omitempty"`
	Nonce            []byte     `json:"nonce,omitempty"`
}

func (r *RequestResource) IsFulfilled() bool {
	return r.SubmittedAt != nil
}

type Webhook struct {
	ID          uuid.UUID `json:"id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	URL         string    `json:"url"`
	Secret      string    `json:"-"`
	Events      []string  `json:"events"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

func (w *Webhook) MatchesEvent(event string) bool {
	if !w.Active {
		return false
	}
	for _, e := range w.Events {
		if e == "*" || e == event {
			return true
		}
		if strings.HasSuffix(e, ":*") && strings.HasPrefix(event, strings.TrimSuffix(e, "*")) {
			return true
		}
	}
	return false
}

// SignWebhookPayload generates HMAC-SHA256 signature for header X-Relay-Signature
func SignWebhookPayload(secret string, timestamp int64, body []byte) string {
	message := fmt.Sprintf("%d.%s", timestamp, string(body))
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
