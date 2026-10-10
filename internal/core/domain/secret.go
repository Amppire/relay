package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrSecretAlreadyConsumed = errors.New("secret has already been consumed or destroyed")
	ErrInvalidSecretPayload  = errors.New("invalid ciphertext, nonce, or cipher specification")
	ErrDecryptionFailed      = errors.New("decryption failed: incorrect key or corrupted ciphertext")
)

type SecretResource struct {
	ResourceID        uuid.UUID  `json:"resource_id"`
	Ciphertext        []byte     `json:"ciphertext"`
	Cipher            string     `json:"cipher"`            // AES-256-GCM
	CipherVersion     int        `json:"cipher_version"`    // 1
	Nonce             []byte     `json:"nonce"`
	WrappedDEK        []byte     `json:"wrapped_dek,omitempty"`
	Salt              []byte     `json:"salt,omitempty"`
	KDFParams         string     `json:"kdf_params,omitempty"`
	EncryptedMetadata []byte     `json:"encrypted_metadata,omitempty"`
	DestroyAfterRead  bool       `json:"destroy_after_read"`
	ConsumedAt        *time.Time `json:"consumed_at,omitempty"`
}

func (s *SecretResource) IsConsumed() bool {
	return s.ConsumedAt != nil
}
