package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	CurrentCipherVersion = 1
	CipherSuiteAESGCM    = "AES-256-GCM"
	NonceSize            = 12 // 96 bits recommended for GCM
	KeySize              = 32 // 256 bits for AES-256
)

// AADMetadata binds critical resource properties into AEAD authentication tag
type AADMetadata struct {
	ResourceID string `json:"resource_id"`
	Type       string `json:"type"`
	Version    int    `json:"version"`
}

// BuildAAD constructs authenticated associated data JSON bytes
func BuildAAD(resourceID, resType string, version int) []byte {
	m := AADMetadata{
		ResourceID: resourceID,
		Type:       resType,
		Version:    version,
	}
	bytes, _ := json.Marshal(m)
	return bytes
}

// EncryptPayload encrypts plaintext with a random 256-bit DEK using AES-GCM
func EncryptPayload(plaintext []byte, aad []byte) (ciphertext, nonce, key []byte, err error) {
	key = make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, nil, fmt.Errorf("read random key: %w", err)
	}

	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("read random nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create gcm: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, key, nil
}

// DecryptPayload decrypts ciphertext using AES-GCM with the provided key and AAD
func DecryptPayload(ciphertext, nonce, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed or tag mismatch: %w", err)
	}

	return plaintext, nil
}

// Argon2id parameters matching OWASP baseline
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    2,
		Memory:  19 * 1024, // 19 MiB
		Threads: 1,
		KeyLen:  32,
	}
}

// WrapKey derives KEK from password via Argon2id and wraps DEK
func WrapKey(dek []byte, password string) (wrappedDEK, salt, nonce []byte, paramsJSON string, err error) {
	salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, "", err
	}

	p := DefaultKDFParams()
	kek := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, "", err
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, "", err
	}

	wrappedDEK = gcm.Seal(nil, nonce, dek, salt)
	pj, _ := json.Marshal(p)
	return wrappedDEK, salt, nonce, string(pj), nil
}

// UnwrapKey unwraps DEK using password-derived KEK
func UnwrapKey(wrappedDEK, salt, nonce []byte, password string, paramsJSON string) ([]byte, error) {
	var p KDFParams
	if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
		p = DefaultKDFParams()
	}

	kek := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dek, err := gcm.Open(nil, nonce, wrappedDEK, salt)
	if err != nil {
		return nil, fmt.Errorf("incorrect password or invalid tag: %w", err)
	}

	return dek, nil
}

// EncodeKeyFragment converts raw 32-byte DEK to base64url string for URL fragment
func EncodeKeyFragment(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKeyFragment decodes base64url fragment back to raw bytes
func DecodeKeyFragment(fragment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(fragment)
}
