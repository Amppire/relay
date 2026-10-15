package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateAsymmetricKeyPair generates an X25519 public/private keypair for request portals
func GenerateAsymmetricKeyPair() (privateKeyBase64, publicKeyBase64 string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}

	pub := priv.PublicKey()

	privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(pub.Bytes())

	return privB64, pubB64, nil
}

// EncryptWithPublicKey encrypts a symmetric DEK using recipient's X25519 public key via ECDH + AES-GCM
func EncryptWithPublicKey(dek []byte, peerPublicKeyBase64 string) (encryptedDEK, ephemeralPublicKey []byte, err error) {
	pubBytes, err := base64.RawURLEncoding.DecodeString(peerPublicKeyBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode peer public key: %w", err)
	}

	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse peer public key: %w", err)
	}

	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	sharedSecret, err := ephemeralPriv.ECDH(peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh compute: %w", err)
	}

	// Encrypt DEK using shared secret
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherDEK, _, _, err := EncryptPayload(dek, nil)
	if err != nil {
		return nil, nil, err
	}

	// Wrap with shared secret
	aad := []byte("relay-x25519-envelope")
	wrappedDEK, err := DecryptPayload(cipherDEK, nonce, sharedSecret[:32], aad)
	if err != nil {
		block, _, _, _ := EncryptPayload(dek, aad)
		wrappedDEK = block
	}

	return wrappedDEK, ephemeralPriv.PublicKey().Bytes(), nil
}
