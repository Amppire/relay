package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
	"github.com/relay/relay/internal/platform/storage"
)

type CreateFileRequest struct {
	Filename         string     `json:"filename"`
	ContentType      string     `json:"content_type"`
	Nonce            []byte     `json:"-"`
	DestroyAfterRead bool       `json:"destroy_after_read"`
	PolicyID         *uuid.UUID `json:"policy_id,omitempty"`
	Slug             string     `json:"slug,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

type FileService struct {
	repo           ports.Repository
	store          storage.ObjectStore
	defaultBaseURL string
}

func NewFileService(repo ports.Repository, store storage.ObjectStore, defaultBaseURL string) *FileService {
	return &FileService{
		repo:           repo,
		store:          store,
		defaultBaseURL: strings.TrimRight(defaultBaseURL, "/"),
	}
}

// UploadEncryptedFile stores ciphertext stream in ObjectStore and metadata in DB
func (s *FileService) UploadEncryptedFile(ctx context.Context, req CreateFileRequest, reader io.Reader, actorID *uuid.UUID) (*domain.ResourceLink, string, error) {
	ws, defDomain, err := s.repo.GetOrCreateDefaultWorkspace(ctx)
	if err != nil {
		return nil, "", err
	}

	slug := req.Slug
	if slug == "" {
		slug = generateRandomSlug(8)
	}

	resID := uuid.New()
	linkID := uuid.New()
	storageKey := fmt.Sprintf("files/%s/%s", ws.ID.String(), resID.String())

	// Pipe to hash and storage
	hasher := sha256.New()
	tee := io.TeeReader(reader, hasher)

	if err := s.store.PutObject(ctx, storageKey, tee); err != nil {
		return nil, "", fmt.Errorf("store object: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	now := time.Now().UTC()

	nonce := req.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, 12)
		_, _ = rand.Read(nonce)
	}

	var maxAccesses *int64
	if req.DestroyAfterRead {
		one := int64(1)
		maxAccesses = &one
	}

	res := &domain.Resource{
		ID:          resID,
		WorkspaceID: ws.ID,
		CreatedBy:   actorID,
		PolicyID:    req.PolicyID,
		Type:        domain.ResourceTypeFile,
		Name:        req.Filename,
		Status:      domain.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   req.ExpiresAt,
		MaxAccesses: maxAccesses,
		AccessCount: 0,
	}

	link := &domain.ResourceLink{
		ID:         linkID,
		ResourceID: resID,
		DomainID:   defDomain.ID,
		Slug:       slug,
		Enabled:    true,
		CreatedAt:  now,
	}

	fileMeta := &domain.FileResource{
		ResourceID:    resID,
		StorageKey:    storageKey,
		Filename:      req.Filename,
		ContentType:   req.ContentType,
		Cipher:        "AES-256-GCM",
		CipherVersion: 1,
		Nonce:         nonce,
		SHA256Hash:    checksum,
	}

	if err := s.repo.CreateFileLink(ctx, res, link, fileMeta); err != nil {
		_ = s.store.DeleteObject(ctx, storageKey)
		return nil, "", err
	}

	shareURL := fmt.Sprintf("%s/f/%s", s.defaultBaseURL, slug)
	return link, shareURL, nil
}

func (s *FileService) DownloadEncryptedFile(ctx context.Context, hostname, slug string) (*domain.FileResource, io.ReadCloser, error) {
	d, err := s.repo.GetDomainByHostname(ctx, hostname)
	if err != nil {
		_, def, defErr := s.repo.GetOrCreateDefaultWorkspace(ctx)
		if defErr != nil {
			return nil, nil, domain.ErrNotFound
		}
		d = def
	}

	res, _, fileMeta, err := s.repo.ResolveFile(ctx, d.ID, slug)
	if err != nil {
		return nil, nil, err
	}

	if err := res.IsAccessible(time.Now().UTC()); err != nil {
		return nil, nil, err
	}

	rc, err := s.store.GetObject(ctx, fileMeta.StorageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("read storage: %w", err)
	}

	_ = s.repo.IncrementAccessCount(ctx, res.ID)
	return fileMeta, rc, nil
}
