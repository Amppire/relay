package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ObjectStore interface {
	PutObject(ctx context.Context, key string, r io.Reader) error
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	DeleteObject(ctx context.Context, key string) error
}

// LocalDiskStore stores files in a base directory on the local filesystem
type LocalDiskStore struct {
	baseDir string
}

func NewLocalDiskStore(baseDir string) (*LocalDiskStore, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	return &LocalDiskStore{baseDir: baseDir}, nil
}

func (s *LocalDiskStore) PutObject(ctx context.Context, key string, r io.Reader) error {
	path := filepath.Join(s.baseDir, filepath.Clean(key))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	return err
}

func (s *LocalDiskStore) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	path := filepath.Join(s.baseDir, filepath.Clean(key))
	return os.Open(path)
}

func (s *LocalDiskStore) DeleteObject(ctx context.Context, key string) error {
	path := filepath.Join(s.baseDir, filepath.Clean(key))
	return os.Remove(path)
}
