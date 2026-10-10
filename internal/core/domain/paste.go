package domain

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrEmptyPasteContent = errors.New("paste content cannot be empty")
)

type PasteFormat string

const (
	FormatPlaintext PasteFormat = "plaintext"
	FormatMarkdown  PasteFormat = "markdown"
	FormatCode      PasteFormat = "code"
)

type PasteResource struct {
	ResourceID  uuid.UUID   `json:"resource_id"`
	Content     string      `json:"content"`
	Format      PasteFormat `json:"format"`
	Language    string      `json:"language,omitempty"`
	LineNumbers bool        `json:"line_numbers"`
	RawEnabled  bool        `json:"raw_enabled"`
}
