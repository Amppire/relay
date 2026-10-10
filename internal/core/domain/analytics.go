package domain

import (
	"time"

	"github.com/google/uuid"
)

type AnalyticsEvent struct {
	ID             uuid.UUID `json:"id"`
	LinkID         uuid.UUID `json:"link_id"`
	ResourceID     uuid.UUID `json:"resource_id"`
	Timestamp      time.Time `json:"timestamp"`
	IP             string    `json:"ip"` // Truncated / hashed
	UserAgent      string    `json:"user_agent"`
	Referer        string    `json:"referer"`
	Country        string    `json:"country,omitempty"`
	Device         string    `json:"device,omitempty"`
	Browser        string    `json:"browser,omitempty"`
	ResponseTimeMs int64     `json:"response_time_ms"`
}
