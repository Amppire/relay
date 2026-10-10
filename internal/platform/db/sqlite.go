package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/ports"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(dsn string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode & foreign keys
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		return nil, fmt.Errorf("pragma setup: %w", err)
	}

	repo := &SQLiteRepository{db: db}
	if err := repo.Migrate(); err != nil {
		return nil, fmt.Errorf("migrate db: %w", err)
	}

	return repo, nil
}

func (r *SQLiteRepository) Migrate() error {
	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	return goose.Up(r.db, "migrations")
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

func (r *SQLiteRepository) GetOrCreateDefaultWorkspace(ctx context.Context) (*domain.Workspace, *domain.Domain, error) {
	var ws domain.Workspace
	var wsID, wsName, wsSlug string
	var wsCreated, wsUpdated time.Time

	row := r.db.QueryRowContext(ctx, "SELECT id, name, slug, created_at, updated_at FROM workspaces WHERE slug = 'default'")
	err := row.Scan(&wsID, &wsName, &wsSlug, &wsCreated, &wsUpdated)

	if errors.Is(err, sql.ErrNoRows) {
		newID := uuid.New()
		now := time.Now().UTC()
		_, err = r.db.ExecContext(ctx,
			"INSERT INTO workspaces (id, name, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			newID.String(), "Default Workspace", "default", now, now,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("create default workspace: %w", err)
		}
		ws = domain.Workspace{
			ID:        newID,
			Name:      "Default Workspace",
			Slug:      "default",
			CreatedAt: now,
			UpdatedAt: now,
		}

		// Create default domain
		domID := uuid.New()
		_, err = r.db.ExecContext(ctx,
			"INSERT INTO domains (id, workspace_id, hostname, is_default, created_at) VALUES (?, ?, ?, ?, ?)",
			domID.String(), newID.String(), "localhost", true, now,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("create default domain: %w", err)
		}

		dom := &domain.Domain{
			ID:          domID,
			WorkspaceID: newID,
			Hostname:    "localhost",
			IsDefault:   true,
			CreatedAt:   now,
		}
		return &ws, dom, nil
	} else if err != nil {
		return nil, nil, err
	}

	parsedID, _ := uuid.Parse(wsID)
	ws = domain.Workspace{
		ID:        parsedID,
		Name:      wsName,
		Slug:      wsSlug,
		CreatedAt: wsCreated,
		UpdatedAt: wsUpdated,
	}

	var dID, dHost string
	var dDef bool
	var dCreated time.Time
	err = r.db.QueryRowContext(ctx, "SELECT id, hostname, is_default, created_at FROM domains WHERE workspace_id = ? AND is_default = TRUE", wsID).
		Scan(&dID, &dHost, &dDef, &dCreated)
	if err != nil {
		return nil, nil, err
	}

	domParsedID, _ := uuid.Parse(dID)
	dom := &domain.Domain{
		ID:          domParsedID,
		WorkspaceID: parsedID,
		Hostname:    dHost,
		IsDefault:   dDef,
		CreatedAt:   dCreated,
	}

	return &ws, dom, nil
}

func (r *SQLiteRepository) GetDomainByHostname(ctx context.Context, hostname string) (*domain.Domain, error) {
	var id, wsID, host string
	var isDef bool
	var created time.Time

	row := r.db.QueryRowContext(ctx, "SELECT id, workspace_id, hostname, is_default, created_at FROM domains WHERE hostname = ?", hostname)
	if err := row.Scan(&id, &wsID, &host, &isDef, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	domID, _ := uuid.Parse(id)
	workspaceID, _ := uuid.Parse(wsID)

	return &domain.Domain{
		ID:          domID,
		WorkspaceID: workspaceID,
		Hostname:    host,
		IsDefault:   isDef,
		CreatedAt:   created,
	}, nil
}

func (r *SQLiteRepository) CreateRedirectLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, redir *domain.RedirectResource) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert resource
	_, err = tx.ExecContext(ctx, `
		INSERT INTO resources (
			id, workspace_id, created_by, type, name, description, status,
			created_at, updated_at, expires_at, max_accesses, access_count, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		res.ID.String(), res.WorkspaceID.String(), nil, string(res.Type), res.Name, res.Description,
		string(res.Status), res.CreatedAt, res.UpdatedAt, res.ExpiresAt, res.MaxAccesses, res.AccessCount, "{}",
	)
	if err != nil {
		return fmt.Errorf("insert resource: %w", err)
	}

	// Insert link
	_, err = tx.ExecContext(ctx, `
		INSERT INTO resource_links (id, resource_id, domain_id, slug, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, link.ID.String(), link.ResourceID.String(), link.DomainID.String(), link.Slug, link.Enabled, link.CreatedAt)
	if err != nil {
		if stringsContains(err.Error(), "UNIQUE") {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("insert link: %w", err)
	}

	// Insert redirect
	_, err = tx.ExecContext(ctx, `
		INSERT INTO redirect_resources (resource_id, destination_url, redirect_code, preserve_query, fallback_url)
		VALUES (?, ?, ?, ?, ?)
	`, redir.ResourceID.String(), redir.DestinationURL, redir.RedirectCode, redir.PreserveQuery, redir.FallbackURL)
	if err != nil {
		return fmt.Errorf("insert redirect: %w", err)
	}

	return tx.Commit()
}

func (r *SQLiteRepository) ResolveLink(ctx context.Context, domainID uuid.UUID, slug string) (*ports.ResolvedRedirect, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT 
			r.id, r.workspace_id, r.type, r.status, r.created_at, r.updated_at, r.expires_at, r.revoked_at, r.max_accesses, r.access_count,
			l.id, l.resource_id, l.domain_id, l.slug, l.enabled, l.created_at,
			red.destination_url, red.redirect_code, red.preserve_query, red.fallback_url
		FROM resource_links l
		JOIN resources r ON r.id = l.resource_id
		JOIN redirect_resources red ON red.resource_id = r.id
		WHERE l.domain_id = ? AND l.slug = ? AND l.enabled = TRUE
	`, domainID.String(), slug)

	var (
		rID, rWsID, rType, rStatus string
		rCreated, rUpdated         time.Time
		rExpires, rRevoked         *time.Time
		rMax                       *int64
		rAccessCount               int64

		lID, lResID, lDomID, lSlug string
		lEnabled                   bool
		lCreated                   time.Time

		destURL     string
		redirCode   int
		presQuery   bool
		fallbackURL *string
	)

	err := row.Scan(
		&rID, &rWsID, &rType, &rStatus, &rCreated, &rUpdated, &rExpires, &rRevoked, &rMax, &rAccessCount,
		&lID, &lResID, &lDomID, &lSlug, &lEnabled, &lCreated,
		&destURL, &redirCode, &presQuery, &fallbackURL,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	parsedRID, _ := uuid.Parse(rID)
	parsedRWsID, _ := uuid.Parse(rWsID)
	parsedLID, _ := uuid.Parse(lID)
	parsedLDomID, _ := uuid.Parse(lDomID)

	res := &domain.Resource{
		ID:          parsedRID,
		WorkspaceID: parsedRWsID,
		Type:        domain.ResourceType(rType),
		Status:      domain.ResourceStatus(rStatus),
		CreatedAt:   rCreated,
		UpdatedAt:   rUpdated,
		ExpiresAt:   rExpires,
		RevokedAt:   rRevoked,
		MaxAccesses: rMax,
		AccessCount: rAccessCount,
	}

	link := &domain.ResourceLink{
		ID:         parsedLID,
		ResourceID: parsedRID,
		DomainID:   parsedLDomID,
		Slug:       lSlug,
		Enabled:    lEnabled,
		CreatedAt:  lCreated,
	}

	redir := &domain.RedirectResource{
		ResourceID:    parsedRID,
		DestinationURL: destURL,
		RedirectCode:  redirCode,
		PreserveQuery: presQuery,
		FallbackURL:   fallbackURL,
	}

	return &ports.ResolvedRedirect{
		Resource: res,
		Link:     link,
		Redirect: redir,
	}, nil
}

func (r *SQLiteRepository) GetLinkByID(ctx context.Context, id uuid.UUID) (*domain.ResourceLink, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, resource_id, domain_id, slug, enabled, created_at FROM resource_links WHERE id = ?", id.String())
	var lid, rid, did, slug string
	var enabled bool
	var created time.Time
	if err := row.Scan(&lid, &rid, &did, &slug, &enabled, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	plid, _ := uuid.Parse(lid)
	prid, _ := uuid.Parse(rid)
	pdid, _ := uuid.Parse(did)
	return &domain.ResourceLink{ID: plid, ResourceID: prid, DomainID: pdid, Slug: slug, Enabled: enabled, CreatedAt: created}, nil
}

func (r *SQLiteRepository) GetResourceByID(ctx context.Context, id uuid.UUID) (*domain.Resource, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, workspace_id, type, status, created_at, updated_at, expires_at, max_accesses, access_count FROM resources WHERE id = ?", id.String())
	var rid, wid, rtype, status string
	var created, updated time.Time
	var expires *time.Time
	var max *int64
	var count int64
	if err := row.Scan(&rid, &wid, &rtype, &status, &created, &updated, &expires, &max, &count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	prid, _ := uuid.Parse(rid)
	pwid, _ := uuid.Parse(wid)
	return &domain.Resource{
		ID:          prid,
		WorkspaceID: pwid,
		Type:        domain.ResourceType(rtype),
		Status:      domain.ResourceStatus(status),
		CreatedAt:   created,
		UpdatedAt:   updated,
		ExpiresAt:   expires,
		MaxAccesses: max,
		AccessCount: count,
	}, nil
}

func (r *SQLiteRepository) IncrementAccessCount(ctx context.Context, resourceID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "UPDATE resources SET access_count = access_count + 1 WHERE id = ?", resourceID.String())
	return err
}

func (r *SQLiteRepository) DeleteLink(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM resource_links WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) RecordAnalyticsEvents(ctx context.Context, events []domain.AnalyticsEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO analytics_events (
			id, link_id, resource_id, timestamp, ip, user_agent, referer, country, device, browser, response_time_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.ExecContext(ctx,
			e.ID.String(), e.LinkID.String(), e.ResourceID.String(), e.Timestamp,
			e.IP, e.UserAgent, e.Referer, e.Country, e.Device, e.Browser, e.ResponseTimeMs,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (len(substr) == 0 || (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()))
}
