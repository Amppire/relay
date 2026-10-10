package db

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

func (r *SQLiteRepository) CreateSecretLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, secret *domain.SecretResource) error {
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
		return fmt.Errorf("insert secret resource: %w", err)
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
		return fmt.Errorf("insert secret link: %w", err)
	}

	// Insert secret_resources
	_, err = tx.ExecContext(ctx, `
		INSERT INTO secret_resources (
			resource_id, ciphertext, cipher, cipher_version, nonce, wrapped_dek, salt, kdf_params, encrypted_metadata, destroy_after_read
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		secret.ResourceID.String(), secret.Ciphertext, secret.Cipher, secret.CipherVersion, secret.Nonce,
		secret.WrappedDEK, secret.Salt, secret.KDFParams, secret.EncryptedMetadata, secret.DestroyAfterRead,
	)
	if err != nil {
		return fmt.Errorf("insert secret details: %w", err)
	}

	return tx.Commit()
}

func (r *SQLiteRepository) ResolveSecret(ctx context.Context, domainID uuid.UUID, slug string) (*ports.ResolvedSecret, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT 
			r.id, r.workspace_id, r.type, r.name, r.status, r.created_at, r.updated_at, r.expires_at, r.revoked_at, r.max_accesses, r.access_count,
			l.id, l.resource_id, l.domain_id, l.slug, l.enabled, l.created_at,
			s.ciphertext, s.cipher, s.cipher_version, s.nonce, s.wrapped_dek, s.salt, s.kdf_params, s.encrypted_metadata, s.destroy_after_read, s.consumed_at
		FROM resource_links l
		JOIN resources r ON r.id = l.resource_id
		JOIN secret_resources s ON s.resource_id = r.id
		WHERE l.domain_id = ? AND l.slug = ? AND l.enabled = TRUE
	`, domainID.String(), slug)

	var (
		rID, rWsID, rType, rStatus string
		rName                      *string
		rCreated, rUpdated         time.Time
		rExpires, rRevoked         *time.Time
		rMax                       *int64
		rAccessCount               int64

		lID, lResID, lDomID, lSlug string
		lEnabled                   bool
		lCreated                   time.Time

		ciphertext, nonce             []byte
		cipherName                    string
		cipherVer                     int
		wrappedDEK, salt, encMeta     []byte
		kdfParams                     *string
		destroyAfterRead              bool
		consumedAt                    *time.Time
	)

	err := row.Scan(
		&rID, &rWsID, &rType, &rName, &rStatus, &rCreated, &rUpdated, &rExpires, &rRevoked, &rMax, &rAccessCount,
		&lID, &lResID, &lDomID, &lSlug, &lEnabled, &lCreated,
		&ciphertext, &cipherName, &cipherVer, &nonce, &wrappedDEK, &salt, &kdfParams, &encMeta, &destroyAfterRead, &consumedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	if consumedAt != nil {
		return nil, domain.ErrSecretAlreadyConsumed
	}

	parsedRID, _ := uuid.Parse(rID)
	parsedRWsID, _ := uuid.Parse(rWsID)
	parsedLID, _ := uuid.Parse(lID)
	parsedLDomID, _ := uuid.Parse(lDomID)

	var nameStr string
	if rName != nil {
		nameStr = *rName
	}
	var kdfStr string
	if kdfParams != nil {
		kdfStr = *kdfParams
	}

	res := &domain.Resource{
		ID:          parsedRID,
		WorkspaceID: parsedRWsID,
		Type:        domain.ResourceType(rType),
		Name:        nameStr,
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

	secret := &domain.SecretResource{
		ResourceID:        parsedRID,
		Ciphertext:        ciphertext,
		Cipher:            cipherName,
		CipherVersion:     cipherVer,
		Nonce:             nonce,
		WrappedDEK:        wrappedDEK,
		Salt:              salt,
		KDFParams:         kdfStr,
		EncryptedMetadata: encMeta,
		DestroyAfterRead:  destroyAfterRead,
		ConsumedAt:        consumedAt,
	}

	return &ports.ResolvedSecret{
		Resource: res,
		Link:     link,
		Secret:   secret,
	}, nil
}

// ConsumeSecret performs atomic burn-after-read update in SQL
func (r *SQLiteRepository) ConsumeSecret(ctx context.Context, resourceID uuid.UUID) (*domain.SecretResource, error) {
	now := time.Now().UTC()
	row := r.db.QueryRowContext(ctx, `
		UPDATE secret_resources
		SET consumed_at = ?
		WHERE resource_id = ? AND consumed_at IS NULL
		RETURNING ciphertext, cipher, cipher_version, nonce, wrapped_dek, salt, kdf_params, encrypted_metadata, destroy_after_read, consumed_at
	`, now, resourceID.String())

	var (
		ciphertext, nonce         []byte
		cipherName                string
		cipherVer                 int
		wrappedDEK, salt, encMeta []byte
		kdfParams                 *string
		destroyAfterRead          bool
		consumedAt                *time.Time
	)

	err := row.Scan(&ciphertext, &cipherName, &cipherVer, &nonce, &wrappedDEK, &salt, &kdfParams, &encMeta, &destroyAfterRead, &consumedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrSecretAlreadyConsumed
		}
		return nil, err
	}

	// Also mark root resource as consumed
	_, _ = r.db.ExecContext(ctx, "UPDATE resources SET status = 'consumed' WHERE id = ?", resourceID.String())

	var kdfStr string
	if kdfParams != nil {
		kdfStr = *kdfParams
	}

	return &domain.SecretResource{
		ResourceID:        resourceID,
		Ciphertext:        ciphertext,
		Cipher:            cipherName,
		CipherVersion:     cipherVer,
		Nonce:             nonce,
		WrappedDEK:        wrappedDEK,
		Salt:              salt,
		KDFParams:         kdfStr,
		EncryptedMetadata: encMeta,
		DestroyAfterRead:  destroyAfterRead,
		ConsumedAt:        consumedAt,
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

func (r *SQLiteRepository) CreatePasteLink(ctx context.Context, res *domain.Resource, link *domain.ResourceLink, paste *domain.PasteResource) error {
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
		return fmt.Errorf("insert paste resource: %w", err)
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
		return fmt.Errorf("insert paste link: %w", err)
	}

	// Insert paste_resources
	_, err = tx.ExecContext(ctx, `
		INSERT INTO paste_resources (resource_id, content, format, language, line_numbers, raw_enabled)
		VALUES (?, ?, ?, ?, ?, ?)
	`, paste.ResourceID.String(), paste.Content, string(paste.Format), paste.Language, paste.LineNumbers, paste.RawEnabled)
	if err != nil {
		return fmt.Errorf("insert paste details: %w", err)
	}

	return tx.Commit()
}

func (r *SQLiteRepository) ResolvePaste(ctx context.Context, domainID uuid.UUID, slug string) (*ports.ResolvedPaste, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT 
			r.id, r.workspace_id, r.type, r.name, r.status, r.created_at, r.updated_at, r.expires_at, r.revoked_at, r.max_accesses, r.access_count,
			l.id, l.resource_id, l.domain_id, l.slug, l.enabled, l.created_at,
			p.content, p.format, p.language, p.line_numbers, p.raw_enabled
		FROM resource_links l
		JOIN resources r ON r.id = l.resource_id
		JOIN paste_resources p ON p.resource_id = r.id
		WHERE l.domain_id = ? AND l.slug = ? AND l.enabled = TRUE
	`, domainID.String(), slug)

	var (
		rID, rWsID, rType, rStatus string
		rName                      *string
		rCreated, rUpdated         time.Time
		rExpires, rRevoked         *time.Time
		rMax                       *int64
		rAccessCount               int64

		lID, lResID, lDomID, lSlug string
		lEnabled                   bool
		lCreated                   time.Time

		content, format string
		lang            *string
		lineNumbers     bool
		rawEnabled      bool
	)

	err := row.Scan(
		&rID, &rWsID, &rType, &rName, &rStatus, &rCreated, &rUpdated, &rExpires, &rRevoked, &rMax, &rAccessCount,
		&lID, &lResID, &lDomID, &lSlug, &lEnabled, &lCreated,
		&content, &format, &lang, &lineNumbers, &rawEnabled,
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

	var nameStr string
	if rName != nil {
		nameStr = *rName
	}
	var langStr string
	if lang != nil {
		langStr = *lang
	}

	res := &domain.Resource{
		ID:          parsedRID,
		WorkspaceID: parsedRWsID,
		Type:        domain.ResourceType(rType),
		Name:        nameStr,
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

	paste := &domain.PasteResource{
		ResourceID:  parsedRID,
		Content:     content,
		Format:      domain.PasteFormat(format),
		Language:    langStr,
		LineNumbers: lineNumbers,
		RawEnabled:  rawEnabled,
	}

	return &ports.ResolvedPaste{
		Resource: res,
		Link:     link,
		Paste:    paste,
	}, nil
}

func (r *SQLiteRepository) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	scopesStr := strings.Join(key.Scopes, ",")
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, workspace_id, name, key_prefix, key_hash, scopes, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, key.ID.String(), key.WorkspaceID.String(), key.Name, key.KeyPrefix, key.KeyHash, scopesStr, key.ExpiresAt, key.CreatedAt)
	return err
}

func (r *SQLiteRepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, workspace_id, name, key_prefix, key_hash, scopes, expires_at, last_used_at, created_at, revoked_at
		FROM api_keys
		WHERE key_hash = ?
	`, keyHash)

	var (
		id, wsID, name, prefix, hash, scopes string
		expires, lastUsed, revoked           *time.Time
		created                              time.Time
	)

	if err := row.Scan(&id, &wsID, &name, &prefix, &hash, &scopes, &expires, &lastUsed, &created, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrInvalidAPIKey
		}
		return nil, err
	}

	parsedID, _ := uuid.Parse(id)
	parsedWsID, _ := uuid.Parse(wsID)

	var scopeList []string
	if scopes != "" {
		scopeList = strings.Split(scopes, ",")
	}

	return &domain.APIKey{
		ID:          parsedID,
		WorkspaceID: parsedWsID,
		Name:        name,
		KeyPrefix:   prefix,
		KeyHash:     hash,
		Scopes:      scopeList,
		ExpiresAt:   expires,
		LastUsedAt:  lastUsed,
		CreatedAt:   created,
		RevokedAt:   revoked,
	}, nil
}

func (r *SQLiteRepository) ListAPIKeys(ctx context.Context, workspaceID uuid.UUID) ([]domain.APIKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, workspace_id, name, key_prefix, scopes, expires_at, last_used_at, created_at, revoked_at
		FROM api_keys
		WHERE workspace_id = ?
		ORDER BY created_at DESC
	`, workspaceID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []domain.APIKey
	for rows.Next() {
		var id, wsID, name, prefix, scopes string
		var expires, lastUsed, revoked *time.Time
		var created time.Time

		if err := rows.Scan(&id, &wsID, &name, &prefix, &scopes, &expires, &lastUsed, &created, &revoked); err != nil {
			return nil, err
		}

		pid, _ := uuid.Parse(id)
		pwid, _ := uuid.Parse(wsID)

		keys = append(keys, domain.APIKey{
			ID:          pid,
			WorkspaceID: pwid,
			Name:        name,
			KeyPrefix:   prefix,
			Scopes:      strings.Split(scopes, ","),
			ExpiresAt:   expires,
			LastUsedAt:  lastUsed,
			CreatedAt:   created,
			RevokedAt:   revoked,
		})
	}
	return keys, nil
}

func (r *SQLiteRepository) RevokeAPIKey(ctx context.Context, workspaceID, id uuid.UUID) error {
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at = ?
		WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL
	`, now, workspaceID.String(), id.String())
	return err
}

func (r *SQLiteRepository) RecordAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	metaJSON, _ := json.Marshal(event.Metadata)
	var actorIDStr *string
	if event.ActorID != nil {
		s := event.ActorID.String()
		actorIDStr = &s
	}
	var resIDStr *string
	if event.ResourceID != nil {
		s := event.ResourceID.String()
		resIDStr = &s
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, workspace_id, actor_id, actor_type, action, resource_id, ip, user_agent, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID.String(), event.WorkspaceID.String(), actorIDStr, event.ActorType, event.Action, resIDStr, event.IP, event.UserAgent, string(metaJSON), event.CreatedAt)
	return err
}

func (r *SQLiteRepository) ListAuditEvents(ctx context.Context, workspaceID uuid.UUID, limit int) ([]domain.AuditEvent, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, workspace_id, actor_id, actor_type, action, resource_id, ip, user_agent, metadata, created_at
		FROM audit_events
		WHERE workspace_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, workspaceID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		var id, wsID, actorType, action, metaStr string
		var actorID, resID, ip, ua *string
		var created time.Time

		if err := rows.Scan(&id, &wsID, &actorID, &actorType, &action, &resID, &ip, &ua, &metaStr, &created); err != nil {
			return nil, err
		}

		pid, _ := uuid.Parse(id)
		pwid, _ := uuid.Parse(wsID)

		var parsedActorID *uuid.UUID
		if actorID != nil {
			u, _ := uuid.Parse(*actorID)
			parsedActorID = &u
		}
		var parsedResID *uuid.UUID
		if resID != nil {
			u, _ := uuid.Parse(*resID)
			parsedResID = &u
		}

		var metaMap map[string]any
		_ = json.Unmarshal([]byte(metaStr), &metaMap)

		var ipStr, uaStr string
		if ip != nil {
			ipStr = *ip
		}
		if ua != nil {
			uaStr = *ua
		}

		events = append(events, domain.AuditEvent{
			ID:          pid,
			WorkspaceID: pwid,
			ActorID:     parsedActorID,
			ActorType:   actorType,
			Action:      action,
			ResourceID:  parsedResID,
			IP:          ipStr,
			UserAgent:   uaStr,
			Metadata:    metaMap,
			CreatedAt:   created,
		})
	}
	return events, nil
}

func stringsContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
