-- +goose Up
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    created_by TEXT,
    type TEXT NOT NULL,
    name TEXT,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    activated_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    max_accesses INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS resource_links (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(domain_id, slug),
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY(domain_id) REFERENCES domains(id)
);

CREATE TABLE IF NOT EXISTS redirect_resources (
    resource_id TEXT PRIMARY KEY,
    destination_url TEXT NOT NULL,
    redirect_code INTEGER NOT NULL DEFAULT 302,
    preserve_query BOOLEAN NOT NULL DEFAULT TRUE,
    fallback_url TEXT,
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analytics_events (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    ip TEXT,
    user_agent TEXT,
    referer TEXT,
    country TEXT,
    device TEXT,
    browser TEXT,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(link_id) REFERENCES resource_links(id) ON DELETE CASCADE,
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_links_domain_slug ON resource_links(domain_id, slug);
CREATE INDEX IF NOT EXISTS idx_analytics_link_time ON analytics_events(link_id, timestamp);

-- +goose Down
DROP TABLE IF EXISTS analytics_events;
DROP TABLE IF EXISTS redirect_resources;
DROP TABLE IF EXISTS resource_links;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS workspaces;
