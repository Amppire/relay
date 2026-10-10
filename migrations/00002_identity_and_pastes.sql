-- +goose Up

-- Users and local identity
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Workspace membership & RBAC
CREATE TABLE IF NOT EXISTS workspace_members (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL, -- owner, admin, editor, viewer, auditor
    created_at TIMESTAMP NOT NULL,
    UNIQUE(workspace_id, user_id),
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API keys: store SHA-256 digests, display raw key only once
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,      -- e.g. "rly_live_7N9f" for safe display in UI
    key_hash TEXT NOT NULL UNIQUE, -- hex-encoded SHA-256 of the raw secret token
    scopes TEXT NOT NULL,          -- comma-separated: link:read,link:create,paste:create,etc.
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

-- Append-only audit events
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    actor_id TEXT,
    actor_type TEXT NOT NULL, -- 'user', 'api_key', 'system'
    action TEXT NOT NULL,     -- 'link.create', 'paste.create', 'api_key.create', etc.
    resource_id TEXT,
    ip TEXT,
    user_agent TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

-- Paste resources (text / markdown / code)
CREATE TABLE IF NOT EXISTS paste_resources (
    resource_id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'plaintext', -- plaintext, markdown, code
    language TEXT,                           -- go, python, js, json, yaml, etc.
    line_numbers BOOLEAN NOT NULL DEFAULT TRUE,
    raw_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_audit_workspace_time ON audit_events(workspace_id, created_at);

-- +goose Down
DROP TABLE IF EXISTS paste_resources;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS workspace_members;
DROP TABLE IF EXISTS users;
