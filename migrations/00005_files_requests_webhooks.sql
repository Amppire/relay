-- +goose Up

-- File resources: metadata for encrypted files stored in object storage
CREATE TABLE IF NOT EXISTS file_resources (
    resource_id TEXT PRIMARY KEY,
    storage_key TEXT NOT NULL,              -- object key or path on disk/S3
    filename TEXT NOT NULL,                 -- original filename (encrypted or display)
    size_bytes INTEGER NOT NULL,            -- encrypted payload size
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    cipher TEXT NOT NULL,                   -- 'AES-256-GCM'
    cipher_version INTEGER NOT NULL DEFAULT 1,
    nonce BLOB NOT NULL,                    -- initialization vector
    sha256_hash TEXT NOT NULL,              -- integrity checksum of encrypted file
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

-- Request resources: asymmetric portals ("Send creds/files to me")
CREATE TABLE IF NOT EXISTS request_resources (
    resource_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,               -- requester's Base64-encoded X25519 public key
    submitted_at TIMESTAMP,                 -- when the recipient fulfilled the request
    encrypted_payload BLOB,                 -- ciphertext uploaded by recipient
    encrypted_key BLOB,                     -- symmetric DEK encrypted with requester's public key
    nonce BLOB,                             -- nonce for payload
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

-- Webhooks: HMAC-SHA256 signed event notifications
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,                   -- HMAC signing secret
    events TEXT NOT NULL,                   -- comma-separated: resource.created, secret.consumed, etc.
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_storage ON file_resources(storage_key);
CREATE INDEX IF NOT EXISTS idx_webhooks_workspace ON webhooks(workspace_id);

-- +goose Down
DROP TABLE IF EXISTS webhooks;
DROP TABLE IF EXISTS request_resources;
DROP TABLE IF EXISTS file_resources;
