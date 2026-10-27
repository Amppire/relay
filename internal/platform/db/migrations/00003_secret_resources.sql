-- +goose Up

-- Zero-knowledge encrypted secret storage
CREATE TABLE IF NOT EXISTS secret_resources (
    resource_id TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    cipher TEXT NOT NULL,                   -- 'AES-256-GCM'
    cipher_version INTEGER NOT NULL,        -- 1
    nonce BLOB NOT NULL,
    wrapped_dek BLOB,                       -- populated only if password protected
    salt BLOB,                              -- KDF salt (for Argon2id if password protected)
    kdf_params TEXT,                        -- JSON params (memory, iterations, parallelism)
    encrypted_metadata BLOB,
    destroy_after_read BOOLEAN NOT NULL DEFAULT TRUE,
    consumed_at TIMESTAMP,
    FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secret_consumed ON secret_resources(resource_id, consumed_at);

-- +goose Down
DROP TABLE IF EXISTS secret_resources;
