-- +goose Up

-- Structured access policies
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    rules TEXT NOT NULL DEFAULT '{}', -- JSON serialized structured policy DSL
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

-- Associate resources with an optional access policy
ALTER TABLE resources ADD COLUMN policy_id TEXT REFERENCES policies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_policies_workspace ON policies(workspace_id);
CREATE INDEX IF NOT EXISTS idx_resources_policy ON resources(policy_id);

-- +goose Down
DROP INDEX IF EXISTS idx_resources_policy;
DROP INDEX IF EXISTS idx_policies_workspace;
DROP TABLE IF EXISTS policies;
