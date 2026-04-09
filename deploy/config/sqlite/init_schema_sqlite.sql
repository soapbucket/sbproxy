-- Initialize the config_storage table for SQLite
-- This table stores origin configurations with hostname as key and JSON config as value

CREATE TABLE IF NOT EXISTS config_storage (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index on key for faster lookups
CREATE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key);

