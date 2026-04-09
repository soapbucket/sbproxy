-- Initialize the config_storage table for PostgreSQL
-- This table stores origin configurations with hostname as key and JSON config as value

CREATE TABLE IF NOT EXISTS config_storage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL,
    value BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ensure id column has default (in case table already existed without it)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_attrdef ad
        JOIN pg_attribute a ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attrelid = 'config_storage'::regclass
        AND a.attname = 'id'
    ) THEN
        ALTER TABLE config_storage ALTER COLUMN id SET DEFAULT gen_random_uuid();
    END IF;
END $$;

-- Create index on key for faster lookups
CREATE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key);

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_config_storage_updated_at ON config_storage;
CREATE TRIGGER update_config_storage_updated_at
    BEFORE UPDATE ON config_storage
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

