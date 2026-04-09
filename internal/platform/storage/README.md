# Storage Package

This package provides a flexible storage interface with support for multiple database backends.

## Supported Backends

- **PostgreSQL** - Production-ready relational database
- **SQLite** - Embedded database, ideal for development and testing
- **File** - JSON file-based storage for read-only configurations
- **CDB** - Constant Database for fast read-only key-value storage

## Features

- **Multiple Backends**: Support for databases, files, and specialized storage formats
- **Unified Interface**: Single API for all storage operations
- **Context Support**: All operations support context cancellation
- **Binary-Safe**: Safe storage of binary data
- **Prefix Operations**: Delete operations with key prefixes
- **Upsert Operations**: Insert or update existing keys
- **Auto-Initialization**: Automatic table/schema setup
- **Driver-Based**: Easy configuration through driver selection
- **UUID Primary Keys**: Automatic UUID generation for database entries
- **Comprehensive Testing**: Full test coverage for all backends

## Database Schema

Both implementations use the same table structure with a UUID primary key:

**PostgreSQL:**
```sql
CREATE TABLE IF NOT EXISTS config_storage (
    id UUID PRIMARY KEY,
    key VARCHAR(255) NOT NULL,
    value BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key);
```

**SQLite:**
```sql
CREATE TABLE IF NOT EXISTS config_storage (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key);
```

**Key Features:**
- `id` is a UUID (stored as TEXT in SQLite) and serves as the primary key
- `key` is indexed for fast lookups
- Multiple entries can theoretically share the same key, but `Put()` updates existing keys
- Automatic timestamps for created_at and updated_at

## Usage

```go
import (
    "context"
    "github.com/soapbucket/proxy/lib/storage"
)

// PostgreSQL
settings, err := storage.NewSettingsFromDSN("postgres://user:pass@localhost/db")
if err != nil {
    // handle error
}

// SQLite
settings, err := storage.NewSettingsFromDSN("sqlite:///path/to/database.db")

// File (read-only JSON)
settings, err := storage.NewSettingsFromDSN("file:///path/to/config.json")

// CDB (read-only)
settings, err := storage.NewSettingsFromDSN("cdb:///path/to/data.cdb")

// Create storage instance
store, err := storage.NewStorage(settings)
if err != nil {
    // handle error
}
defer store.Close()

// Use the storage
ctx := context.Background()

// Put data (automatically generates UUID for databases)
err = store.Put(ctx, "my-key", []byte("my-value"))

// Get data by key
value, err := store.Get(ctx, "my-key")

// Get data by ID (if you know the UUID)
value, err := store.GetByID(ctx, "550e8400-e29b-41d4-a716-446655440000")

// Delete data by key (not supported for read-only backends)
err = store.Delete(ctx, "my-key")

// Delete by prefix (not supported for read-only backends)
err = store.DeleteByPrefix(ctx, "prefix:")
```

## Backend Types

### Database Backends (Read/Write)

**PostgreSQL**
- Production-ready relational database
- Supports concurrent access
- ACID compliance
- UUID primary keys

**SQLite**
- Embedded database
- Single-file storage
- Good for development and testing
- TEXT primary keys (UUIDs as strings)

### File Backends (Read-Only)

**File Storage**
- JSON file-based configuration storage
- Loaded once into memory
- Fast key lookups
- Ideal for configuration data

**CDB Storage**
- Constant Database format
- Fast read-only key-value storage
- Immutable data
- Optimized for read-heavy workloads

## Configuration

### Settings Structure

```go
type Settings struct {
    Driver string            `json:"driver"` // Backend driver name
    Params map[string]string `json:"params"` // Driver-specific parameters
}
```

### DSN Formats

- **PostgreSQL**: `postgres://user:pass@host:port/dbname?sslmode=disable`
- **SQLite**: `sqlite:///path/to/database.db`
- **File**: `file:///path/to/config.json`
- **CDB**: `cdb:///path/to/data.cdb`

### Direct Configuration

```go
// PostgreSQL
settings := &storage.Settings{
    Driver: "postgres",
    Params: map[string]string{
        "dsn": "postgres://user:pass@localhost/db",
    },
}

// SQLite
settings := &storage.Settings{
    Driver: "sqlite",
    Params: map[string]string{
        "path": "/path/to/database.db",
    },
}

// File
settings := &storage.Settings{
    Driver: "file",
    Params: map[string]string{
        "path": "/path/to/config.json",
    },
}

// CDB
settings := &storage.Settings{
    Driver: "cdb",
    Params: map[string]string{
        "path": "/path/to/data.cdb",
    },
}
```

## Running Tests

### SQLite Tests

SQLite tests run locally without any external dependencies:

```bash
cd /Users/rick/projects/proxy/internal/storage/sqlite
go test -v
```

### PostgreSQL Tests

PostgreSQL tests require a running PostgreSQL instance. 

**Option 1: Using Docker Compose (Recommended)**

```bash
cd /Users/rick/projects/proxy/internal/storage/postgres
./test-with-docker.sh
```

This script automatically starts PostgreSQL in Docker, runs the tests, and cleans up.

**Option 2: Manual Docker Setup**

```bash
# Start PostgreSQL
docker run -d --name postgres-test \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:latest

# Run tests
cd /Users/rick/projects/proxy/internal/storage/postgres
go test -v

# Or with custom DSN
POSTGRES_TEST_DSN="postgres://user:pass@host:port/db?sslmode=disable" go test -v

# Clean up
docker stop postgres-test
docker rm postgres-test
```

**Option 3: Run Tests Entirely in Docker**

```bash
cd /Users/rick/projects/proxy/internal/storage/postgres
./test-with-docker-runner.sh
```

See [README-DOCKER-TESTS.md](postgres/README-DOCKER-TESTS.md) for more details and options.

### Running All Storage Tests

```bash
cd /Users/rick/projects/proxy/internal/storage
go test -v ./...
```

## Test Coverage

Both implementations include comprehensive tests for:

- ✅ Table initialization (with UUID and index)
- ✅ Put/Insert operations (with UUID generation)
- ✅ Put/Update operations (upsert preserves UUID)
- ✅ Get operations (by key)
- ✅ GetByID operations (by UUID)
- ✅ Get with non-existent keys
- ✅ GetByID with non-existent UUIDs
- ✅ GetByID context cancellation
- ✅ Delete operations
- ✅ Delete by prefix
- ✅ Context cancellation
- ✅ Context timeout
- ✅ Binary data storage
- ✅ Empty value handling
- ✅ Connection closing
- ✅ Large value storage (SQLite)
- ✅ Special characters in keys (SQLite)
- ✅ Concurrent access (SQLite)
- ✅ Multiple instances (SQLite)

**Test Results:**
- PostgreSQL: 18 tests ✅
- SQLite: 20 tests ✅

## DSN Format

### PostgreSQL
```
postgres://username:password@hostname:port/database?sslmode=disable
```

### SQLite
```
/path/to/database.db
:memory:  # for in-memory database
```

## Error Handling

The package defines standard errors:

- `storage.ErrUnsupportedDriver` - Returned when an unsupported driver is requested
- `storage.ErrKeyNotFound` - Returned when a key is not found (currently returns `sql.ErrNoRows`)

## Implementation Notes

### PostgreSQL
- Uses `$1`, `$2` placeholder syntax
- Uses `BYTEA` for binary data
- Uses `ON CONFLICT ... DO UPDATE` for upsert
- Requires external PostgreSQL server

### SQLite
- Uses `?` placeholder syntax
- Uses `BLOB` for binary data
- Uses `ON CONFLICT ... DO UPDATE` for upsert
- Embedded database, no external dependencies
- Supports in-memory databases

## Thread Safety

Both implementations use `database/sql` which is safe for concurrent use by multiple goroutines. The underlying database connections are managed by the `sql.DB` connection pool.

