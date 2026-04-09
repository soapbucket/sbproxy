# Quick Start Guide

## Installation

```bash
cd /Users/rick/projects/proxy/tools/config-loader
go build -o config-loader
```

## 30-Second Demo

```bash
# Run the demo script
./test-demo.sh
```

This demonstrates:
- ✅ Loading 3 configurations
- ✅ UUID auto-generation
- ✅ Upsert (preserving UUIDs on update)
- ✅ Delete operations
- ✅ Safety features

## Basic Usage

### Load Configurations

```bash
./config-loader -dsn 'sqlite:///tmp/config.db' -load configs.example.txt
```

### View What Was Loaded

```bash
sqlite3 /tmp/config.db "SELECT id, key FROM config_storage"
```

### Delete Specific Config

```bash
./config-loader -dsn 'sqlite:///tmp/config.db' -delete api.example.com
```

### Delete by Prefix

```bash
./config-loader -dsn 'sqlite:///tmp/config.db' -delete-prefix 'api.'
# Will prompt for confirmation (y/n)
```

## Configuration File Format

Create a file with one configuration per line:

```
hostname json-config
```

Example (`myconfigs.txt`):
```
# The 'id' field will be auto-generated
api.example.com {"hostname":"api.example.com","type":"proxy","config":{"url":"https://backend.example.com","timeout":"30s"}}
www.example.com {"hostname":"www.example.com","type":"proxy","config":{"url":"https://cdn.example.com","timeout":"20s"}}
localhost:8080 {"hostname":"localhost:8080","type":"proxy","config":{"url":"https://httpbin.org","timeout":"45s"}}
```

Then load it:
```bash
./config-loader -dsn 'sqlite:///tmp/config.db' -load myconfigs.txt
```

## Using PostgreSQL

```bash
# Start PostgreSQL with Docker
docker run -d --name config-db \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 \
  postgres:16-alpine

# Wait a few seconds for it to start
sleep 3

# Load configs
./config-loader \
  -dsn 'postgres://postgres:secret@localhost:5432/postgres?sslmode=disable' \
  -load configs.example.txt

# View results
docker exec config-db psql -U postgres -c "SELECT key FROM config_storage"

# Cleanup
docker stop config-db && docker rm config-db
```

## Using Environment Variable

```bash
export STORAGE_DSN='sqlite:///tmp/config.db'
./config-loader -load configs.example.txt
./config-loader -delete localhost:8443
```

## Help

```bash
./config-loader -h
```

## Testing

Run all demos:
```bash
./test-demo.sh          # SQLite demo
./test-postgres.sh      # PostgreSQL demo (requires Docker)
```

## Example Configurations

The tool comes with `configs.example.txt` containing:

1. **api.soapbucket.com** - Hacker News proxy
2. **api.soapbucket.com:8443** - Forward hostname config  
3. **localhost:8443** - Local development proxy

## Common Tasks

### Update a Configuration

Just re-run with the same hostname in your file:
```bash
# configs.txt has updated JSON for api.example.com
./config-loader -dsn 'sqlite:///tmp/config.db' -load configs.txt
# UUID is preserved, value is updated
```

### Bulk Delete

```bash
# Delete all staging configs
./config-loader -dsn 'sqlite:///tmp/config.db' -delete-prefix 'staging.'

# Delete all localhost configs
./config-loader -dsn 'sqlite:///tmp/config.db' -delete-prefix 'localhost'
```

### View All Keys

```bash
sqlite3 /tmp/config.db "SELECT key FROM config_storage ORDER BY key"
```

## Safety Features

- ✅ Empty prefix rejected (prevents deleting everything)
- ✅ Single-character prefix rejected  
- ✅ Confirmation prompt before bulk delete
- ✅ Detailed error messages
- ✅ Line-by-line validation

## Next Steps

- Read [README.md](README.md) for complete documentation
- Check [SUMMARY.md](SUMMARY.md) for implementation details
- View [configs.example.txt](configs.example.txt) for examples

