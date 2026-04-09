# CDBGen Quick Start

Get started with `cdbgen` in 5 minutes. Generate, read, and inspect CDB files.

## 1. Build the Tool

```bash
cd tools/cdbgen
go build
```

## 2. Create a Configuration File

Create a file `myconfigs.txt`:

```text
api.example.com {"hostname":"api.example.com","type":"proxy","config":{"url":"https://backend.example.com","timeout":"30s"}}
www.example.com {"hostname":"www.example.com","type":"static","config":{"root":"/var/www/html"}}
```

## 3. Generate CDB File

```bash
./cdbgen -i myconfigs.txt -o myconfigs.cdb
```

Output:
```
Processing configurations from myconfigs.txt...
✓ Added config for api.example.com (id: 550e8400-e29b-41d4-a716-446655440000)
✓ Added config for www.example.com (id: 660e9500-f39c-52e5-b827-557766551111)

Summary: 2 configurations added, 0 errors

✓ Successfully created CDB file: myconfigs.cdb
```

## 4. Read from the CDB File

### Get a Specific Hostname

```bash
./cdbgen -file myconfigs.cdb -get api.example.com
```

Output:
```
Configuration for api.example.com:
{
  "config": {
    "timeout": "30s",
    "url": "https://backend.example.com"
  },
  "hostname": "api.example.com",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "proxy"
}
```

### Dump All Configurations

```bash
./cdbgen -file myconfigs.cdb -dump
```

Output:
```
CDB file: myconfigs.cdb (size: 2803 bytes)
Dumping all configurations:

--- api.example.com ---
{
  ...
}

--- www.example.com ---
{
  ...
}

Total configurations: 2
```

## 5. Use the CDB File in Your Proxy

### Option A: Set as Environment Variable

```bash
export STORAGE_DSN="cdb:///path/to/myconfigs.cdb"
./your-proxy
```

### Option B: Pass as Command Line Argument

```bash
./your-proxy -storage-dsn "cdb:///path/to/myconfigs.cdb"
```

### Option C: Use Programmatically

```go
import (
    "github.com/soapbucket/proxy/lib/storage"
    _ "github.com/soapbucket/proxy/lib/storage/cdb"
)

settings := &storage.Settings{
    Driver: "cdb",
    DSN:    "/path/to/myconfigs.cdb",
}

store, _ := storage.NewStorage(settings)
defer store.Close()

data, _ := store.Get(ctx, "api.example.com")
```

## 6. Update Configurations

To update the CDB file:

```bash
# Edit your configs
vim myconfigs.txt

# Generate new CDB
./cdbgen -i myconfigs.txt -o myconfigs.cdb.new

# Atomically replace
mv myconfigs.cdb.new myconfigs.cdb

# Restart your application
```

## Run the Demo

```bash
./test-demo.sh
```

This will:
1. Build the tool
2. Generate a CDB file from the example config
3. Read and display configurations
4. Show file information

## Common Commands

```bash
# Generate CDB
./cdbgen -i input.txt -o output.cdb
./cdbgen -input input.txt -output output.cdb

# Read specific hostname
./cdbgen -f output.cdb -g api.example.com
./cdbgen -file output.cdb -get api.example.com

# Dump all configs
./cdbgen -f output.cdb -d
./cdbgen -file output.cdb -dump

# See help
./cdbgen -h

# Run demo
./test-demo.sh
```

## Input File Format

```text
# Comments start with #
hostname {"json":"config"}

# Example
api.example.com {"hostname":"api.example.com","type":"proxy","config":{"url":"https://backend.example.com"}}
```

**Key Points:**
- One configuration per line
- Format: `hostname<space>json`
- The `id` field is auto-generated
- Comments and blank lines are ignored

## Troubleshooting

### Tool not building?

```bash
go mod tidy
go build
```

### "Output file must have .cdb extension"?

Make sure your output file ends with `.cdb`:
```bash
./cdbgen -i input.txt -o output.cdb  # ✓ Correct
```

### "Invalid JSON" error?

Validate your JSON:
```bash
echo '{"test":"value"}' | jq .
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [configs.example.txt](configs.example.txt) for more examples
- See [CDB Storage docs](../../internal/storage/cdb/README.md) for usage details

## Need Help?

```bash
./cdbgen -h
```

Or check the [README.md](README.md) for complete documentation.

