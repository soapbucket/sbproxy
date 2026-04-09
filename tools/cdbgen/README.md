# CDB Generator and Reader (cdbgen)

A command-line tool to create and inspect CDB (Constant Database) files. Uses the same input format as `config-loader` for generation, and provides read/dump capabilities for inspection.

## Overview

`cdbgen` is a dual-purpose tool that can:
1. **Generate**: Create CDB files from text configuration data with auto-generated UUIDs
2. **Read**: Query specific hostnames from existing CDB files
3. **Dump**: Display all configurations stored in a CDB file

## Installation

```bash
cd tools/cdbgen
go build
```

Or install to your PATH:

```bash
cd tools/cdbgen
go install
```

## Usage

### Generate Mode

Create a CDB file from a text configuration file:

```bash
cdbgen -input <file> -output <file.cdb>
cdbgen -i <file> -o <file.cdb>
```

### Read Mode

Get configuration for a specific hostname:

```bash
cdbgen -file <file.cdb> -get <hostname>
cdbgen -f <file.cdb> -g <hostname>
```

### Dump Mode

Display all configurations in a CDB file:

```bash
cdbgen -file <file.cdb> -dump
cdbgen -f <file.cdb> -d
```

### Options

**Generation Mode:**
- `-input`, `-i` - Input configuration file (required)
- `-output`, `-o` - Output CDB file (required, must end with .cdb)

**Read Mode:**
- `-file`, `-f` - CDB file to read (required)
- `-get`, `-g` - Get configuration for specific hostname
- `-dump`, `-d` - Dump all keys and values

### Examples

```bash
# Generate CDB file
cdbgen -input configs.txt -output configs.cdb
cdbgen -i configs.txt -o configs.cdb

# Read specific hostname
cdbgen -file configs.cdb -get api.example.com
cdbgen -f configs.cdb -g api.example.com

# Dump all configurations
cdbgen -file configs.cdb -dump
cdbgen -f configs.cdb -d
```

## Input File Format

Each line in the input file should have the format:

```
hostname <space> json-config
```

### Rules

- **Hostname**: The key used to look up the configuration
- **JSON Config**: The configuration object (will have `id` field added automatically)
- **Comments**: Lines starting with `#` are ignored
- **Empty Lines**: Blank lines are ignored

### Example Input File

```text
# Proxy origin
api.example.com {"hostname":"api.example.com","type":"proxy","config":{"url":"https://backend.example.com","timeout":"30s"}}

# Static origin
cdn.example.com {"hostname":"cdn.example.com","type":"static","config":{"root":"/var/www/static"}}

# Storage origin
files.example.com {"hostname":"files.example.com","type":"storage","config":{"kind":"s3","bucket":"my-bucket","region":"us-east-1"}}
```

### ID Field

The tool automatically:
1. Parses the JSON configuration
2. Generates a UUID (e.g., `550e8400-e29b-41d4-a716-446655440000`)
3. Injects it as the `id` field
4. Stores the updated JSON in the CDB file

**Before:**
```json
{"hostname":"api.example.com","type":"proxy","config":{"url":"https://backend.example.com"}}
```

**After:**
```json
{"hostname":"api.example.com","id":"550e8400-e29b-41d4-a716-446655440000","type":"proxy","config":{"url":"https://backend.example.com"}}
```

## Output Examples

### Generation Output

```
Processing configurations from configs.txt...
✓ Added config for api.example.com (id: 550e8400-e29b-41d4-a716-446655440000)
✓ Added config for cdn.example.com (id: 660e9500-f39c-52e5-b827-557766551111)

Summary: 2 configurations added, 0 errors

✓ Successfully created CDB file: configs.cdb
```

### Read Output

```bash
$ cdbgen -f configs.cdb -g api.example.com
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

### Dump Output

```bash
$ cdbgen -f configs.cdb -dump
CDB file: configs.cdb (size: 2803 bytes)
Dumping all configurations:

--- api.example.com ---
{
  "config": {
    "timeout": "30s",
    "url": "https://backend.example.com"
  },
  "hostname": "api.example.com",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "proxy"
}

--- cdn.example.com ---
{
  "config": {
    "root": "/var/www/static"
  },
  "hostname": "cdn.example.com",
  "id": "660e9500-f39c-52e5-b827-557766551111",
  "type": "static"
}

Total configurations: 2
```

## Using the Generated CDB File

### With the Proxy

Configure the proxy to use CDB storage:

```bash
export STORAGE_DSN="cdb:///path/to/configs.cdb"
./proxy
```

### Programmatically

```go
import (
    "context"
    "github.com/soapbucket/proxy/lib/storage"
    _ "github.com/soapbucket/proxy/lib/storage/cdb"
)

settings := &storage.Settings{
    Driver: "cdb",
    DSN:    "configs.cdb",
}

store, err := storage.NewStorage(settings)
if err != nil {
    log.Fatal(err)
}
defer store.Close()

// Read configuration by hostname
ctx := context.Background()
data, err := store.Get(ctx, "api.example.com")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Config: %s\n", data)
```

## Updating Configurations

CDB files are immutable. To update configurations:

1. Create a new CDB file with updated data:
   ```bash
   cdbgen -i configs-new.txt -o configs.cdb.new
   ```

2. Atomically replace the old file:
   ```bash
   mv configs.cdb.new configs.cdb
   ```

3. The application will need to reload or restart to pick up the new file

### Atomic Replacement

```bash
# Safe replacement pattern
cdbgen -i configs.txt -o configs.cdb.tmp
mv configs.cdb.tmp configs.cdb
```

This ensures the CDB file is never in an incomplete state.

## Error Handling

The tool reports errors for:

- ❌ Invalid line format (missing hostname or JSON)
- ❌ Empty hostname
- ❌ Invalid JSON syntax
- ❌ JSON marshaling errors
- ❌ File I/O errors

Errors are reported with line numbers, and the tool continues processing remaining lines.

### Example Error Output

```
Line 5: Invalid format (expected: hostname json-config)
Line 8: Invalid JSON for bad.example.com: unexpected end of JSON input
Line 12: Empty hostname

Summary: 7 configurations added, 3 errors
Error: 3 errors encountered during processing
```

## Features

**Generation:**
✅ **Auto-generated IDs**: UUIDs are automatically created and injected
✅ **Error Reporting**: Line-by-line error messages with context
✅ **Comment Support**: Lines starting with `#` are ignored
✅ **Validation**: Input validation for hostnames and JSON
✅ **Summary**: Clear summary of successful and failed entries
✅ **Safe Creation**: Old output file is removed before creation
✅ **Compatible**: Uses same format as `config-loader` tool

**Reading:**
✅ **Single Hostname Lookup**: Query specific hostname configurations
✅ **Full Dump**: Display all configurations in the CDB file
✅ **Pretty JSON**: Formatted JSON output for easy reading
✅ **Error Handling**: Clear error messages for missing hostnames
✅ **File Info**: Shows file size and configuration count

## Comparison with config-loader

| Feature | cdbgen | config-loader |
|---------|--------|---------------|
| Input Format | Same | Same |
| ID Generation | Auto (UUID) | Auto (UUID) |
| Output | CDB file | Database (SQLite/PostgreSQL) |
| Read-Only | Yes | No |
| Write Support | No (create only) | Yes (CRUD) |
| Best For | Static configs | Dynamic configs |
| Performance | Fastest reads | Fast reads/writes |

## Performance

CDB files provide:
- O(1) average-case lookups
- Zero locking overhead
- Minimal memory usage
- Extremely fast reads

Ideal for configuration data that is:
- Read frequently
- Updated infrequently
- Small to medium size (< 100 MB)

## Limitations

- **Read-Only**: CDB files cannot be modified after creation
- **No Deletion**: Individual entries cannot be removed
- **No Updates**: Existing entries cannot be changed
- **File Size**: Practical limit around 4 GB (CDB format limitation)

## Troubleshooting

### "Output file must have .cdb extension"

Ensure your output file ends with `.cdb`:
```bash
cdbgen -i configs.txt -o configs.cdb  # ✓ Correct
cdbgen -i configs.txt -o configs.db   # ✗ Wrong
```

### "Invalid JSON for hostname"

Check that your JSON is valid:
```bash
# Test JSON validity
echo '{"test":"value"}' | jq .
```

### "Error writing to CDB"

Ensure you have write permissions to the output directory:
```bash
ls -la /path/to/output/
```

## See Also

- [config-loader](../config-loader/README.md) - Load configs to database
- [CDB Storage](../../internal/storage/cdb/README.md) - CDB storage implementation
- [Storage Documentation](../../internal/storage/README.md) - Storage abstraction

## References

- [CDB specification](https://cr.yp.to/cdb.html) by D. J. Bernstein
- [github.com/colinmarc/cdb](https://github.com/colinmarc/cdb) - Go CDB library

