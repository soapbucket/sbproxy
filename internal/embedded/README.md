# Embedded Data Package

This package embeds pre-compressed data files into the proxy binary at compile time using Go's `//go:embed` directive. This eliminates external file dependencies at runtime.

## Files

| File | Description |
|------|-------------|
| `ai_providers.yml.gz` | AI provider definitions (endpoints, auth patterns, model mappings) |
| `model_pricing.json.gz` | Per-model token pricing for cost tracking and budget enforcement |
| `regexes.yml.gz` | User-agent parsing rules for device/browser detection |
| `version.json` | Metadata (SHA256 hashes, sizes, timestamps) for each embedded file |

All `.gz` files are gzip-compressed with maximum compression (`gzip -9`). They are decompressed in memory on first use.

## Updating Files

Source files live in `proxy/data/`. To regenerate the embedded copies:

```bash
./scripts/update-embedded-data.sh
```

The script copies each source file, compresses it, computes SHA256 checksums, and writes `version.json`.

## MMDB (GeoIP)

The MMDB file (`ipinfo_lite.mmdb`) is not handled by the script because it requires manual steps:

1. Download the latest IP-to-country MMDB from your provider.
2. Strip it to a country-only version to keep the binary small.
3. Place the stripped file at `proxy/data/ipinfo_lite.mmdb`.
4. Compress manually: `gzip -9 -c data/ipinfo_lite.mmdb > internal/embedded/data/ipinfo_lite.mmdb.gz`
