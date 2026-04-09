# Manual Setup Instructions

If the automated scripts don't work, follow these manual steps:

## Option 1: Use Python Script (Recommended)

```bash
cd /Users/rick/projects/proxy/test/fixtures
python3 add_hn_test_configs.py
```

## Option 2: Use Fixed Bash Script

```bash
cd /Users/rick/projects/proxy/test/fixtures
./add_hn_test_configs.sh
```

## Option 3: Manual JSON Editing

### Step 1: Backup your sites.json

```bash
cp /Users/rick/projects/proxy/conf/sites.json /Users/rick/projects/proxy/conf/sites.json.backup
```

### Step 2: Add the test configs manually

Open `/Users/rick/projects/proxy/conf/sites.json` in your editor and add these entries:

```json
{
  "existing-configs": "...",
  
  "hn-signature.test": {
    "id": "hn-signature-cache",
    "hostname": "hn-signature.test",
    "description": "HackerNews with signature-based caching for HTML head",
    "action": {
      "proxy": {
        "url": "https://news.ycombinator.com",
        "preserve_host": false
      }
    },
    "chunk_cache": {
      "ignore_no_cache": false,
      "signature_cache": {
        "enabled": true,
        "content_types": ["text/html"],
        "max_examine_bytes": 16384,
        "default_ttl": "30m",
        "signatures": [
          {
            "name": "html_doctype_to_body",
            "pattern_type": "regex",
            "regex_pattern": "<!DOCTYPE[^>]*>.*?<body[^>]*>",
            "min_prefix_length": 100,
            "max_prefix_length": 8192,
            "cache_ttl": "1h"
          }
        ]
      },
      "url_cache": {
        "enabled": false
      }
    }
  },
  
  "hn-url.test": {
    "id": "hn-url-cache",
    "hostname": "hn-url.test",
    "description": "HackerNews with URL-based caching",
    "action": {
      "proxy": {
        "url": "https://news.ycombinator.com",
        "preserve_host": false
      }
    },
    "chunk_cache": {
      "ignore_no_cache": false,
      "signature_cache": {
        "enabled": false
      },
      "url_cache": {
        "enabled": true,
        "ttl": "5m"
      }
    }
  },
  
  "hn-hybrid.test": {
    "id": "hn-hybrid-cache",
    "hostname": "hn-hybrid.test",
    "description": "HackerNews with both signature and URL caching",
    "action": {
      "proxy": {
        "url": "https://news.ycombinator.com",
        "preserve_host": false
      }
    },
    "chunk_cache": {
      "ignore_no_cache": false,
      "signature_cache": {
        "enabled": true,
        "content_types": ["text/html"],
        "max_examine_bytes": 16384,
        "default_ttl": "30m",
        "signatures": [
          {
            "name": "html_head",
            "pattern_type": "regex",
            "regex_pattern": "<!DOCTYPE[^>]*>.*?</head>",
            "min_prefix_length": 100,
            "max_prefix_length": 8192,
            "cache_ttl": "2h"
          }
        ]
      },
      "url_cache": {
        "enabled": true,
        "ttl": "10m"
      }
    }
  },
  
  "hn-ignore-nocache.test": {
    "id": "hn-ignore-nocache",
    "hostname": "hn-ignore-nocache.test",
    "description": "HackerNews ignoring Cache-Control: no-cache from client",
    "action": {
      "proxy": {
        "url": "https://news.ycombinator.com",
        "preserve_host": false
      }
    },
    "chunk_cache": {
      "ignore_no_cache": true,
      "signature_cache": {
        "enabled": true,
        "content_types": ["text/html"],
        "signatures": [
          {
            "name": "html_prefix",
            "pattern_type": "regex",
            "regex_pattern": "<!DOCTYPE[^>]*>.*?<body[^>]*>",
            "cache_ttl": "1h"
          }
        ]
      },
      "url_cache": {
        "enabled": true,
        "ttl": "5m"
      }
    }
  }
}
```

**Note**: Copy just ONE or TWO configs to start with, not all at once. Start with `hn-signature.test` for testing.

### Step 3: Validate JSON

```bash
# Check if JSON is valid
jq empty /Users/rick/projects/proxy/conf/sites.json
# If no output, JSON is valid. If error, fix syntax.
```

### Step 4: Add to /etc/hosts

```bash
sudo tee -a /etc/hosts << EOF
127.0.0.1 hn-signature.test
127.0.0.1 hn-url.test
127.0.0.1 hn-hybrid.test
127.0.0.1 hn-ignore-nocache.test
EOF
```

### Step 5: Restart Proxy

Restart your proxy service to load the new configs.

## Quick Test: Single Config Only

If you just want to test quickly, add ONLY this one config:

```json
{
  "hn-signature.test": {
    "id": "hn-signature-cache",
    "hostname": "hn-signature.test",
    "action": {
      "proxy": {
        "url": "https://news.ycombinator.com",
        "preserve_host": false
      }
    },
    "chunk_cache": {
      "signature_cache": {
        "enabled": true,
        "content_types": ["text/html"],
        "signatures": [
          {
            "name": "html_head",
            "pattern_type": "regex",
            "regex_pattern": "<!DOCTYPE[^>]*>.*?</head>",
            "cache_ttl": "1h"
          }
        ]
      }
    }
  }
}
```

Then test:
```bash
# Add to hosts
echo "127.0.0.1 hn-signature.test" | sudo tee -a /etc/hosts

# Test (after proxy restart)
curl -ksv -H "Host: hn-signature.test" -H "X-Sb-Flags: debug" https://localhost:8443/
```

## Troubleshooting

### Script Error: "jq: command not found"

Install jq:
```bash
# macOS
brew install jq

# Linux
sudo apt-get install jq  # Debian/Ubuntu
sudo yum install jq      # RHEL/CentOS
```

### Script Error: Invalid JSON

Check the test config file:
```bash
jq empty /Users/rick/projects/proxy/test/fixtures/chunk_cache_test_configs.json
```

### Python Script: Module not found

Ensure Python 3 is installed:
```bash
python3 --version
```

### JSON Validation Failed

Use an online JSON validator:
1. Copy your sites.json content
2. Go to https://jsonlint.com/
3. Paste and validate
4. Fix any syntax errors

### After Adding Configs

1. **Validate JSON**: `jq empty /Users/rick/projects/proxy/conf/sites.json`
2. **Check hosts file**: `cat /etc/hosts | grep hn-`
3. **Restart proxy**: Restart your proxy service
4. **Test connectivity**: `curl -I -H "Host: hn-signature.test" https://localhost:8443/`

## Getting Help

If you're still stuck:

1. Check the JSON syntax carefully (commas, brackets, quotes)
2. Look at proxy startup logs for config errors
3. Start with just ONE test config instead of all seven
4. Ensure the proxy can reach news.ycombinator.com

