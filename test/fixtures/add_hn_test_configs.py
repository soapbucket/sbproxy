#!/usr/bin/env python3

"""
Add HackerNews chunk cache test configs to sites.json
Alternative to the bash script - simpler and more reliable
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

SITES_JSON = Path("/Users/rick/projects/proxy/conf/sites.json")
TEST_CONFIGS = Path("/Users/rick/projects/proxy/test/fixtures/chunk_cache_test_configs.json")

def main():
    print("Adding HackerNews chunk cache test configs to sites.json...")
    
    # Backup original
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = SITES_JSON.with_suffix(f".json.backup.{timestamp}")
    shutil.copy2(SITES_JSON, backup_path)
    print(f"✅ Backup created: {backup_path}")
    
    # Load existing sites
    with open(SITES_JSON) as f:
        sites = json.load(f)
    
    print(f"📝 Current sites: {len(sites)} configs")
    
    # Load test configs
    with open(TEST_CONFIGS) as f:
        test_data = json.load(f)
    
    # Convert array to object with hostname keys
    new_configs = {}
    for config in test_data["configs"]:
        hostname = config["hostname"]
        new_configs[hostname] = config
        print(f"  + {hostname}")
    
    # Merge
    sites.update(new_configs)
    
    # Write back
    with open(SITES_JSON, 'w') as f:
        json.dump(sites, f, indent=2)
    
    print(f"\n✅ Successfully added {len(new_configs)} configs to sites.json")
    print(f"📝 Total sites: {len(sites)} configs")
    print("\nTest hostnames added:")
    for hostname in new_configs.keys():
        print(f"  - {hostname}")
    
    print("\nAdd these to /etc/hosts:")
    for hostname in new_configs.keys():
        print(f"  127.0.0.1 {hostname}")
    
    print("\n✅ Reload proxy to apply changes")

if __name__ == "__main__":
    main()

