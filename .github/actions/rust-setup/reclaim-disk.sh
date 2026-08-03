#!/usr/bin/env bash
set -euo pipefail

# GitHub's hosted runner currently has ample headroom. Keep the cleanup for
# smaller images, where a cold Rust build can still run out of disk.
readonly RUNNER_DISK_FLOOR_KIB=$((40 * 1024 * 1024))

available_root_kib() {
  LC_ALL=C df -Pk / | awk 'NR == 2 { print $4 }'
}

is_unsigned_integer() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

reclaim_runner_disk() {
  sudo rm -rf \
    /usr/local/lib/android \
    /usr/share/dotnet \
    /opt/ghc \
    /usr/local/.ghcup
  sudo docker image prune --all --force >/dev/null 2>&1 || true
}

df -h / || true

if available_kib="$(available_root_kib 2>/dev/null)" \
  && is_unsigned_integer "$available_kib"
then
  if [ "$available_kib" -gt "$RUNNER_DISK_FLOOR_KIB" ]; then
    printf 'runner disk cleanup skipped: %s KiB available exceeds the %s KiB floor\n' \
      "$available_kib" "$RUNNER_DISK_FLOOR_KIB"
  else
    printf 'runner disk cleanup starting: %s KiB available is at or below the %s KiB floor\n' \
      "$available_kib" "$RUNNER_DISK_FLOOR_KIB"
    reclaim_runner_disk
  fi
else
  printf 'runner disk measurement was unavailable; reclaiming the allowlisted toolchains\n'
  reclaim_runner_disk
fi

df -h / || true
