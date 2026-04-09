#!/usr/bin/env bash
set -euo pipefail

# Suppress noisy Apple linker warnings on newer macOS toolchains when
# building race-enabled test binaries. This does not change test behavior.
if [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ -n "${CGO_LDFLAGS:-}" ]]; then
    export CGO_LDFLAGS="${CGO_LDFLAGS} -Wl,-w"
  else
    export CGO_LDFLAGS="-Wl,-w"
  fi
fi

if [[ "$#" -eq 0 ]]; then
  set -- ./...
fi

go test -race "$@"
