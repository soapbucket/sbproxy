// Minimal sbproxy WASM transform in TinyGo: uppercase every byte
// from stdin and write the result to stdout.
//
// sbproxy invokes the WASI `_start` entry point (the standard `main`
// in Go) for every transform call. The host pipes the request body in
// on stdin and captures stdout. There is no other ABI to learn.
//
// Build:
//     ./build.sh
//
// The output uppercase.wasm is what you point sbproxy at via
// `wasm.module_path`.
package main

import (
	"bytes"
	"io"
	"os"
)

func main() {
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		// Read errors leave the body empty; nothing to do.
		return
	}
	// Real transforms would mutate `body` based on application
	// logic; we just uppercase to keep the example one line.
	_, _ = os.Stdout.Write(bytes.ToUpper(body))
}
