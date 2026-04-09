// Package pool provides tiered sync.Pool buffer pools for the proxy.
//
// Three pool tiers serve different use cases:
//
//   - SmallBuf (512 bytes): headers, small JSON bodies, error messages
//   - MediumBuf (4 KB): typical API responses, HTML fragments
//   - LargeBuf (32 KB): large response bodies, file uploads, streaming buffers
//
// Callers should pick the smallest tier that fits their expected data size
// to minimize memory waste. Always return buffers via the corresponding
// Put function to enable reuse. Buffers are Reset() on Get to prevent
// data leaks between uses.
package pool

import (
	"bytes"
	"sync"
)

// SmallBuf, MediumBuf, and LargeBuf are the three tiered buffer pools.
// Each pool pre-allocates buffers at its tier capacity to avoid early
// growth allocations.
var (
	SmallBuf  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 512)) }}
	MediumBuf = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) }}
	LargeBuf  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 32768)) }}
)

// GetSmall returns a reset buffer from the small (512-byte) pool.
func GetSmall() *bytes.Buffer { b := SmallBuf.Get().(*bytes.Buffer); b.Reset(); return b }

// PutSmall returns a buffer to the small pool. Nil buffers are silently ignored.
func PutSmall(b *bytes.Buffer) { if b != nil { SmallBuf.Put(b) } }

// GetMedium returns a reset buffer from the medium (4 KB) pool.
func GetMedium() *bytes.Buffer { b := MediumBuf.Get().(*bytes.Buffer); b.Reset(); return b }

// PutMedium returns a buffer to the medium pool. Nil buffers are silently ignored.
func PutMedium(b *bytes.Buffer) { if b != nil { MediumBuf.Put(b) } }

// GetLarge returns a reset buffer from the large (32 KB) pool.
func GetLarge() *bytes.Buffer { b := LargeBuf.Get().(*bytes.Buffer); b.Reset(); return b }

// PutLarge returns a buffer to the large pool. Nil buffers are silently ignored.
func PutLarge(b *bytes.Buffer) { if b != nil { LargeBuf.Put(b) } }
