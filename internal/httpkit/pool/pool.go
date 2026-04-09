package pool

import (
	"bytes"
	"sync"
)

var (
	SmallBuf  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 512)) }}
	MediumBuf = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) }}
	LargeBuf  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 32768)) }}
)

func GetSmall() *bytes.Buffer  { b := SmallBuf.Get().(*bytes.Buffer); b.Reset(); return b }
func PutSmall(b *bytes.Buffer) { if b != nil { SmallBuf.Put(b) } }

func GetMedium() *bytes.Buffer  { b := MediumBuf.Get().(*bytes.Buffer); b.Reset(); return b }
func PutMedium(b *bytes.Buffer) { if b != nil { MediumBuf.Put(b) } }

func GetLarge() *bytes.Buffer  { b := LargeBuf.Get().(*bytes.Buffer); b.Reset(); return b }
func PutLarge(b *bytes.Buffer) { if b != nil { LargeBuf.Put(b) } }
