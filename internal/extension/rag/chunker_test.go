package rag

import (
	"strings"
	"testing"
)

func TestChunkDoc(t *testing.T) {
	tests := []struct {
		name      string
		chunkSize int
		overlap   int
		doc       Document
		wantCount int
		check     func(t *testing.T, chunks []Chunk)
	}{
		{
			name:      "empty document returns nil",
			chunkSize: 10,
			overlap:   2,
			doc:       Document{ID: "empty", Content: []byte(""), Filename: "empty.txt"},
			wantCount: 0,
		},
		{
			name:      "whitespace-only document returns nil",
			chunkSize: 10,
			overlap:   2,
			doc:       Document{ID: "ws", Content: []byte("   \n\t  "), Filename: "ws.txt"},
			wantCount: 0,
		},
		{
			name:      "single chunk - content smaller than chunk size",
			chunkSize: 100,
			overlap:   10,
			doc: Document{
				ID:       "small",
				Content:  []byte("hello world this is a small document"),
				Filename: "small.txt",
			},
			wantCount: 1,
			check: func(t *testing.T, chunks []Chunk) {
				if chunks[0].Content != "hello world this is a small document" {
					t.Errorf("unexpected content: %q", chunks[0].Content)
				}
				if chunks[0].DocID != "small" {
					t.Errorf("unexpected doc ID: %q", chunks[0].DocID)
				}
				if chunks[0].DocName != "small.txt" {
					t.Errorf("unexpected doc name: %q", chunks[0].DocName)
				}
				if chunks[0].Index != 0 {
					t.Errorf("unexpected index: %d", chunks[0].Index)
				}
			},
		},
		{
			name:      "multiple chunks with overlap",
			chunkSize: 5,
			overlap:   2,
			doc: Document{
				ID:       "multi",
				Content:  []byte("one two three four five six seven eight nine ten eleven twelve"),
				Filename: "multi.txt",
			},
			wantCount: 4,
			check: func(t *testing.T, chunks []Chunk) {
				// chunkSize=5, overlap=2, step=3
				// Chunk 0: words[0:5] = "one two three four five"
				// Chunk 1: words[3:8] = "four five six seven eight"
				// Chunk 2: words[6:11] = "seven eight nine ten eleven"
				// Chunk 3: words[9:12] = "ten eleven twelve"
				if chunks[0].Content != "one two three four five" {
					t.Errorf("chunk 0: got %q", chunks[0].Content)
				}
				if chunks[1].Content != "four five six seven eight" {
					t.Errorf("chunk 1: got %q", chunks[1].Content)
				}
				if chunks[2].Content != "seven eight nine ten eleven" {
					t.Errorf("chunk 2: got %q", chunks[2].Content)
				}
				if chunks[3].Content != "ten eleven twelve" {
					t.Errorf("chunk 3: got %q", chunks[3].Content)
				}

				// Verify overlap: chunk 0 and chunk 1 share "four five".
				words0 := strings.Fields(chunks[0].Content)
				words1 := strings.Fields(chunks[1].Content)
				if words0[3] != words1[0] || words0[4] != words1[1] {
					t.Error("expected overlap between chunk 0 and chunk 1")
				}
			},
		},
		{
			name:      "exact chunk size boundary",
			chunkSize: 4,
			overlap:   1,
			doc: Document{
				ID:       "exact",
				Content:  []byte("a b c d e f g"),
				Filename: "exact.txt",
			},
			wantCount: 2,
			check: func(t *testing.T, chunks []Chunk) {
				// step=3, words=7
				// Chunk 0: words[0:4] = "a b c d"
				// Chunk 1: words[3:7] = "d e f g"
				if chunks[0].Content != "a b c d" {
					t.Errorf("chunk 0: got %q", chunks[0].Content)
				}
				if chunks[1].Content != "d e f g" {
					t.Errorf("chunk 1: got %q", chunks[1].Content)
				}
			},
		},
		{
			name:      "metadata preserved in chunks",
			chunkSize: 100,
			overlap:   10,
			doc: Document{
				ID:       "meta",
				Content:  []byte("some content here"),
				Filename: "meta.txt",
				Metadata: map[string]string{"source": "test", "author": "bot"},
			},
			wantCount: 1,
			check: func(t *testing.T, chunks []Chunk) {
				if chunks[0].Metadata["source"] != "test" {
					t.Error("metadata 'source' not preserved")
				}
				if chunks[0].Metadata["author"] != "bot" {
					t.Error("metadata 'author' not preserved")
				}
			},
		},
		{
			name:      "chunk IDs are correctly formatted",
			chunkSize: 3,
			overlap:   1,
			doc: Document{
				ID:       "doc123",
				Content:  []byte("a b c d e"),
				Filename: "test.txt",
			},
			wantCount: 2,
			check: func(t *testing.T, chunks []Chunk) {
				if chunks[0].ID != "doc123:chunk:0" {
					t.Errorf("chunk 0 ID: got %q, want %q", chunks[0].ID, "doc123:chunk:0")
				}
				if chunks[1].ID != "doc123:chunk:1" {
					t.Errorf("chunk 1 ID: got %q, want %q", chunks[1].ID, "doc123:chunk:1")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunker := NewChunker(tt.chunkSize, tt.overlap)
			chunks := chunker.ChunkDoc(tt.doc)

			if len(chunks) != tt.wantCount {
				t.Fatalf("got %d chunks, want %d", len(chunks), tt.wantCount)
			}

			if tt.check != nil {
				tt.check(t, chunks)
			}
		})
	}
}

func TestNewChunkerDefaults(t *testing.T) {
	tests := []struct {
		name          string
		chunkSize     int
		overlap       int
		wantChunkSize int
		wantOverlap   int
	}{
		{
			name:          "zero values get defaults",
			chunkSize:     0,
			overlap:       0,
			wantChunkSize: 500,
			wantOverlap:   50,
		},
		{
			name:          "negative values get defaults",
			chunkSize:     -1,
			overlap:       -1,
			wantChunkSize: 500,
			wantOverlap:   50,
		},
		{
			name:          "overlap >= chunkSize gets clamped",
			chunkSize:     10,
			overlap:       10,
			wantChunkSize: 10,
			wantOverlap:   2, // 10/5
		},
		{
			name:          "valid values kept as-is",
			chunkSize:     200,
			overlap:       30,
			wantChunkSize: 200,
			wantOverlap:   30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewChunker(tt.chunkSize, tt.overlap)
			if c.chunkSize != tt.wantChunkSize {
				t.Errorf("chunkSize: got %d, want %d", c.chunkSize, tt.wantChunkSize)
			}
			if c.overlap != tt.wantOverlap {
				t.Errorf("overlap: got %d, want %d", c.overlap, tt.wantOverlap)
			}
		})
	}
}
