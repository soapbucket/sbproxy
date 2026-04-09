package rag

import (
	"fmt"
	"strings"
)

// Chunk represents a piece of a document after splitting.
type Chunk struct {
	ID       string            `json:"id"`
	Content  string            `json:"content"`
	DocID    string            `json:"doc_id"`
	DocName  string            `json:"doc_name"`
	Index    int               `json:"index"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Chunker splits documents into overlapping word-based chunks.
type Chunker struct {
	chunkSize int // max words per chunk
	overlap   int // overlapping words between consecutive chunks
}

// NewChunker creates a Chunker with the given chunk size and overlap in words.
// If chunkSize <= 0, defaults to 500. If overlap <= 0, defaults to 50.
// Overlap is clamped to be less than chunkSize.
func NewChunker(chunkSize, overlap int) *Chunker {
	if chunkSize <= 0 {
		chunkSize = 500
	}
	if overlap <= 0 {
		overlap = 50
	}
	if overlap >= chunkSize {
		overlap = chunkSize / 5
	}
	return &Chunker{
		chunkSize: chunkSize,
		overlap:   overlap,
	}
}

// ChunkDoc splits a Document into overlapping Chunks on word boundaries.
// Returns nil for empty documents.
func (c *Chunker) ChunkDoc(doc Document) []Chunk {
	text := strings.TrimSpace(string(doc.Content))
	if text == "" {
		return nil
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var chunks []Chunk
	step := c.chunkSize - c.overlap
	if step <= 0 {
		step = 1
	}

	for start := 0; start < len(words); start += step {
		end := start + c.chunkSize
		if end > len(words) {
			end = len(words)
		}

		content := strings.Join(words[start:end], " ")
		idx := len(chunks)

		chunk := Chunk{
			ID:       fmt.Sprintf("%s:chunk:%d", doc.ID, idx),
			Content:  content,
			DocID:    doc.ID,
			DocName:  doc.Filename,
			Index:    idx,
			Metadata: doc.Metadata,
		}
		chunks = append(chunks, chunk)

		// If we reached the end of words, stop.
		if end == len(words) {
			break
		}
	}

	return chunks
}
