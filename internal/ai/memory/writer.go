// Package memory manages conversational memory and context persistence for AI sessions.
package memory

import (
	json "github.com/goccy/go-json"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
)

// Writer writes AI memory entries to ClickHouse via the batching HTTP writer.
type Writer struct {
	chWriter *logging.ClickHouseHTTPWriter
	config   *MemoryConfig
}

// NewWriter creates a new memory Writer targeting the ai_memory table.
func NewWriter(chConfig logging.ClickHouseWriterConfig, memConfig *MemoryConfig) (*Writer, error) {
	// Override the table to ai_memory
	chConfig.Table = "ai_memory"

	chWriter, err := logging.NewClickHouseHTTPWriter(chConfig)
	if err != nil {
		return nil, err
	}

	return &Writer{
		chWriter: chWriter,
		config:   memConfig.Defaults(),
	}, nil
}

// Write serializes an Entry to JSON and writes it to the ClickHouse buffer.
func (w *Writer) Write(entry *Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("memory: failed to marshal entry", "error", err)
		return err
	}
	_, err = w.chWriter.Write(data)
	return err
}

// Config returns the memory configuration.
func (w *Writer) Config() *MemoryConfig {
	return w.config
}

// Close flushes remaining entries and stops the writer.
func (w *Writer) Close() error {
	return w.chWriter.Close()
}
