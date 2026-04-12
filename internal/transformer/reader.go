// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import "io"

// TransformReader represents a transform reader.
type TransformReader struct {
	reader io.Reader
	closer io.Closer
}

// Read performs the read operation on the TransformReader.
func (t *TransformReader) Read(p []byte) (n int, err error) {
	return t.reader.Read(p)
}

// Close releases resources held by the TransformReader.
func (t *TransformReader) Close() error {
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

// NewTransformReader creates and initializes a new TransformReader.
func NewTransformReader(rdr io.Reader, clsr io.Closer) io.ReadCloser {
	return &TransformReader{
		reader: rdr,
		closer: clsr,
	}
}
