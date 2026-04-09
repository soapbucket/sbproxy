// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
)

// Replacement represents a replacement.
type Replacement struct {
	Src     string
	Dest    string
	IsRegex bool // If true, Src is treated as a regex pattern
}

// StringReplacer represents a string replacer.
type StringReplacer struct {
	rdr             *bufio.Reader
	replacements    []Replacement
	compiledRegexes []*regexp.Regexp // Pre-compiled regex patterns (nil for non-regex or invalid patterns)
	closer          io.Closer
	buffer          bytes.Buffer
	err             error
}

// Read performs the read operation on the StringReplacer.
func (s *StringReplacer) Read(p []byte) (int, error) {
	var (
		err     error
		n       int
		current int
	)

	for {
		if s.buffer.Len() < len(p) {
			slog.Debug("filling buffer", "buff_length", s.buffer.Len(), "p_length", len(p))
			if err = s.fill(); err != nil {
				if err == io.EOF {
					slog.Debug("read - EOF encountered")
					s.err = err
				} else {
					slog.Debug("read - returning fill error", "n", n, "error", err)
					return n, err
				}
			}
		}

		current, err = s.buffer.Read(p[n:])
		if err != nil && err != io.EOF {
			slog.Debug("read - returning error", "n", n, "error", err)
			return n, err
		}
		n += current

		if n == len(p) {
			slog.Debug("read - returning", "n", n)
			return n, nil
		}
		if s.err != nil {
			slog.Debug("read - returning EOF", "n", n)
			return n, s.err
		}

	}
}

func (s *StringReplacer) fill() error {
	// Check if any replacement uses regex
	hasRegex := false
	for _, r := range s.replacements {
		if r.IsRegex {
			hasRegex = true
			break
		}
	}

	// If regex is involved, we need to read the entire body first
	// because regex matching requires full context
	if hasRegex {
		return s.fillWithRegex()
	}

	// For non-regex replacements, use streaming approach
	return s.fillStreaming()
}

func (s *StringReplacer) fillStreaming() error {
	// Find the maximum length among all replacement sources
	maxLength := 0
	for _, r := range s.replacements {
		if len(r.Src) > maxLength {
			maxLength = len(r.Src)
		}
	}

	// If no replacements, just pass through the data
	if maxLength == 0 {
		maxLength = 1024 // Use a reasonable buffer size for pass-through
	}

	data, err := s.rdr.Peek(maxLength * 2)
	if err != nil && err != io.EOF {
		slog.Debug("fill - error encountered", "error", err)
		return err
	}

	// Find the earliest match among all replacements
	earliestIndex := -1
	var matchedReplacement *Replacement

	for i := range s.replacements {
		srcBytes := []byte(s.replacements[i].Src)
		if index := bytes.Index(data, srcBytes); index != -1 {
			if earliestIndex == -1 || index < earliestIndex {
				earliestIndex = index
				matchedReplacement = &s.replacements[i]
			}
		}
	}

	// If we found a match, write data before it, then the replacement
	if earliestIndex != -1 {
		s.buffer.Write(data[:earliestIndex])
		s.buffer.WriteString(matchedReplacement.Dest)
		_, err := s.rdr.Discard(earliestIndex + len(matchedReplacement.Src))
		slog.Debug("fill - replacement found", "index", earliestIndex, "src", matchedReplacement.Src, "dest", matchedReplacement.Dest)
		return err
	}

	// No match found, write up to maxLength to ensure we don't split a potential match
	if len(data) >= maxLength {
		slog.Debug("fill - adding to buffer from peek", "max_length", maxLength)
		s.buffer.Write(data[:maxLength])
		_, err := s.rdr.Discard(maxLength)
		return err
	}

	// Less than maxLength remaining, write it all
	slog.Debug("fill - remaining", "length", len(data))
	s.buffer.Write(data)
	s.rdr.Discard(len(data))
	return err
}

func (s *StringReplacer) fillWithRegex() error {
	// Read the entire remaining body
	allData, err := io.ReadAll(s.rdr)
	if err != nil && err != io.EOF {
		slog.Debug("fillWithRegex - error reading body", "error", err)
		return err
	}

	// Convert to string for regex operations
	content := string(allData)

	// Apply all replacements in order using pre-compiled regexes
	for i, r := range s.replacements {
		if r.IsRegex {
			re := s.compiledRegexes[i]
			if re == nil {
				// Skip invalid regex patterns (logged during construction)
				continue
			}
			content = re.ReplaceAllString(content, r.Dest)
		} else {
			// Simple string replacement
			content = strings.ReplaceAll(content, r.Src, r.Dest)
		}
	}

	// Write the transformed content to buffer
	s.buffer.WriteString(content)
	s.err = io.EOF // Mark as complete since we've read everything
	return nil
}

// Close releases resources held by the StringReplacer.
func (s *StringReplacer) Close() error {
	return s.closer.Close()
}

// StringReplacement creates a transform that replaces a single string
func StringReplacement(src, dest string) Transformer {
	return Func(func(resp *http.Response) error {
		return stringReplacement(resp, src, dest)
	})
}

// MultiStringReplacement creates a transform that replaces multiple strings in a single pass
func MultiStringReplacement(replacements []Replacement) Transformer {
	return Func(func(resp *http.Response) error {
		return multiStringReplacement(resp, replacements)
	})
}

func stringReplacement(resp *http.Response, src, dest string) error {
	return multiStringReplacement(resp, []Replacement{{Src: src, Dest: dest}})
}

func multiStringReplacement(resp *http.Response, replacements []Replacement) error {
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	// we can parse only text or application json
	if !strings.HasPrefix(contentType, "text/") && !strings.EqualFold(contentType, "application/json") {
		return ErrInvalidContentType
	}

	// Pre-compile regex patterns during construction
	compiled := make([]*regexp.Regexp, len(replacements))
	for i, r := range replacements {
		if r.IsRegex {
			re, err := regexp.Compile(r.Src)
			if err != nil {
				slog.Debug("multiStringReplacement - invalid regex, will skip at runtime", "pattern", r.Src, "error", err)
				continue
			}
			compiled[i] = re
		}
	}

	replacer := &StringReplacer{
		rdr:             bufio.NewReader(resp.Body),
		replacements:    replacements,
		compiledRegexes: compiled,
		closer:          resp.Body,
	}
	resp.Body = replacer
	return nil
}
