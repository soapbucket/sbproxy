// Package formatconvert registers the format_convert transform.
package formatconvert

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("format_convert", New)
}

// Config holds configuration for the format_convert transform.
type Config struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

// formatConvertTransform implements plugin.TransformHandler.
type formatConvertTransform struct {
	from string
	to   string
}

// New creates a new format_convert transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("format_convert: %w", err)
	}

	if cfg.From == "" || cfg.To == "" {
		return nil, fmt.Errorf("format_convert: both 'from' and 'to' are required")
	}

	validFrom := map[string]bool{"xml": true, "csv": true}
	if !validFrom[cfg.From] {
		return nil, fmt.Errorf("format_convert: unsupported source format %q (supported: xml, csv)", cfg.From)
	}

	if cfg.To != "json" {
		return nil, fmt.Errorf("format_convert: unsupported target format %q (supported: json)", cfg.To)
	}

	return &formatConvertTransform{from: cfg.From, to: cfg.To}, nil
}

func (c *formatConvertTransform) Type() string { return "format_convert" }
func (c *formatConvertTransform) Apply(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	var result []byte

	switch c.from {
	case "xml":
		result, err = xmlToJSON(body)
	case "csv":
		result, err = csvToJSON(body)
	default:
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(result))
	resp.Header.Set("Content-Length", strconv.Itoa(len(result)))
	resp.Header.Set("Content-Type", "application/json")
	return nil
}

func xmlToJSON(data []byte) ([]byte, error) {
	result := make(map[string]interface{})
	decoder := xml.NewDecoder(bytes.NewReader(data))

	var stack []map[string]interface{}
	var keyStack []string
	stack = append(stack, result)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch t := token.(type) {
		case xml.StartElement:
			child := make(map[string]interface{})
			for _, attr := range t.Attr {
				child["@"+attr.Name.Local] = attr.Value
			}
			stack = append(stack, child)
			keyStack = append(keyStack, t.Name.Local)

		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 1 {
				current := stack[len(stack)-1]
				if len(current) == 0 {
					parent := stack[len(stack)-2]
					key := keyStack[len(keyStack)-1]
					parent[key] = text
					stack = stack[:len(stack)-1]
					keyStack = keyStack[:len(keyStack)-1]
					stack = append(stack, nil)
					keyStack = append(keyStack, "")
				} else {
					current["#text"] = text
				}
			}

		case xml.EndElement:
			if len(stack) < 2 {
				continue
			}
			child := stack[len(stack)-1]
			key := keyStack[len(keyStack)-1]
			stack = stack[:len(stack)-1]
			keyStack = keyStack[:len(keyStack)-1]

			if child == nil {
				continue
			}

			parent := stack[len(stack)-1]
			if existing, ok := parent[key]; ok {
				switch v := existing.(type) {
				case []interface{}:
					parent[key] = append(v, child)
				default:
					parent[key] = []interface{}{v, child}
				}
			} else {
				parent[key] = child
			}
		}
	}

	return json.Marshal(result)
}

func csvToJSON(data []byte) ([]byte, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) < 1 {
		return []byte("[]"), nil
	}

	headers := records[0]
	var rows []map[string]string

	for _, record := range records[1:] {
		row := make(map[string]string, len(headers))
		for i, header := range headers {
			if i < len(record) {
				row[header] = record[i]
			}
		}
		rows = append(rows, row)
	}

	if rows == nil {
		return []byte("[]"), nil
	}

	return json.Marshal(rows)
}
