// pagination.go implements auto-pagination for cursor, offset, and link-header strategies.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// PaginationConfig configures auto-pagination for a proxy handler.
type PaginationConfig struct {
	// Type: "cursor", "offset", "link_header"
	Type string `json:"type"`

	// CursorPath is a dot-separated path to the next cursor/token in the response.
	// Used with "cursor" type.
	NextCursorPath string `json:"next_cursor_path,omitempty"`

	// CursorParam is the query parameter name to set the cursor value.
	CursorParam string `json:"cursor_param,omitempty"`

	// ResultsPath is a dot-separated path to the results array in each response page.
	ResultsPath string `json:"results_path,omitempty"`

	// OffsetParam is the query parameter for offset (used with "offset" type).
	OffsetParam string `json:"offset_param,omitempty"`

	// LimitParam is the query parameter for page size (used with "offset" type).
	LimitParam string `json:"limit_param,omitempty"`

	// PageSize is the number of items per page for offset pagination.
	PageSize int `json:"page_size,omitempty"`

	// MaxPages limits the number of pages to fetch. Default 5.
	MaxPages int `json:"max_pages,omitempty"`
}

// executePaginated fetches all pages and aggregates results.
func executePaginated(ctx context.Context, client *http.Client, baseURL string, method string,
	headers map[string]string, config *PaginationConfig) (interface{}, error) {

	maxPages := config.MaxPages
	if maxPages <= 0 {
		maxPages = 5
	}

	var allResults []interface{}

	switch config.Type {
	case "cursor":
		return executeCursorPagination(ctx, client, baseURL, method, headers, config, maxPages)
	case "offset":
		return executeOffsetPagination(ctx, client, baseURL, method, headers, config, maxPages)
	case "link_header":
		return executeLinkHeaderPagination(ctx, client, baseURL, method, headers, config, maxPages)
	default:
		return allResults, fmt.Errorf("unsupported pagination type: %s", config.Type)
	}
}

func executeCursorPagination(ctx context.Context, client *http.Client, baseURL, method string,
	headers map[string]string, config *PaginationConfig, maxPages int) (interface{}, error) {

	var allResults []interface{}
	currentURL := baseURL
	cursorParam := config.CursorParam
	if cursorParam == "" {
		cursorParam = "cursor"
	}

	for page := 0; page < maxPages; page++ {
		body, err := doPageRequest(ctx, client, currentURL, method, headers)
		if err != nil {
			return nil, fmt.Errorf("page %d failed: %w", page, err)
		}

		var parsed interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("page %d: invalid JSON: %w", page, err)
		}

		// Extract results from results_path
		if config.ResultsPath != "" {
			items := extractByPath(parsed, config.ResultsPath)
			if arr, ok := items.([]interface{}); ok {
				allResults = append(allResults, arr...)
			}
		} else {
			if arr, ok := parsed.([]interface{}); ok {
				allResults = append(allResults, arr...)
			} else {
				allResults = append(allResults, parsed)
			}
		}

		// Extract next cursor
		if config.NextCursorPath == "" {
			break
		}
		nextCursor := extractByPath(parsed, config.NextCursorPath)
		cursorStr, ok := nextCursor.(string)
		if !ok || cursorStr == "" {
			break // No more pages
		}

		// Build next page URL
		parsedURL, err := url.Parse(baseURL)
		if err != nil {
			break
		}
		q := parsedURL.Query()
		q.Set(cursorParam, cursorStr)
		parsedURL.RawQuery = q.Encode()
		currentURL = parsedURL.String()
	}

	return allResults, nil
}

func executeOffsetPagination(ctx context.Context, client *http.Client, baseURL, method string,
	headers map[string]string, config *PaginationConfig, maxPages int) (interface{}, error) {

	var allResults []interface{}
	offsetParam := config.OffsetParam
	if offsetParam == "" {
		offsetParam = "offset"
	}
	pageSize := config.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	for page := 0; page < maxPages; page++ {
		parsedURL, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		q := parsedURL.Query()
		q.Set(offsetParam, fmt.Sprintf("%d", page*pageSize))
		if config.LimitParam != "" {
			q.Set(config.LimitParam, fmt.Sprintf("%d", pageSize))
		}
		parsedURL.RawQuery = q.Encode()

		body, err := doPageRequest(ctx, client, parsedURL.String(), method, headers)
		if err != nil {
			return nil, fmt.Errorf("page %d failed: %w", page, err)
		}

		var parsed interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("page %d: invalid JSON: %w", page, err)
		}

		var items []interface{}
		if config.ResultsPath != "" {
			if extracted := extractByPath(parsed, config.ResultsPath); extracted != nil {
				if arr, ok := extracted.([]interface{}); ok {
					items = arr
				}
			}
		} else if arr, ok := parsed.([]interface{}); ok {
			items = arr
		}

		if len(items) == 0 {
			break // No more results
		}
		allResults = append(allResults, items...)

		if len(items) < pageSize {
			break // Last page (partial)
		}
	}

	return allResults, nil
}

func executeLinkHeaderPagination(ctx context.Context, client *http.Client, baseURL, method string,
	headers map[string]string, config *PaginationConfig, maxPages int) (interface{}, error) {

	var allResults []interface{}
	currentURL := baseURL

	for page := 0; page < maxPages; page++ {
		req, err := http.NewRequestWithContext(ctx, method, currentURL, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("page %d failed: %w", page, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("page %d: HTTP %d", page, resp.StatusCode)
		}

		var parsed interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, err
		}

		if config.ResultsPath != "" {
			if items := extractByPath(parsed, config.ResultsPath); items != nil {
				if arr, ok := items.([]interface{}); ok {
					allResults = append(allResults, arr...)
				}
			}
		} else if arr, ok := parsed.([]interface{}); ok {
			allResults = append(allResults, arr...)
		}

		// Parse Link header for next URL
		nextURL := parseLinkHeader(resp.Header.Get("Link"), "next")
		if nextURL == "" {
			break
		}
		currentURL = nextURL
	}

	return allResults, nil
}

func doPageRequest(ctx context.Context, client *http.Client, reqURL, method string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// parseLinkHeader extracts a URL from an RFC 5988 Link header by relation type.
// Example: <https://api.example.com/items?page=2>; rel="next"
func parseLinkHeader(header, rel string) string {
	if header == "" {
		return ""
	}

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		sections := strings.Split(part, ";")
		if len(sections) < 2 {
			continue
		}

		urlPart := strings.TrimSpace(sections[0])
		if !strings.HasPrefix(urlPart, "<") || !strings.HasSuffix(urlPart, ">") {
			continue
		}

		for _, param := range sections[1:] {
			param = strings.TrimSpace(param)
			if strings.EqualFold(param, `rel="`+rel+`"`) || strings.EqualFold(param, `rel='`+rel+`'`) {
				return urlPart[1 : len(urlPart)-1]
			}
		}
	}

	return ""
}
