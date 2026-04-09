// Package httperror provides structured HTTP error responses with consistent formatting.
package httputil

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// HandleError processes error.
func HandleError(status int, err error, w http.ResponseWriter, r *http.Request) {
	attrs := []any{"status", status, "error", err, "request", r.URL.String()}
	if status >= 500 && status < 520 {
		slog.Error("handling error", attrs...)
	} else {
		slog.Warn("handling error", attrs...)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	bodyString := string(body)

	var headers = make(map[string]string)
	for key, values := range r.Header {
		headers[strings.ReplaceAll(strings.ToLower(key), "-", "_")] = strings.Join(values, ", ")
	}

	requestData := reqctx.GetRequestData(r.Context())

	var request = map[string]interface{}{
		"url":     r.URL.String(),
		"method":  r.Method,
		"context": requestData,
	}
	if len(headers) > 0 {
		request["headers"] = headers
	}
	if bodyString != "" {
		request["body"] = bodyString
	}

	var obj = map[string]interface{}{
		"status":  status,
		"error":   err.Error(),
		"request": request,
	}

	data, _ := json.Marshal(obj)

	if r.Header.Get("Content-Type") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/html")
		sb := bytes.Buffer{}
		sb.WriteString("<html><body>")
		sb.WriteString("<h1>Error</h1>")
		sb.WriteString("<p>")
		sb.WriteString(err.Error())
		sb.WriteString("</p>")
		sb.WriteString("<p>")
		sb.WriteString("<strong>Request:</strong> ")
		sb.WriteString(request["method"].(string))
		sb.WriteString(" ")
		sb.WriteString(request["url"].(string))
		sb.WriteString("</p>")

		sb.WriteString("<script>var data=")
		sb.Write(data)
		sb.WriteString("; console.log(data);</script>")
		sb.WriteString("</body></html>")
		data = sb.Bytes()
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(status)
	w.Write(data)
}
