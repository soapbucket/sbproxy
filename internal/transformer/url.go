// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"


	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// URLManager defines the interface for url manager operations.
type URLManager interface {
	Get(context.Context, string) ([]byte, error)
}

// SignedURL represents a signed url.
type SignedURL struct {
	URL       string `json:"url"`
	Integrity string `json:"Inegrity"`
}

// RewriteURL performs the rewrite url operation.
func RewriteURL(req *http.Request, manager URLManager) ModifyFn {
	slog.Debug("rewrite url init", "request", req.URL.String())

	return func(token html.Token, writer io.Writer) error {
		if token.Type != html.StartTagToken && token.Type != html.SelfClosingTagToken {
			return nil
		}

		if token.DataAtom != atom.Script && token.DataAtom != atom.Link && token.DataAtom != atom.Img && token.DataAtom != atom.A {
			return nil
		}

		var (
			integrityIndex = -1
			urlIndex       = -1
		)

		for i, attr := range token.Attr {
			switch attr.Key {
			case "integrity":
				integrityIndex = i
			case "src", "href":
				urlIndex = i
			default:
			}
		}

		if urlIndex < 0 {
			return nil
		}

		href := token.Attr[urlIndex].Val
		if URL, err := url.Parse(href); err == nil {
			if URL.Host == "" {
				URL.Host = req.URL.Host
			}
			if URL.Scheme == "" {
				URL.Scheme = req.URL.Scheme
			}
			URL = httputil.SortURLParams(URL)
			href = URL.String()
		}

		slog.Debug("looking up url", "href", href)
		data, err := manager.Get(context.Background(), href)
		if err != nil {
			return nil
		}

		var signed = new(SignedURL)
		if err := json.Unmarshal(data, signed); err != nil {
			return nil
		}

		if signed.URL != "" {
			token.Attr[urlIndex].Val = signed.URL

			if signed.Integrity != "" {
				if integrityIndex != -1 {
					token.Attr[integrityIndex].Val = signed.Integrity
				} else {
					token.Attr = append(token.Attr, html.Attribute{
						Key: "integrity",
						Val: signed.Integrity,
					})
				}
			}
		}

		_, _ = writer.Write([]byte(token.String()))

		return ErrSkipToken
	}
}
