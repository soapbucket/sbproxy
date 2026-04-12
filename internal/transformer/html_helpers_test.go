package transformer

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptimizeHTML_LowercaseTags(t *testing.T) {
	input := `<DIV CLASS="test">Content</DIV>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		LowercaseTags: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Check that tags are lowercase
	assert.Contains(t, string(body), "<div")
	assert.Contains(t, string(body), "</div>")
}

func TestOptimizeHTML_LowercaseAttributes(t *testing.T) {
	input := `<div CLASS="test" ID="main">Content</div>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		LowercaseAttributes: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Check that attributes are lowercase
	assert.Contains(t, string(body), "class=")
	assert.Contains(t, string(body), "id=")
}

func TestOptimizeHTML_RemoveBooleanAttributes(t *testing.T) {
	input := `<input type="checkbox" checked="checked" disabled="disabled">`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		RemoveBooleanAttributes: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Check that boolean attributes don't have values
	assert.Contains(t, string(body), "checked")
	assert.Contains(t, string(body), "disabled")
	assert.NotContains(t, string(body), `checked="checked"`)
	assert.NotContains(t, string(body), `disabled="disabled"`)
}

func TestOptimizeHTML_StripComments(t *testing.T) {
	input := `<div>Content</div><!-- This is a comment --><p>Text</p>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		StripComments: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Comments should be removed
	assert.NotContains(t, string(body), "<!--")
	assert.NotContains(t, string(body), "-->")
}

func TestOptimizeHTML_SortAttributes(t *testing.T) {
	input := `<div z="last" a="first" m="middle">Content</div>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		SortAttributes: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Attributes should be sorted alphabetically
	bodyStr := string(body)
	aIdx := strings.Index(bodyStr, "a=")
	mIdx := strings.Index(bodyStr, "m=")
	zIdx := strings.Index(bodyStr, "z=")
	
	assert.True(t, aIdx < mIdx && mIdx < zIdx, "Attributes should be sorted")
}

func TestStripSpace(t *testing.T) {
	input := `<div>   Content   with   spaces   </div>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(StripSpace(StripSpaceOptions{
		StripNewlines: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Multiple spaces should be reduced
	bodyStr := string(body)
	assert.NotContains(t, bodyStr, "   ")
}

func TestAddUniqueID(t *testing.T) {
	input := `<div>Content</div><p>Text</p><span>More</span>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(AddUniqueID(AddUniqueIDOptions{
		Prefix: "test",
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// IDs should be added (format: test1, test2, etc.)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, `id="test`)
	
	// Count IDs (format: test1, test2, etc. - no hyphen)
	idCount := strings.Count(bodyStr, `id="test`)
	assert.GreaterOrEqual(t, idCount, 2, "Should add IDs to multiple elements")
}

func TestAddUniqueID_ReplaceExisting(t *testing.T) {
	input := `<div id="existing">Content</div>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(AddUniqueID(AddUniqueIDOptions{
		Prefix:          "test",
		ReplaceExisting: true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	// Existing ID should be replaced (format: test1, test2, etc. - no hyphen)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, `id="test`)
	assert.NotContains(t, bodyStr, `id="existing"`)
}

func TestOptimizeHTML_CombinedOptions(t *testing.T) {
	input := `<DIV CLASS="test" ID="main"><!-- Comment -->Content</DIV>`
	resp := &http.Response{
		Body:    io.NopCloser(strings.NewReader(input)),
		Header:  make(http.Header),
		Request: &http.Request{},
	}
	resp.Header.Set("Content-Type", "text/html")

	transform := ModifyHTML(OptimizeHTML(OptimizeHTMLOptions{
		LowercaseTags:       true,
		LowercaseAttributes: true,
		StripComments:       true,
		SortAttributes:      true,
	}))
	err := transform.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	
	bodyStr := string(body)
	// All optimizations should be applied
	assert.Contains(t, bodyStr, "<div")
	assert.Contains(t, bodyStr, "class=")
	assert.Contains(t, bodyStr, "id=")
	assert.NotContains(t, bodyStr, "<!--")
}

