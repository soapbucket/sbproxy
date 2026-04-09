package pii

import (
	"fmt"
	"testing"
	"github.com/tidwall/gjson"
)

func TestGJSONOffset(t *testing.T) {
	body := []byte(`{"name": "John", "data": {"ssn": "123-45-6789"}}`)
	res := gjson.ParseBytes(body)
	
	ssn := res.Get("data.ssn")
	fmt.Printf("SSN: %s, Index: %d, RawLen: %d\n", ssn.String(), ssn.Index, len(ssn.Raw))
	
	// Check if the offset matches in the original body
	extracted := body[ssn.Index : ssn.Index+len(ssn.Raw)]
	fmt.Printf("Extracted: %s\n", extracted)
}
