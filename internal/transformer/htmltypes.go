// Package htmltypes defines HTML token types and utilities for content transformation.
package transformer

// HTMLState represents the parsing state for HTML
type HTMLState int

const (
	// StateText is a constant for state text.
	StateText HTMLState = iota
	// StateTagStart is a constant for state tag start.
	StateTagStart
	// StateTagName is a constant for state tag name.
	StateTagName
	// StateTagAttrName is a constant for state tag attr name.
	StateTagAttrName
	// StateTagAttrValue is a constant for state tag attr value.
	StateTagAttrValue
	// StateTagAttrValueQuoted is a constant for state tag attr value quoted.
	StateTagAttrValueQuoted
	// StateTagAttrValueUnquoted is a constant for state tag attr value unquoted.
	StateTagAttrValueUnquoted
	// StateComment is a constant for state comment.
	StateComment
	// StateCDATA is a constant for state cdata.
	StateCDATA
	// StateDoctype is a constant for state doctype.
	StateDoctype
	// StateProcessingInstruction is a constant for state processing instruction.
	StateProcessingInstruction
)

// SimpleToken represents a simple HTML token for optimized parsing
type SimpleToken struct {
	Type       HTMLState
	Data       string
	TagName    string
	Attributes map[string]string
	Raw        []byte
}

// Attr represents an HTML attribute
type Attr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
