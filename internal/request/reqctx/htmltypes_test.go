package reqctx

import (
	"encoding/json"
	"testing"
)

func TestHTMLState_Constants(t *testing.T) {
	// Verify the iota ordering is correct
	states := []struct {
		name  string
		state HTMLState
		value int
	}{
		{"StateText", StateText, 0},
		{"StateTagStart", StateTagStart, 1},
		{"StateTagName", StateTagName, 2},
		{"StateTagAttrName", StateTagAttrName, 3},
		{"StateTagAttrValue", StateTagAttrValue, 4},
		{"StateTagAttrValueQuoted", StateTagAttrValueQuoted, 5},
		{"StateTagAttrValueUnquoted", StateTagAttrValueUnquoted, 6},
		{"StateComment", StateComment, 7},
		{"StateCDATA", StateCDATA, 8},
		{"StateDoctype", StateDoctype, 9},
		{"StateProcessingInstruction", StateProcessingInstruction, 10},
	}

	for _, tt := range states {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.state) != tt.value {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.value, int(tt.state))
			}
		})
	}
}

func TestHTMLState_Distinct(t *testing.T) {
	seen := make(map[HTMLState]string)
	all := map[string]HTMLState{
		"StateText":                  StateText,
		"StateTagStart":              StateTagStart,
		"StateTagName":               StateTagName,
		"StateTagAttrName":           StateTagAttrName,
		"StateTagAttrValue":          StateTagAttrValue,
		"StateTagAttrValueQuoted":    StateTagAttrValueQuoted,
		"StateTagAttrValueUnquoted":  StateTagAttrValueUnquoted,
		"StateComment":               StateComment,
		"StateCDATA":                 StateCDATA,
		"StateDoctype":               StateDoctype,
		"StateProcessingInstruction": StateProcessingInstruction,
	}

	for name, state := range all {
		if existing, ok := seen[state]; ok {
			t.Errorf("Duplicate state value: %s and %s both have value %d", name, existing, state)
		}
		seen[state] = name
	}
}

func TestSimpleToken_Defaults(t *testing.T) {
	var token SimpleToken

	if token.Type != StateText {
		t.Error("Default Type should be StateText (0)")
	}
	if token.Data != "" {
		t.Error("Default Data should be empty")
	}
	if token.TagName != "" {
		t.Error("Default TagName should be empty")
	}
	if token.Attributes != nil {
		t.Error("Default Attributes should be nil")
	}
	if token.Raw != nil {
		t.Error("Default Raw should be nil")
	}
}

func TestSimpleToken_Fields(t *testing.T) {
	token := SimpleToken{
		Type:       StateTagName,
		Data:       "<div class=\"main\">",
		TagName:    "div",
		Attributes: map[string]string{"class": "main", "id": "root"},
		Raw:        []byte("<div class=\"main\" id=\"root\">"),
	}

	if token.Type != StateTagName {
		t.Errorf("Expected StateTagName, got %d", token.Type)
	}
	if token.TagName != "div" {
		t.Errorf("Expected 'div', got '%s'", token.TagName)
	}
	if len(token.Attributes) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(token.Attributes))
	}
	if token.Attributes["class"] != "main" {
		t.Errorf("Expected class='main', got '%s'", token.Attributes["class"])
	}
	if token.Attributes["id"] != "root" {
		t.Errorf("Expected id='root', got '%s'", token.Attributes["id"])
	}
}

func TestAttr_JSON(t *testing.T) {
	t.Run("Marshal", func(t *testing.T) {
		a := Attr{Key: "class", Value: "container"}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		expected := `{"key":"class","value":"container"}`
		if string(data) != expected {
			t.Errorf("Expected %s, got %s", expected, string(data))
		}
	})

	t.Run("Unmarshal", func(t *testing.T) {
		data := `{"key":"href","value":"https://example.com"}`
		var a Attr
		if err := json.Unmarshal([]byte(data), &a); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if a.Key != "href" {
			t.Errorf("Expected key 'href', got '%s'", a.Key)
		}
		if a.Value != "https://example.com" {
			t.Errorf("Expected value 'https://example.com', got '%s'", a.Value)
		}
	})

	t.Run("EmptyValue", func(t *testing.T) {
		a := Attr{Key: "disabled", Value: ""}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var b Attr
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if b.Key != "disabled" {
			t.Errorf("Expected key 'disabled', got '%s'", b.Key)
		}
		if b.Value != "" {
			t.Errorf("Expected empty value, got '%s'", b.Value)
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		original := Attr{Key: "data-value", Value: `"quoted"`}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded Attr
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if original.Key != decoded.Key || original.Value != decoded.Value {
			t.Errorf("Round-trip mismatch: %+v != %+v", original, decoded)
		}
	})
}
