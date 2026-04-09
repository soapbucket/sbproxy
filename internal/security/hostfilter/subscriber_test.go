package hostfilter

import (
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

func TestHandleMessage_AddHostname(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{})

	sub := &hostFilterSub{filter: hf}

	body, _ := json.Marshal(hostFilterMessage{
		ConfigID:       "cfg-1",
		ConfigHostname: "new.example.com",
	})

	msg := &messenger.Message{Body: body}
	if err := sub.handleMessage(nil, msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hf.Check("new.example.com") {
		t.Error("expected new.example.com to be in filter after Add")
	}
}

func TestHandleMessage_BatchAdd(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{})

	sub := &hostFilterSub{filter: hf}

	batch := hostFilterBatch{
		Updates: []hostFilterMessage{
			{ConfigID: "cfg-1", ConfigHostname: "a.com"},
			{ConfigID: "cfg-2", ConfigHostname: "b.com"},
			{ConfigID: "cfg-3", ConfigHostname: "c.com"},
		},
	}
	body, _ := json.Marshal(batch)

	msg := &messenger.Message{Body: body}
	if err := sub.handleMessage(nil, msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, h := range []string{"a.com", "b.com", "c.com"} {
		if !hf.Check(h) {
			t.Errorf("expected %s to be in filter after batch Add", h)
		}
	}
}

func TestHandleMessage_ParamsFallback(t *testing.T) {
	hf := New(100, 0.001)
	hf.Reload([]string{})

	sub := &hostFilterSub{filter: hf}

	msg := &messenger.Message{
		Params: map[string]string{
			"config_id":       "cfg-1",
			"config_hostname": "param.example.com",
		},
	}

	if err := sub.handleMessage(nil, msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hf.Check("param.example.com") {
		t.Error("expected param.example.com to be in filter after params fallback")
	}
}

func TestHandleMessage_EmptyMessage(t *testing.T) {
	hf := New(100, 0.001)
	sub := &hostFilterSub{filter: hf}

	msg := &messenger.Message{}
	if err := sub.handleMessage(nil, msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
