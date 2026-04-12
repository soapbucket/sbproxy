package transport_test

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

func TestStorage(t *testing.T) {
	// Check for GCP credentials environment variable
	credsPath := os.Getenv("GCP_CREDENTIALS_PATH")
	if credsPath == "" {
		t.Skip("Skipping storage test: GCP_CREDENTIALS_PATH environment variable not set")
	}

	creds, err := os.ReadFile(credsPath)
	if err != nil {
		t.Skipf("Skipping storage test: could not read credentials file %s: %v", credsPath, err)
	}

	settings := make(transport.Settings)
	settings[transport.StorageSettingSecret] = string(creds)
	settings[transport.StorageSettingBucket] = "sb-storagetest"
	settings[transport.StorageSettingProjectID] = "durable-utility-336220"

	manager, err := cacher.NewCacher(cacher.Settings{Driver: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	s := transport.NewStorage("google", settings, manager)
	req := httptest.NewRequest("GET", "http://test/bike.png", nil)

	resp, err := s.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("expected 200, got", resp.StatusCode)
	}

}
