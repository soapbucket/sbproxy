package service

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureMTLS_Disabled(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientCAs != nil {
		t.Error("expected nil ClientCAs when disabled")
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %d", tlsCfg.ClientAuth)
	}
}

func TestConfigureMTLS_RequireMode(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	caPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
		VerifyMode:   "require",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %d", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("expected non-nil ClientCAs")
	}
}

func TestConfigureMTLS_DefaultMode(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	caPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert for default, got %d", tlsCfg.ClientAuth)
	}
}

func TestConfigureMTLS_OptionalMode(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	caPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
		VerifyMode:   "optional",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("expected VerifyClientCertIfGiven, got %d", tlsCfg.ClientAuth)
	}
}

func TestConfigureMTLS_NoneMode(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	caPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
		VerifyMode:   "none",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %d", tlsCfg.ClientAuth)
	}
}

func TestConfigureMTLS_UnknownMode(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	caPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
		VerifyMode:   "invalid",
	})
	if err == nil {
		t.Fatal("expected error for unknown verify_mode")
	}
}

func TestConfigureMTLS_MissingFile(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestConfigureMTLS_InvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tlsCfg := &tls.Config{}
	err := ConfigureMTLS(tlsCfg, MTLSConfig{
		Enabled:      true,
		ClientCAFile: caFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid certificate")
	}
}
