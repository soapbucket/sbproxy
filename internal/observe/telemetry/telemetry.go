// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/security/tlsutil"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

)

const (
	metricsPath   = "/metrics"
	pprofBasePath = "/debug"
)

var (
	certMgr   *tlsutil.CertManager
	certMgrMu sync.RWMutex
)

// Config represents telemetry server configuration
type Config struct {
	BindAddress        string
	BindPort           int
	TLSCert            string
	TLSKey             string
	CertificateFile    string
	CertificateKeyFile string
	EnableProfiler     bool
	MinTLSVersion      int
	TLSCipherSuites    []string
}

// ShouldBind returns true if the service must be started
func ShouldBind(c Config) bool {
	if c.BindPort > 0 {
		return true
	}
	if filepath.IsAbs(c.BindAddress) {
		return true
	}
	return false
}

// Initialize configures and starts the telemetry server
func Initialize(c Config, ctx context.Context, configDir string) error {
	slog.Info("initializing telemetry server", "config", c)

	certificateFile := reqctx.GetConfigPath(c.CertificateFile, configDir)
	certificateKeyFile := reqctx.GetConfigPath(c.CertificateKeyFile, configDir)

	router := InitializeRouter(c.EnableProfiler)

	httpServer := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16KB
		ErrorLog:          log.New(os.Stderr, "", 0),
	}

	// Start graceful shutdown goroutine
	go func() {
		<-ctx.Done()
		slog.Info("Shutting down telemetry server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Telemetry server shutdown error", "error", err)
		}
	}()

	if certificateFile != "" && certificateKeyFile != "" {
		keyPairs := []tlsutil.TLSKeyPair{
			{
				Cert: certificateFile,
				Key:  certificateKeyFile,
			},
		}
		mgr, err := tlsutil.NewCertManager(keyPairs, configDir, "telemetry")
		if err != nil {
			return fmt.Errorf("failed to create certificate manager: %w", err)
		}

		certMgrMu.Lock()
		certMgr = mgr
		certMgrMu.Unlock()

		tlsConfig := &tls.Config{
			GetCertificate:           certMgr.GetCertificateFunc(tlsutil.DefaultTLSKeyPairID),
			MinVersion:               tlsutil.GetTLSVersion(c.MinTLSVersion),
			NextProtos:               []string{"h2", "http/1.1"},
			CipherSuites:             tlsutil.GetTLSCiphersFromNames(c.TLSCipherSuites),
			PreferServerCipherSuites: true,
		}
		slog.Debug("configured TLS cipher suites", "cipher_suites", tlsConfig.CipherSuites)
		httpServer.TLSConfig = tlsConfig
		return HTTPListenAndServe(httpServer, c.BindAddress, c.BindPort, true, "telemetry")
	}
	return HTTPListenAndServe(httpServer, c.BindAddress, c.BindPort, false, "telemetry")
}

// HTTPListenAndServe is a wrapper for ListenAndServe that support both tcp
// and Unix-domain sockets
func HTTPListenAndServe(srv *http.Server, address string, port int, isTLS bool, logSender string) error {
	var listener net.Listener
	var err error

	if filepath.IsAbs(address) {
		if !reqctx.IsFileInputValid(address) {
			return fmt.Errorf("invalid socket address %#v", address)
		}
		err = createDirPathIfMissing(address, os.ModePerm)
		if err != nil {
			slog.Error("error creating Unix-domain socket parent dir", "error", err)
			slog.Error("error creating Unix-domain socket parent dir", "error", err)
		}
		os.Remove(address)
		listener, err = httputil.NewListener("unix", address, srv.ReadTimeout, srv.WriteTimeout)
	} else {
		listener, err = httputil.NewListener("tcp", fmt.Sprintf("%s:%d", address, port), srv.ReadTimeout, srv.WriteTimeout)
	}
	if err != nil {
		return err
	}

	slog.Info("server listener registered", "address", listener.Addr().String(), "tls_enabled", isTLS)

	defer listener.Close()

	if isTLS {
		return srv.ServeTLS(listener, "", "")
	}
	return srv.Serve(listener)
}

// Reload reloads the certificate manager
func Reload() error {
	certMgrMu.RLock()
	defer certMgrMu.RUnlock()

	if certMgr != nil {
		return certMgr.Reload()
	}
	return nil
}

func createDirPathIfMissing(file string, perm os.FileMode) error {
	dirPath := filepath.Dir(file)
	if _, err := os.Stat(dirPath); errors.Is(err, fs.ErrNotExist) {
		err = os.MkdirAll(dirPath, perm)
		if err != nil {
			return err
		}
	}
	return nil
}
