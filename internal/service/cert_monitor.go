// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// CertMonitor monitors TLS certificate expiration
type CertMonitor struct {
	checkInterval time.Duration
	tlsConfig     *tls.Config
	origin        string
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewCertMonitor creates a new certificate monitor
func NewCertMonitor(ctx context.Context, tlsConfig *tls.Config, origin string, checkInterval time.Duration) *CertMonitor {
	monitorCtx, cancel := context.WithCancel(ctx)
	return &CertMonitor{
		checkInterval: checkInterval,
		tlsConfig:     tlsConfig,
		origin:        origin,
		ctx:           monitorCtx,
		cancel:        cancel,
	}
}

// Start starts the certificate monitoring service
func (cm *CertMonitor) Start() {
	if cm.checkInterval <= 0 {
		cm.checkInterval = 1 * time.Hour // Default to hourly checks
	}

	go cm.monitorLoop()
}

// Stop stops the certificate monitoring service
func (cm *CertMonitor) Stop() {
	if cm.cancel != nil {
		cm.cancel()
	}
}

// monitorLoop periodically checks certificate expiration
func (cm *CertMonitor) monitorLoop() {
	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	// Perform initial check
	cm.checkCertificates()

	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-ticker.C:
			cm.checkCertificates()
		}
	}
}

// checkCertificates checks all certificates in the TLS config
func (cm *CertMonitor) checkCertificates() {
	if cm.tlsConfig == nil {
		return
	}

	// Check server certificates if GetCertificate is set
	if cm.tlsConfig.GetCertificate != nil {
		// We can't easily enumerate all certificates that GetCertificate might return
		// This would require knowing all hostnames, which we don't have
		// For now, we'll check certificates that are statically configured
	}

	// Check certificates from Certificates field
	for i, cert := range cm.tlsConfig.Certificates {
		if len(cert.Certificate) == 0 {
			continue
		}

		// Parse the first certificate in the chain
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			slog.Warn("failed to parse certificate for expiration check",
				"origin", cm.origin,
				"cert_index", i,
				"error", err)
			continue
		}

		// Calculate days until expiration
		now := time.Now()
		daysUntilExpiry := x509Cert.NotAfter.Sub(now).Hours() / 24

		// Record metric
		certSerial := x509Cert.SerialNumber.String()
		certType := "server"
		metric.TLSCertExpiryDaysSet(cm.origin, certType, certSerial, daysUntilExpiry)

		// Log warning if expiring soon
		if daysUntilExpiry < 30 {
			slog.Warn("TLS certificate expiring soon",
				"origin", cm.origin,
				"cert_serial", certSerial,
				"days_until_expiry", daysUntilExpiry,
				"expires_at", x509Cert.NotAfter.Format(time.RFC3339))
		}
	}
}

// MonitorServerCertificates monitors server TLS certificates
// This should be called with the server's TLS config
func MonitorServerCertificates(ctx context.Context, tlsConfig *tls.Config, checkInterval time.Duration) *CertMonitor {
	if checkInterval <= 0 {
		checkInterval = 1 * time.Hour
	}

	monitor := NewCertMonitor(ctx, tlsConfig, "server", checkInterval)
	monitor.Start()
	return monitor
}

