// Package cli defines the CLI entry point and command-line flag parsing for the proxy server.
package cli

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/service"
)

// NewServeCmd creates the serve command
func NewServeCmd() *cobra.Command {
	cfg := &Config{}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Soapbucket service",
		Long: `To start the Soapbucket with the default values for the command line flags simply
use:

$ sb serve

Please take a look at the usage below to customize the startup options`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// If config file is set but config dir was not explicitly provided,
			// derive config dir from the config file's parent directory
			if cfg.ConfigFile != "" && !cmd.Flags().Changed(configDirFlag) {
				cfg.ConfigDir = filepath.Dir(cfg.ConfigFile)
				cfg.ConfigFile = filepath.Base(cfg.ConfigFile)
			}

			svc := &service.Service{
				ConfigDir:         reqctx.CleanDirInput(cfg.ConfigDir),
				ConfigFile:        cfg.ConfigFile,
				LogLevel:          cfg.LogLevel,
				RequestLogLevel:   cfg.RequestLogLevel,
				GraceTime:         cfg.GraceTime,
				DisableHostFilter: cfg.DisableHostFilter,
				DisableSbFlags:    cfg.DisableSbFlags,
			}

			if err := svc.Start(); err != nil {
				return err
			}

			// Wait for service (graceful shutdown or error)
			if err := svc.Wait(); err != nil {
				// Suppress usage output for expected shutdown errors
				if err == http.ErrServerClosed || strings.Contains(err.Error(), "http: Server closed") {
					// Graceful shutdown, no error to report
					return nil
				}
				return err
			}
			return nil
		},
	}

	addServeFlags(serveCmd, cfg)
	return serveCmd
}
