// Package cli defines the CLI entry point and command-line flag parsing for the proxy server.
package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/service"
)

// NewValidateCmd creates the validate command
func NewValidateCmd() *cobra.Command {
	cfg := &Config{}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate proxy configuration",
		Long: `Validate the proxy configuration file without starting the server.

Loads and parses the configuration, reporting any errors found.
Exits with code 0 if the configuration is valid, or code 1 if errors are found.

Examples:
  sb validate
  sb validate -c /etc/sbproxy
  sb validate -f /path/to/sb.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// If config file is set but config dir was not explicitly provided,
			// derive config dir from the config file's parent directory
			if cfg.ConfigFile != "" && !cmd.Flags().Changed(configDirFlag) {
				cfg.ConfigDir = filepath.Dir(cfg.ConfigFile)
				cfg.ConfigFile = filepath.Base(cfg.ConfigFile)
			}

			configDir := reqctx.CleanDirInput(cfg.ConfigDir)

			if err := service.LoadConfig(configDir, cfg.ConfigFile); err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}

			fmt.Println("Configuration is valid.")
			return nil
		},
	}

	addConfigFlags(cmd, cfg)
	return cmd
}
