// Package cli defines the CLI entry point and command-line flag parsing for the proxy server.
package cli

import (
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/soapbucket/sbproxy/internal/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//go:embed banner.txt
var banner string

const (
	configDirFlag        = "config-dir"
	configDirKey         = "config_dir"
	configFileFlag       = "config-file"
	configFileKey        = "config_file"
	logLevelFlag         = "log-level"
	logLevelKey          = "log_level"
	requestLogLevelFlag  = "request-log-level"
	requestLogLevelKey   = "request_log_level"
	graceTimeFlag        = "grace-time"
	graceTimeKey         = "grace_time"
	disableHostFilterFlag = "disable-host-filter"
	disableHostFilterKey  = "disable_host_filter"
	defaultConfigDir     = "."
	defaultConfigFile    = ""
	defaultLogLevel      = "info"
	defaultRequestLogLevel = ""
	defaultGraceTime     = 0
)

// Config holds all command-line configuration
type Config struct {
	ConfigDir          string
	ConfigFile         string
	LogLevel           string
	RequestLogLevel    string
	GraceTime          int
	DisableHostFilter  bool
}

// NewRootCmd creates the root command
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sb",
		Short: "Soapbucket Proxy",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("%s  v%s\n", banner, version.Version)
			_ = cmd.Usage()
		},
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolP("version", "v", false, "")
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s, go: %s, platform: %s)",
		version.Version, version.BuildHash, version.BuildDate, version.GoVersion, version.BuildPlatform)
	rootCmd.SetVersionTemplate("sbproxy v{{.Version}}\n")
	return rootCmd
}

// Execute runs the root command
func Execute() {
	rootCmd := NewRootCmd()
	rootCmd.AddCommand(NewServeCmd())
	rootCmd.AddCommand(NewValidateCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func addConfigFlags(cmd *cobra.Command, cfg *Config) {
	viper.SetDefault(configDirKey, defaultConfigDir)
	if err := viper.BindEnv(configDirKey, "SB_CONFIG_DIR"); err != nil {
		// This should never happen as BindEnv only errors with empty key
		log.Fatalf("failed to bind config_dir env: %v", err)
	}
	cmd.Flags().StringVarP(&cfg.ConfigDir, configDirFlag, "c", viper.GetString(configDirKey),
		`Location for the config dir. This directory
is used as the base for files with a relative
path, eg. the private keys for the web
server or the SQLite database if you use
SQLite as data provider.
The configuration file, if not explicitly set,
is looked for in this dir. We support reading
from JSON, TOML, YAML, HCL, envfile and Java
properties config files. The default config
file name is "sb" and therefore
"sb.json", "sb.yaml" and so on are
searched.
This flag can be set using SB_CONFIG_DIR
env var.`)
	if err := viper.BindPFlag(configDirKey, cmd.Flags().Lookup(configDirFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", configDirFlag, err)
	}

	viper.SetDefault(configFileKey, defaultConfigFile)
	if err := viper.BindEnv(configFileKey, "SB_CONFIG_FILE"); err != nil {
		log.Fatalf("failed to bind config_file env: %v", err)
	}
	cmd.Flags().StringVarP(&cfg.ConfigFile, configFileFlag, "f", viper.GetString(configFileKey),
		`Path to the proxy configuration file.
This flag explicitly defines the path, name
and extension of the config file. If must be
an absolute path or a path relative to the
configuration directory. The specified file
name must have a supported extension (JSON,
YAML, TOML, HCL or Java properties).
This flag can be set using SB_CONFIG_FILE
env var.`)
	if err := viper.BindPFlag(configFileKey, cmd.Flags().Lookup(configFileFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", configFileFlag, err)
	}
}

func addServeFlags(cmd *cobra.Command, cfg *Config) {
	addConfigFlags(cmd, cfg)

	viper.SetDefault(logLevelKey, defaultLogLevel)
	if err := viper.BindEnv(logLevelKey, "SB_LOG_LEVEL"); err != nil {
		log.Fatalf("failed to bind log_level env: %v", err)
	}
	cmd.Flags().StringVar(&cfg.LogLevel, logLevelFlag, viper.GetString(logLevelKey),
		`Set the log level. Supported values:
debug, info, warn, error.
This flag can be set
using SB_LOG_LEVEL env var too.
`)
	if err := viper.BindPFlag(logLevelKey, cmd.Flags().Lookup(logLevelFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", logLevelFlag, err)
	}

	viper.SetDefault(requestLogLevelKey, defaultRequestLogLevel)
	if err := viper.BindEnv(requestLogLevelKey, "SB_REQUEST_LOG_LEVEL"); err != nil {
		log.Fatalf("failed to bind request_log_level env: %v", err)
	}
	cmd.Flags().StringVar(&cfg.RequestLogLevel, requestLogLevelFlag, viper.GetString(requestLogLevelKey),
		`Set the request log level independently.
Supported values: debug, info, warn, error.
When empty, inherits from --log-level.
This flag can be set using
SB_REQUEST_LOG_LEVEL env var too.
`)
	if err := viper.BindPFlag(requestLogLevelKey, cmd.Flags().Lookup(requestLogLevelFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", requestLogLevelFlag, err)
	}

	viper.SetDefault(graceTimeKey, defaultGraceTime)
	if err := viper.BindEnv(graceTimeKey, "SB_GRACE_TIME"); err != nil {
		log.Fatalf("failed to bind grace_time env: %v", err)
	}
	cmd.Flags().IntVar(&cfg.GraceTime, graceTimeFlag, viper.GetInt(graceTimeKey),
		`Graceful shutdown is an option to initiate a
shutdown without abrupt cancellation of the
currently ongoing sessions.
This grace time defines the number of seconds
allowed for existing transfers to get
completed before shutting down.
A graceful shutdown is triggered by an
interrupt signal.
This flag can be set using SB_GRACE_TIME env
var. 0 means disabled. (default 0)`)
	if err := viper.BindPFlag(graceTimeKey, cmd.Flags().Lookup(graceTimeFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", graceTimeFlag, err)
	}

	viper.SetDefault(disableHostFilterKey, false)
	if err := viper.BindEnv(disableHostFilterKey, "SB_DISABLE_HOST_FILTER"); err != nil {
		log.Fatalf("failed to bind disable_host_filter env: %v", err)
	}
	cmd.Flags().BoolVar(&cfg.DisableHostFilter, disableHostFilterFlag, viper.GetBool(disableHostFilterKey),
		`Disable the host filter (bloom filter).
When disabled, all hostnames are accepted
without pre-checking. The host filter is
enabled by default.
This flag can be set using
SB_DISABLE_HOST_FILTER env var.`)
	if err := viper.BindPFlag(disableHostFilterKey, cmd.Flags().Lookup(disableHostFilterFlag)); err != nil {
		log.Fatalf("failed to bind %s flag: %v", disableHostFilterFlag, err)
	}
}
