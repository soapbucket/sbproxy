// Package billing tracks and reports usage metrics for metered billing.
package billing

// BillingConfig holds configuration for billing/metering writers.
// When no fields are set, the meter uses a NoopWriter (silent discard).
type BillingConfig struct {
	// ClickHouseDSN is the ClickHouse server address (e.g., "clickhouse:9000").
	// When set, metrics are written to ClickHouse for analytics.
	ClickHouseDSN string `yaml:"clickhouse_dsn" mapstructure:"clickhouse_dsn"`

	// BackendURL is the base URL of the billing API (e.g., "https://api.soapbucket.com").
	// When set, metrics are POSTed to the backend database via HTTP.
	BackendURL string `yaml:"backend_url" mapstructure:"backend_url"`

	// BackendAPIKey is the Bearer token sent with backend HTTP requests.
	BackendAPIKey string `yaml:"backend_api_key" mapstructure:"backend_api_key"`

	// BufferSize is the maximum number of records the buffered writer will hold
	// before sending overflow records to the dead-letter log. Default: 10000.
	BufferSize int `yaml:"buffer_size" mapstructure:"buffer_size"`
}
