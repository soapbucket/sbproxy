// Package storage provides storage backend abstractions for caching and persistence.
package storage

// Driver names
const (
	// DriverPostgres is a constant for driver postgres.
	DriverPostgres  = "postgres"
	// DriverSQLite is a constant for driver sq lite.
	DriverSQLite    = "sqlite"
	// DriverFile is a constant for driver file.
	DriverFile      = "file"
	// DriverCDB is a constant for driver cdb.
	DriverCDB       = "cdb"
	// DriverLocal is a constant for driver local.
	DriverLocal     = "local"
	// DriverComposite is a constant for driver composite.
	DriverComposite = "composite"
	// DriverPebble is a constant for driver pebble.
	DriverPebble    = "pebble"
)

// Parameter keys
const (
	// ParamDSN is a constant for param dsn.
	ParamDSN  = "dsn"
	// ParamPath is a constant for param path.
	ParamPath = "path"
)
